//! A Groth16 proof from a snarkjs-format proving key (`.zkey`) and a witness.
//!
//! The file layout and the witness map follow snarkjs's `groth16_prove.js`,
//! which is what the key was made for: the quotient is evaluated on the odd
//! coset of a domain twice the size, against the Lagrange-form points in the
//! key's H section. The layout was read from `ark-circom` 0.6.0's `zkey.rs`
//! and `circom/qap.rs` (MIT OR Apache-2.0) and reimplemented here on arkworks
//! 0.5 without that crate's WebAssembly runtime.
//!
//! Points are loaded without subgroup or curve checks. A key that is not the
//! one the verifier was built for yields a proof the verifier refuses.
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::Instant,
};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Key(&'static str),
    Witness(&'static str),
    /// The proof this code produced does not satisfy the key's own
    /// verification equation. Nothing is returned in that case.
    SelfCheck,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(error) => write!(f, "proving key: {error}"),
            Error::Key(what) => write!(f, "proving key malformed: {what}"),
            Error::Witness(what) => write!(f, "witness: {what}"),
            Error::SelfCheck => write!(f, "the proof does not verify against the proving key"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// Seconds spent in each part, for the record.
#[derive(Debug, Default, Clone, Copy)]
pub struct Timing {
    pub quotient: f64,
    pub load_and_multiply: f64,
    pub check: f64,
}

/// A Groth16 proof as RISC Zero's seal lays it out: 32-byte big-endian
/// coordinates `A.x A.y B.x.c1 B.x.c0 B.y.c1 B.y.c0 C.x C.y`.
pub type ProofBytes = [u8; 256];

fn limbs(bytes: &[u8]) -> BigInt<4> {
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }
    BigInt::new(out)
}
/// A base-field element stored in Montgomery form, as the key stores it.
fn fq(bytes: &[u8]) -> Fq {
    Fq::new_unchecked(limbs(bytes))
}
fn g1(bytes: &[u8]) -> G1Affine {
    let (x, y) = (fq(&bytes[..32]), fq(&bytes[32..64]));
    if x.is_zero() && y.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(x, y)
    }
}
fn g2(bytes: &[u8]) -> G2Affine {
    let x = Fq2::new(fq(&bytes[..32]), fq(&bytes[32..64]));
    let y = Fq2::new(fq(&bytes[64..96]), fq(&bytes[96..128]));
    if x.is_zero() && y.is_zero() {
        G2Affine::identity()
    } else {
        G2Affine::new_unchecked(x, y)
    }
}
/// A coefficient of the key: stored multiplied by R squared, so reading it as
/// a Montgomery value and then reading that value's integer as a Montgomery
/// value again gives the coefficient.
fn coefficient(bytes: &[u8]) -> Fr {
    Fr::new_unchecked(Fr::new_unchecked(limbs(bytes)).into_bigint())
}

struct Key {
    file: File,
    sections: HashMap<u32, (u64, u64)>,
    variables: usize,
    public: usize,
    domain: usize,
    alpha1: G1Affine,
    beta1: G1Affine,
    beta2: G2Affine,
    gamma2: G2Affine,
    delta1: G1Affine,
    delta2: G2Affine,
}

impl Key {
    fn open(path: &Path) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let mut head = [0u8; 12];
        file.read_exact(&mut head)?;
        if &head[..4] != b"zkey" {
            return Err(Error::Key("magic"));
        }
        let count = u32::from_le_bytes([head[8], head[9], head[10], head[11]]);
        let mut sections = HashMap::new();
        for _ in 0..count {
            let mut entry = [0u8; 12];
            file.read_exact(&mut entry)?;
            let id = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let size = u64::from_le_bytes([
                entry[4], entry[5], entry[6], entry[7], entry[8], entry[9], entry[10], entry[11],
            ]);
            let position = file.stream_position()?;
            sections.insert(id, (position, size));
            file.seek(SeekFrom::Current(
                i64::try_from(size).map_err(|_| Error::Key("section size"))?,
            ))?;
        }
        let &(position, size) = sections.get(&2).ok_or(Error::Key("no header section"))?;
        let mut header = vec![0u8; usize::try_from(size).map_err(|_| Error::Key("header size"))?];
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut header)?;
        // n8q, q, n8r, r, nVars, nPublic, domainSize, then six points.
        if header.len() != 4 + 32 + 4 + 32 + 12 + 64 + 64 + 128 + 128 + 64 + 128
            || header[..4] != 32u32.to_le_bytes()
            || header[36..40] != 32u32.to_le_bytes()
        {
            return Err(Error::Key("header is not for a 254-bit curve"));
        }
        let word = |at: usize| {
            u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
                as usize
        };
        let (variables, public, domain) = (word(72), word(76), word(80));
        if !domain.is_power_of_two() || public + 1 > variables {
            return Err(Error::Key("header counts"));
        }
        let points = &header[84..];
        Ok(Self {
            alpha1: g1(&points[..64]),
            beta1: g1(&points[64..128]),
            beta2: g2(&points[128..256]),
            gamma2: g2(&points[256..384]),
            delta1: g1(&points[384..448]),
            delta2: g2(&points[448..576]),
            file,
            sections,
            variables,
            public,
            domain,
        })
    }

    fn section(&mut self, id: u32, expected: usize) -> Result<Vec<u8>, Error> {
        let &(position, size) = self
            .sections
            .get(&id)
            .ok_or(Error::Key("missing section"))?;
        if size != expected as u64 {
            return Err(Error::Key("section has an unexpected size"));
        }
        let mut bytes = vec![0u8; expected];
        self.file.seek(SeekFrom::Start(position))?;
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// Sum of `scalars[i] * point[i]` over a G1 section of `scalars.len()` points.
    fn msm_g1(&mut self, id: u32, scalars: &[BigInt<4>]) -> Result<G1Projective, Error> {
        let bytes = self.section(id, scalars.len() * 64)?;
        let points: Vec<G1Affine> = bytes.par_chunks_exact(64).map(g1).collect();
        drop(bytes);
        Ok(G1Projective::msm_bigint(&points, scalars))
    }
    fn msm_g2(&mut self, id: u32, scalars: &[BigInt<4>]) -> Result<G2Projective, Error> {
        let bytes = self.section(id, scalars.len() * 128)?;
        let points: Vec<G2Affine> = bytes.par_chunks_exact(128).map(g2).collect();
        drop(bytes);
        Ok(G2Projective::msm_bigint(&points, scalars))
    }

    /// The quotient's evaluations on the odd coset: `A*B - C` there, where A
    /// and B are the two linear forms of every constraint applied to the
    /// witness and C is their product on the domain.
    fn quotient(&mut self, witness: &[Fr]) -> Result<Vec<Fr>, Error> {
        let &(position, size) = self.sections.get(&4).ok_or(Error::Key("no coefficients"))?;
        let mut bytes = vec![0u8; usize::try_from(size).map_err(|_| Error::Key("coefficients"))?];
        self.file.seek(SeekFrom::Start(position))?;
        self.file.read_exact(&mut bytes)?;
        if bytes.len() < 4 {
            return Err(Error::Key("coefficients"));
        }
        let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        const RECORD: usize = 12 + 32;
        if bytes.len() != 4 + count * RECORD {
            return Err(Error::Key("coefficient count"));
        }
        let (domain, variables) = (self.domain, self.variables);
        // Each record adds `coefficient * witness[signal]` to one constraint
        // of one matrix. Products in parallel, sums in file order.
        let terms: Vec<(u8, u32, Fr)> = bytes[4..]
            .par_chunks_exact(RECORD)
            .map(|r| {
                let matrix = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
                let constraint = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
                let signal = u32::from_le_bytes([r[8], r[9], r[10], r[11]]) as usize;
                if matrix > 1 || constraint as usize >= domain || signal >= variables {
                    return Err(Error::Key("coefficient out of range"));
                }
                Ok((
                    matrix as u8,
                    constraint,
                    coefficient(&r[12..]) * witness[signal],
                ))
            })
            .collect::<Result<_, _>>()?;
        drop(bytes);
        let mut a = vec![Fr::zero(); domain];
        let mut b = vec![Fr::zero(); domain];
        for (matrix, constraint, term) in terms {
            if matrix == 0 {
                a[constraint as usize] += term;
            } else {
                b[constraint as usize] += term;
            }
        }
        let mut c: Vec<Fr> = a.par_iter().zip(&b).map(|(a, b)| *a * b).collect();

        let small = Radix2EvaluationDomain::<Fr>::new(domain).ok_or(Error::Key("domain size"))?;
        let twice =
            Radix2EvaluationDomain::<Fr>::new(2 * domain).ok_or(Error::Key("domain size"))?;
        let step = twice.group_gen();
        let to_odd_coset = |values: &mut Vec<Fr>| {
            small.ifft_in_place(values);
            Radix2EvaluationDomain::<Fr>::distribute_powers(values, step);
            small.fft_in_place(values);
        };
        rayon::scope(|scope| {
            scope.spawn(|_| to_odd_coset(&mut a));
            scope.spawn(|_| to_odd_coset(&mut b));
            scope.spawn(|_| to_odd_coset(&mut c));
        });
        Ok(a.into_par_iter()
            .zip(b)
            .zip(c)
            .map(|((a, b), c)| a * b - c)
            .collect())
    }

    /// The key's own verification equation for this proof and these public
    /// inputs: e(A, B) = e(alpha, beta) * e(sum of inputs, gamma) * e(C, delta).
    fn verifies(
        &mut self,
        witness: &[Fr],
        a: G1Affine,
        b: G2Affine,
        c: G1Affine,
    ) -> Result<bool, Error> {
        let bytes = self.section(3, (self.public + 1) * 64)?;
        let ic: Vec<G1Affine> = bytes.chunks_exact(64).map(g1).collect();
        let scalars: Vec<BigInt<4>> = witness[..=self.public]
            .iter()
            .map(|w| w.into_bigint())
            .collect();
        let inputs = G1Projective::msm_bigint(&ic, &scalars).into_affine();
        let left = Bn254::pairing(a, b);
        let right = Bn254::pairing(self.alpha1, self.beta2)
            + Bn254::pairing(inputs, self.gamma2)
            + Bn254::pairing(c, self.delta2);
        Ok(left == right)
    }
}

fn be(value: Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out
        .chunks_exact_mut(8)
        .zip(value.into_bigint().0.iter().rev())
    {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Prove with fresh randomness from the operating system. The result is
/// returned only if it satisfies the key's verification equation.
pub fn prove(key: &Path, witness: &[Fr]) -> Result<(ProofBytes, Timing), Error> {
    let mut rng = rand::rngs::OsRng;
    prove_with(key, witness, Fr::rand(&mut rng), Fr::rand(&mut rng))
}

fn prove_with(key: &Path, witness: &[Fr], r: Fr, s: Fr) -> Result<(ProofBytes, Timing), Error> {
    let mut timing = Timing::default();
    let mut key = Key::open(key)?;
    if witness.len() != key.variables {
        return Err(Error::Witness(
            "length differs from the key's variable count",
        ));
    }
    if witness[0] != Fr::one() {
        return Err(Error::Witness("first value is not one"));
    }

    let started = Instant::now();
    let quotient: Vec<BigInt<4>> = key
        .quotient(witness)?
        .into_par_iter()
        .map(|h| h.into_bigint())
        .collect();
    timing.quotient = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let scalars: Vec<BigInt<4>> = witness.par_iter().map(|w| w.into_bigint()).collect();
    let private = &scalars[key.public + 1..];
    let a_sum = key.msm_g1(5, &scalars)?;
    let b1_sum = key.msm_g1(6, &scalars)?;
    let b2_sum = key.msm_g2(7, &scalars)?;
    let c_sum = key.msm_g1(8, private)?;
    let h_sum = key.msm_g1(9, &quotient)?;
    timing.load_and_multiply = started.elapsed().as_secs_f64();

    let a = a_sum + key.alpha1 + key.delta1 * r;
    let b1 = b1_sum + key.beta1 + key.delta1 * s;
    let b2 = b2_sum + key.beta2 + key.delta2 * s;
    let c = c_sum + h_sum + a * s + b1 * r - key.delta1 * (r * s);
    let (a, b2, c) = (a.into_affine(), b2.into_affine(), c.into_affine());

    let started = Instant::now();
    if !key.verifies(witness, a, b2, c)? {
        return Err(Error::SelfCheck);
    }
    timing.check = started.elapsed().as_secs_f64();

    let (ax, ay) = a.xy().ok_or(Error::SelfCheck)?;
    let (bx, by) = b2.xy().ok_or(Error::SelfCheck)?;
    let (cx, cy) = c.xy().ok_or(Error::SelfCheck)?;
    let mut out = [0u8; 256];
    for (slot, value) in out
        .chunks_exact_mut(32)
        .zip([ax, ay, bx.c1, bx.c0, by.c1, by.c0, cx, cy])
    {
        slot.copy_from_slice(&be(value));
    }
    Ok((out, timing))
}
