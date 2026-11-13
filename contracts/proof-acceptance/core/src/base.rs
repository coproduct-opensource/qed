//! Checked base libraries (docs/rfcs/proof-commerce-checked-bases-2026-11-12.md).
//!
//! A base is a complete Lean export of its own. The base program checks one
//! in the kernel checker under a stated list of permitted axioms and commits
//! that it did, together with who is to be paid for its use and at what rate.
//! An order program that verifies that commitment may skip type-checking the
//! base's declarations when a statement begins with exactly those bytes.
use crate::{Hash, field};
use nanoda_lib::acceptance::inspect;
use sha3::{Digest, Keccak256};

/// Largest royalty a base program will commit to: all of an order.
pub const BPS_SCALE: u16 = 10_000;

/// Keccak-256 over a length-prefixed encoding of the permitted axioms, in
/// order. A base is checked under one such list; an order may rely on the
/// base only under the same list.
pub fn axioms_hash(permitted_axioms: &[String]) -> Hash {
    let mut hasher = Keccak256::new();
    field(&mut hasher, b"NucleusPermittedAxiomsV1");
    hasher.update(
        u64::try_from(permitted_axioms.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for axiom in permitted_axioms {
        field(&mut hasher, axiom.as_bytes());
    }
    hasher.finalize().into()
}

/// The base program's journal: five 32-byte words, as `abi.encode` of
/// `(bytes32 tag, bytes32 base, bytes32 axiomsHash, address payee, uint16 bps)`.
pub fn journal(base: Hash, axioms: Hash, payee: [u8; 20], bps: u16) -> [u8; 160] {
    let tag: Hash = Keccak256::digest(b"NucleusBaseV1").into();
    let mut out = [0u8; 160];
    let (words, _) = out.as_chunks_mut::<32>();
    if let [w0, w1, w2, w3, w4] = words {
        *w0 = tag;
        *w1 = base;
        *w2 = axioms;
        if let Some(tail) = w3.get_mut(12..) {
            tail.copy_from_slice(&payee);
        }
        if let Some(tail) = w4.get_mut(30..) {
            tail.copy_from_slice(&bps.to_be_bytes());
        }
    }
    out
}

/// What the base program reads.
/// `B` is the base's bytes: owned (`Vec<u8>`, the default) or borrowed from
/// the input (`&[u8]`, what the base guest uses, so the 5 MB base is not
/// copied out of its input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input<B = Vec<u8>> {
    pub payee: [u8; 20],
    pub bps: u16,
    pub permitted_axioms: Vec<String>,
    pub base: B,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    /// No payee, or a rate above the whole of an order.
    Terms,
    /// The base is empty or does not end at a line end.
    Unterminated,
    /// The base does not parse, or declares an axiom outside the list.
    Invalid(String),
    /// The kernel checker refused a declaration.
    KernelRefused,
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], Refusal> {
    let (head, tail) = rest.split_at_checked(n).ok_or(Refusal::Malformed)?;
    *rest = tail;
    Ok(head)
}
fn take_u32(rest: &mut &[u8]) -> Result<usize, Refusal> {
    let word: [u8; 4] = take(rest, 4)?.try_into().map_err(|_| Refusal::Malformed)?;
    usize::try_from(u32::from_be_bytes(word)).map_err(|_| Refusal::Malformed)
}

impl<B: AsRef<[u8]>> Input<B> {
    pub fn encode(&self) -> Vec<u8> {
        let Input {
            payee,
            bps,
            permitted_axioms,
            base,
        } = self;
        let mut out = Vec::new();
        out.extend_from_slice(payee);
        out.extend_from_slice(&bps.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(permitted_axioms.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for axiom in permitted_axioms {
            put(&mut out, axiom.as_bytes());
        }
        put(&mut out, base.as_ref());
        out
    }
}

impl Input {
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        let Input {
            payee,
            bps,
            permitted_axioms,
            base,
        } = Input::decode_borrowed(bytes)?;
        Ok(Input {
            payee,
            bps,
            permitted_axioms,
            base: base.to_vec(),
        })
    }
}

impl<'a> Input<&'a [u8]> {
    /// As `Input::decode`, with the base borrowed from `bytes`.
    pub fn decode_borrowed(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let mut rest = bytes;
        let payee = take(&mut rest, 20)?
            .try_into()
            .map_err(|_| Refusal::Malformed)?;
        let bps = u16::from_be_bytes(
            take(&mut rest, 2)?
                .try_into()
                .map_err(|_| Refusal::Malformed)?,
        );
        let count = take_u32(&mut rest)?;
        let mut permitted_axioms = Vec::new();
        for _ in 0..count {
            let n = take_u32(&mut rest)?;
            permitted_axioms.push(
                String::from_utf8(take(&mut rest, n)?.to_vec()).map_err(|_| Refusal::Malformed)?,
            );
        }
        let n = take_u32(&mut rest)?;
        let base = take(&mut rest, n)?;
        if !rest.is_empty() {
            return Err(Refusal::Malformed);
        }
        Ok(Input {
            payee,
            bps,
            permitted_axioms,
            base,
        })
    }
}

/// The identity of a base: SHA-256 of its bytes.
pub fn id(base: &[u8]) -> Hash {
    crate::sha256(base)
}

fn decide<B: AsRef<[u8]>>(
    input: &Input<B>,
    run: impl FnOnce(&[u8], &[String]) -> Option<Result<usize, String>>,
) -> Result<[u8; 160], Refusal> {
    let base = input.base.as_ref();
    if input.payee == [0; 20] || input.bps > BPS_SCALE {
        return Err(Refusal::Terms);
    }
    if !nanoda_lib::acceptance::ends_at_a_record_end(base) {
        return Err(Refusal::Unterminated);
    }
    run(base, &input.permitted_axioms)
        .ok_or(Refusal::KernelRefused)?
        .map_err(Refusal::Invalid)?;
    Ok(journal(
        id(base),
        axioms_hash(&input.permitted_axioms),
        input.payee,
        input.bps,
    ))
}

/// For the base guest: parse and type-check every declaration of the base on
/// this thread. A kernel refusal aborts the process, so nothing is committed.
pub fn check_aborting<B: AsRef<[u8]>>(input: &Input<B>) -> Result<[u8; 160], Refusal> {
    decide(input, |base, axioms| {
        Some(inspect(base, axioms, true).map(|entries| entries.len()))
    })
}

/// For a host: the same check on its own deep-stack thread; a kernel refusal
/// is returned as `Refusal::KernelRefused`.
#[cfg(not(target_os = "zkvm"))]
pub fn check<B: AsRef<[u8]>>(input: &Input<B>) -> Result<[u8; 160], Refusal> {
    decide(input, |base, axioms| {
        let (base, axioms) = (base.to_vec(), axioms.to_vec());
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || inspect(&base, &axioms, true).map(|entries| entries.len()))
            .ok()?
            .join()
            .ok()
    })
}
