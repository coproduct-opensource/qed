//! The `stark_verify` circuit's inputs from an `identity_p254` seal: the same
//! text RISC Zero's `risc0_groth16::prove::to_json` writes to `input.json`
//! (reimplemented from `src/prove/seal_to_json.rs`, Apache-2.0, because that
//! function is only compiled together with RISC Zero's prover kernels).
use crate::seal_layout::{RUNS, SEAL_ELEMENTS, SEAL_WORDS};
use ruint::Uint;
use std::fmt::Write;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The seal is not the size this layout describes.
    Length { words: usize },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Length { words } => write!(
                f,
                "identity_p254 seal has {words} words; this build expects {SEAL_WORDS} (risc0 3.x recursion)"
            ),
        }
    }
}
impl std::error::Error for Error {}

/// BabyBear: 15 * 2^27 + 1.
const P: u64 = 2013265921;

/// A BabyBear element out of Montgomery form (it is stored times 2^32).
fn baby_bear(raw: u32) -> u32 {
    // 2^-32 mod P, by Fermat: (2^32)^(P-2).
    let mut inverse = 1u64;
    let (mut base, mut exponent) = ((1u64 << 32) % P, P - 2);
    while exponent > 0 {
        if exponent & 1 == 1 {
            inverse = inverse * base % P;
        }
        base = base * base % P;
        exponent >>= 1;
    }
    (u64::from(raw) % P * inverse % P) as u32
}

pub fn from_seal(seal: &[u8]) -> Result<String, Error> {
    if seal.len() != SEAL_WORDS * 4 {
        return Err(Error::Length {
            words: seal.len() / 4,
        });
    }
    let mut json = String::with_capacity(800_000);
    json.push_str("{\n  \"iop\" : [\n");
    let mut at = 0;
    let mut written = 0;
    for (run, &count) in RUNS.iter().enumerate() {
        let digest = run % 2 == 1;
        for _ in 0..count {
            if written != 0 {
                json.push_str(",\n");
            }
            if digest {
                // Eight little-endian words are one little-endian 256-bit
                // integer, the scalar the digest stands for.
                let value = Uint::<256, 4>::from_le_slice(&seal[at..at + 32]);
                at += 32;
                let _ = writeln!(json, "    \"{value}\"");
            } else {
                let raw = u32::from_le_bytes([seal[at], seal[at + 1], seal[at + 2], seal[at + 3]]);
                at += 4;
                let _ = writeln!(json, "    \"{}\"", baby_bear(raw));
            }
            written += 1;
        }
    }
    debug_assert_eq!((at, written), (SEAL_WORDS * 4, SEAL_ELEMENTS));
    json.push_str("  ]\n}");
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_accounts_for_every_word() {
        let (mut words, mut elements) = (0usize, 0usize);
        for (run, &count) in RUNS.iter().enumerate() {
            elements += count as usize;
            words += count as usize * if run % 2 == 1 { 8 } else { 1 };
        }
        assert_eq!((words, elements), (SEAL_WORDS, SEAL_ELEMENTS));
    }

    #[test]
    fn baby_bear_leaves_montgomery_form() {
        // One is stored as 2^32 mod P.
        assert_eq!(baby_bear(((1u64 << 32) % P) as u32), 1);
        assert_eq!(baby_bear(0), 0);
    }

    #[test]
    fn a_seal_of_another_size_is_refused() {
        assert_eq!(from_seal(&[0; 8]), Err(Error::Length { words: 2 }));
    }
}
