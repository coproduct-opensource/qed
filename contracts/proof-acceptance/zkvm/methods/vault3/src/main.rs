//! Proof guest for the third vault (NucleusVault3), with checked bases: read
//! one encoded input, run the vault program on it as a third-form order, and
//! commit its 160-byte journal. Every refusal is a panic, so a refused
//! delivery yields nothing a verifier would accept.
//!
//! An order that names a base is accepted only if the base program
//! (`BASE_IMAGE_ID`) committed that base under this order's permitted axioms.
//! That is asked of the proof system by composition: `env::verify` adds an
//! assumption the final receipt is unconditional only if a receipt of the
//! base program resolves. Then the base's declarations are parsed and not
//! type-checked again.
use nucleus_proof_acceptance::{
    accept_aborting, accept_on_base_aborting,
    vault_program::{decode_with_base_borrowed, journal_on_base},
};
use risc0_zkvm::guest::env;
use std::io::Read;

/// Image ID of the base program (`program/nucleus-base-check-fmt2r.bin`), as bytes.
/// `program/REPRODUCIBLE` rebuilds both guests in the pinned image to check it.
const BASE_IMAGE_ID: [u8; 32] = [
    0x38, 0x2c, 0x21, 0x75, 0xb9, 0xb6, 0xe1, 0xea, 0xde, 0x3f, 0xdd, 0x54, 0x39, 0x41, 0x49, 0x6d,
    0x88, 0x0d, 0xc8, 0x22, 0xa5, 0x02, 0x0b, 0x72, 0x0c, 0xc0, 0xb1, 0xe4, 0xd8, 0xfe, 0x77, 0x1e,
];

fn main() {
    let mut bytes = Vec::new();
    env::stdin().read_to_end(&mut bytes).expect("input unreadable");
    // Statement and artifact are read in place from `bytes`, not copied out.
    let (input, witness) = decode_with_base_borrowed(&bytes).expect("input refused");
    let journal = journal_on_base(
        &input,
        witness.as_ref(),
        accept_aborting,
        accept_on_base_aborting,
        |committed| env::verify(BASE_IMAGE_ID, committed).is_ok(),
    )
    .expect("delivery refused");
    env::commit_slice(&journal);
}
