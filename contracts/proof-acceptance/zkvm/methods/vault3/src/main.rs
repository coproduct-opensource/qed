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
    0x4e, 0x33, 0x25, 0x65, 0xd7, 0x27, 0x09, 0x22, 0x4b, 0xbe, 0xee, 0xa3, 0x6b, 0x92, 0xe6, 0xb8,
    0xda, 0xb0, 0xc1, 0xa1, 0x0e, 0x5d, 0x7a, 0xaf, 0x43, 0x77, 0x89, 0x01, 0x13, 0x57, 0xd4, 0x40,
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
