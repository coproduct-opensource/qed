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

/// Image ID of the base program (`program/nucleus-base-check-fmt2.bin`), as bytes.
/// `methods/tests/published.rs` checks it against the built base guest.
const BASE_IMAGE_ID: [u8; 32] = [
    0x84, 0x30, 0x9d, 0x93, 0x65, 0x58, 0x4b, 0x89, 0xf0, 0xdb, 0xd2, 0x69, 0xbd, 0x31, 0xd4, 0x48,
    0xd3, 0x36, 0xb8, 0xda, 0x4c, 0xa7, 0x14, 0xc2, 0x3a, 0x9d, 0x90, 0x12, 0x7a, 0x96, 0x82, 0x37,
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
