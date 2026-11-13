//! NucleusVault3 settling on a REAL proof: the real RISC Zero Groth16 verifier
//! bytecode, the real FiatToken bytecode, and a Groth16 seal produced by
//! proving the third-form guest (the Lean checker) on this exact order.
//!
//! The seal is a fixture because making it takes about a quarter of an hour.
//! To regenerate after changing the guest or the order:
//!
//!   cargo test --test real_proof3 -- --ignored emit       # writes fixtures/real-order3.input
//!   HOST vault3-image                                     # put the id in fixtures/real-order3.program.hex
//!   HOST vault3-prove fixtures/real-order3.input R && HOST vault3-groth16 R G fixtures/real-order3.seal.hex
//!
//! The order names the program by image ID, so a stale fixture fails here
//! rather than passing for the wrong program.
mod common;
use common::third::*;
use common::{CHAIN, PRICE, SELLER, TOKEN, TREASURY, buyer, unhex};
use nucleus_proof_acceptance::{Policy, vault_program::Input};
use nucleus_proof_commerce::vault;
use revm::{
    primitives::{Address, U256},
    state::{AccountInfo, Bytecode},
};
use sha2::{Digest, Sha256};

const STATEMENT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/suffix.ndjson");
/// Where RISC Zero's 3.1.0 Groth16 verifier lives on Base and Arbitrum Sepolia.
const REAL_VERIFIER: Address = Address::new([
    0x8c, 0x91, 0x5b, 0x50, 0x71, 0x20, 0x6c, 0x6e, 0x32, 0x8b, 0xc1, 0x85, 0x29, 0x58, 0x6c, 0x51,
    0x34, 0x08, 0xab, 0x3b,
]);

fn policy() -> Policy {
    Policy {
        statement_sha256: Sha256::digest(STATEMENT).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
/// The world with the real verifier's bytecode installed, and the fixture order.
fn world() -> (World, vault::Order) {
    let mut w = World::new();
    let code = unhex(include_str!(
        "../../agents/fixtures/risc0-groth16-verifier-3.1.0.runtime.hex"
    ));
    w.chain.db.insert_account_info(
        REAL_VERIFIER,
        AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
    );
    let mut o = w.order(1);
    o.verifier = REAL_VERIFIER.into_array();
    o.program = unhex(include_str!("../fixtures/real-order3.program.hex"))
        .try_into()
        .unwrap();
    o.policy_hash = policy().hash();
    (w, o)
}

#[test]
#[ignore = "writes the guest input for the fixture order; run when regenerating the seal"]
fn emit() {
    let (w, o) = world();
    let input = Input {
        form: vault::Form::Third,
        chain_id: CHAIN,
        vault: w.vault.into_array(),
        order: o,
        policy: policy(),
        statement: STATEMENT.to_vec(),
        artifact: ARTIFACT.to_vec(),
    };
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/real-order3.input"),
        input.encode(),
    )
    .unwrap();
}

#[test]
fn the_vault_books_on_a_real_proof_and_refuses_a_non_proof_or_an_altered_one() {
    let (mut w, o) = world();
    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);

    let seal = unhex(include_str!("../fixtures/real-order3.seal.hex"));
    assert_eq!(seal.len(), 260);
    // What the TEST verifier would have accepted is not a proof. `refused`
    // panics if the call is accepted; the real verifier reverts with its own
    // error data, which this harness does not decode.
    let test_seal = w.test_seal(&o, ARTIFACT);
    w.refused(1500, settle_with(&o, ARTIFACT, test_seal));
    let mut flipped = seal.clone();
    flipped[100] ^= 1;
    w.refused(1500, settle_with(&o, ARTIFACT, flipped));
    // The real seal for a different artifact.
    w.refused(1500, settle_with(&o, b"not the artifact", seal.clone()));
    // The second-form program's real seal for the corresponding second-form
    // order is not a proof for this vault.
    let second_seal = unhex(include_str!("../fixtures/real-order.seal.hex"));
    w.refused(1500, settle_with(&o, ARTIFACT, second_seal));
    assert_eq!(w.owed(SELLER, TOKEN), U256::ZERO);

    w.must(1500, settle_with(&o, ARTIFACT, seal));
    assert_eq!(w.phase(vault::digest(&w.deployment(), &o)), 2);
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(997_500u64));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from(2_500u64));
    w.claim(1600, SELLER);
    w.claim(1600, TREASURY);
    assert_eq!(w.chain.balance(SELLER), U256::from(997_500u64));
    assert_eq!(w.chain.balance(TREASURY), U256::from(2_500u64));
    let vault_address = w.vault;
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);
}

/// The same order, with the seal the native Rust wrap made from the same
/// succinct receipt (`NUCLEUS_GROTH16=native`, no container). The bytes differ
/// from the container's seal because Groth16 proofs are randomised; the real
/// verifier accepts both, and refuses this one for anything but this artifact.
#[test]
fn the_real_verifier_accepts_a_natively_wrapped_seal_and_only_for_this_artifact() {
    let (mut w, o) = world();
    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);

    let native = unhex(include_str!("../fixtures/real-order3.native.seal.hex"));
    let container = unhex(include_str!("../fixtures/real-order3.seal.hex"));
    assert_eq!(native.len(), 260);
    assert_eq!(native[..4], container[..4], "same verifier selector");
    assert_ne!(native, container, "a different proof of the same statement");
    // Every one of the eight proof coordinates matters.
    for at in [4, 36, 68, 100, 132, 164, 196, 228, 259] {
        let mut changed = native.clone();
        changed[at] ^= 1;
        w.refused(1500, settle_with(&o, ARTIFACT, changed));
    }
    w.refused(1500, settle_with(&o, b"not the artifact", native.clone()));
    assert_eq!(w.owed(SELLER, TOKEN), U256::ZERO);

    w.must(1500, settle_with(&o, ARTIFACT, native));
    assert_eq!(w.phase(vault::digest(&w.deployment(), &o)), 2);
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(997_500u64));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from(2_500u64));
}
