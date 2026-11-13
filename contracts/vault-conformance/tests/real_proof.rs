//! The vault settling on a REAL proof: the real RISC Zero Groth16 verifier
//! bytecode, the real FiatToken bytecode, and a Groth16 seal produced by
//! proving the vault guest (the Lean checker) on this exact order.
//!
//! The seal is a fixture because making it takes about a quarter of an hour.
//! To regenerate after changing the guest or the order:
//!
//!   cargo test --test real_proof -- --ignored emit        # writes fixtures/real-order.input
//!   HOST vault-image                                      # put the id in fixtures/real-order.program.hex
//!   HOST vault-prove fixtures/real-order.input R && HOST vault-groth16 R G fixtures/real-order.seal.hex
//!
//! The order names the program by image ID, so a stale fixture fails here
//! rather than passing for the wrong program.
mod common;
use alloy_sol_types::SolCall;
use common::*;
use nucleus_proof_acceptance::{Policy, vault_program::Input};
use nucleus_proof_commerce::vault;
use revm::{
    primitives::{Address, Bytes, U256},
    state::{AccountInfo, Bytecode},
};
use sha2::{Digest, Sha256};

const STATEMENT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/suffix.ndjson");
/// Where RISC Zero's 3.1.0 Groth16 verifier lives on Base Sepolia and Arbitrum Sepolia.
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
/// The chain with the real verifier's bytecode installed, and the fixture order.
fn world() -> (Chain, vault::Order) {
    let mut chain = Chain::new();
    let code = unhex(include_str!(
        "../../agents/fixtures/risc0-groth16-verifier-3.1.0.runtime.hex"
    ));
    chain.db.insert_account_info(
        REAL_VERIFIER,
        AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
    );
    let mut o = order(&chain, 1);
    o.verifier = REAL_VERIFIER.into_array();
    o.program = unhex(include_str!("../fixtures/real-order.program.hex"))
        .try_into()
        .unwrap();
    o.policy_hash = policy().hash();
    (chain, o)
}
fn settle(o: &vault::Order, seal: Vec<u8>) -> Vec<u8> {
    settleCall {
        o: abi(o),
        artifact: Bytes::copy_from_slice(ARTIFACT),
        seal: seal.into(),
    }
    .abi_encode()
}

#[test]
#[ignore = "writes the guest input for the fixture order; run when regenerating the seal"]
fn emit() {
    let (chain, o) = world();
    let input = Input {
        form: vault::Form::Second,
        chain_id: CHAIN,
        vault: chain.vault.into_array(),
        order: o,
        policy: policy(),
        statement: STATEMENT.to_vec(),
        artifact: ARTIFACT.to_vec(),
    };
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/real-order.input"),
        input.encode(),
    )
    .unwrap();
}

#[test]
fn the_vault_pays_on_a_real_proof_and_refuses_a_non_proof_or_an_altered_one() {
    let (mut chain, o) = world();
    let vault = chain.vault;
    chain.mint(o.buyer.into(), PRICE);
    let call = fund_call(&chain, &o, &buyer());
    chain.must(RELAYER, vault, 500, call);

    let seal = unhex(include_str!("../fixtures/real-order.seal.hex"));
    assert_eq!(seal.len(), 260);
    // What the TEST verifier would have accepted is not a proof.
    // `refused` panics if the call is accepted. The real verifier reverts with
    // its own error data, which this harness does not decode.
    chain.refused(
        RELAYER,
        vault,
        1500,
        settle(&o, test_seal(&chain, &o, ARTIFACT)),
    );
    let mut flipped = seal.clone();
    flipped[100] ^= 1;
    chain.refused(RELAYER, vault, 1500, settle(&o, flipped));
    // The real seal for a different artifact.
    let other = settleCall {
        o: abi(&o),
        artifact: Bytes::copy_from_slice(b"not the artifact"),
        seal: seal.clone().into(),
    }
    .abi_encode();
    chain.refused(RELAYER, vault, 1500, other);
    assert_eq!(chain.balance(SELLER), U256::ZERO);

    chain.must(RELAYER, vault, 1500, settle(&o, seal));
    assert_eq!(chain.balance(SELLER), U256::from(997_500u64));
    chain.collect(TOKEN);
    assert_eq!(chain.balance(TREASURY), U256::from(2_500u64));
    assert_eq!(chain.balance(vault), U256::ZERO);
    assert_eq!(chain.phase(vault::digest(&chain.deployment(), &o)), 2);
}
