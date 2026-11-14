//! NucleusVault3 and BaseRegistry on REAL proofs from the reproducible statement-format-v2
//! programs (`program/nucleus-order-fmt2r.bin`, `program/nucleus-base-check-fmt2r.bin`):
//! the real RISC Zero Groth16 verifier bytecode, the real FiatToken bytecode,
//! and Groth16 seals made by proving those programs on export-v2 inputs.
//! The fmt2 and earlier programs keep their own tests (`real_proof_fmt2.rs`, `real_proof3.rs`, `registry.rs`).
//!
//! To regenerate after changing either guest:
//!
//!   cargo test --test real_proof_fmt2r -- --ignored emit
//!   HOST order2r-prove fixtures/fmt2r-order.input R && HOST order2r-groth16 R G fixtures/fmt2r-order.seal.hex
//!   HOST base2r-prove fixtures/fmt2r-base.input BR && HOST base2r-groth16 BR BG fixtures/fmt2r-base.seal.hex
//!   HOST order2r-prove fixtures/fmt2r-order-on-base.input R2 BR && HOST order2r-groth16 R2 G2 fixtures/fmt2r-order-on-base.seal.hex
//!   and put `HOST order2r-image` / `HOST base2r-image` in the two `.program.hex` files.
//!
//! An order names its program by image ID, so a stale fixture fails here
//! rather than passing for the wrong program.
mod common;
use alloy_sol_types::{SolCall, SolValue, sol};
use common::third::*;
use common::{CHAIN, Chain, PRICE, RELAYER, SELLER, TOKEN, TREASURY, buyer, unhex};
use nucleus_proof_acceptance::{
    Policy, base, export_v2_from_ndjson,
    vault_program::{BaseWitness, Input, encode_with_base},
};
use nucleus_proof_commerce::vault;
use revm::{
    primitives::{Address, B256, Bytes, U256},
    state::{AccountInfo, Bytecode},
};
use sha2::{Digest, Sha256};

sol! {
    function register(bytes32 base, bytes32 axiomsHash, address payee, uint16 bps, bytes seal);
    function entryOf(bytes32 base) returns (address payee, uint16 bps);
}

const FIXTURES: &str = "../proof-acceptance/core/tests/fixtures";
const REAL_REGISTRY_BIN: &str = include_str!("../../vault/out/BaseRegistry.bin");
const REAL_VERIFIER: Address = Address::new([
    0x8c, 0x91, 0x5b, 0x50, 0x71, 0x20, 0x6c, 0x6e, 0x32, 0x8b, 0xc1, 0x85, 0x29, 0x58, 0x6c, 0x51,
    0x34, 0x08, 0xab, 0x3b,
]);
const BPS: u16 = 10;
const MAXIMUM_BPS: u16 = 50;

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/{FIXTURES}/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
/// A statement in export v2 (with its header) and its artifact (records only).
fn v2(statement: &str, artifact: &str) -> (Vec<u8>, Vec<u8>) {
    (
        export_v2_from_ndjson(&read(statement), true).unwrap(),
        export_v2_from_ndjson(&read(artifact), false).unwrap(),
    )
}
fn base_v2() -> Vec<u8> {
    export_v2_from_ndjson(&read("base/base.ndjson"), true).unwrap()
}
fn policy(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: Sha256::digest(statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
fn program(file: &str) -> [u8; 32] {
    unhex(file).try_into().unwrap()
}
fn real_verifier(chain: &mut Chain) {
    let code = unhex(include_str!(
        "../../agents/fixtures/risc0-groth16-verifier-3.1.0.runtime.hex"
    ));
    chain.db.insert_account_info(
        REAL_VERIFIER,
        AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
    );
}
fn register_call(
    base: [u8; 32],
    axioms: [u8; 32],
    payee: Address,
    bps: u16,
    seal: Vec<u8>,
) -> Vec<u8> {
    registerCall {
        base: base.into(),
        axiomsHash: axioms.into(),
        payee,
        bps,
        seal: Bytes::from(seal),
    }
    .abi_encode()
}
fn entry(chain: &mut Chain, registry: Address, base: [u8; 32]) -> (Address, u16) {
    let out = chain.must(
        RELAYER,
        registry,
        1,
        entryOfCall { base: base.into() }.abi_encode(),
    );
    (
        Address::from_slice(&out[12..32]),
        u16::from_be_bytes([out[62], out[63]]),
    )
}

/// The base-less order: a vault with the real verifier, the toy task in v2.
fn order_world() -> (World, vault::Order, Vec<u8>, Vec<u8>) {
    let mut w = World::new();
    real_verifier(&mut w.chain);
    let (statement, artifact) = v2("task.ndjson", "suffix.ndjson");
    let mut o = w.order(1);
    o.verifier = REAL_VERIFIER.into_array();
    o.program = program(include_str!("../fixtures/fmt2r-order.program.hex"));
    o.policy_hash = policy(&statement).hash();
    (w, o, statement, artifact)
}

/// The order on a base: a registry for the v2 base program, a vault naming
/// it, the toy base and the toy task on it, all in v2.
fn base_world() -> (World, vault::Order, Vec<u8>, Vec<u8>) {
    let mut chain = Chain::new();
    real_verifier(&mut chain);
    let constructor = (
        REAL_VERIFIER,
        B256::from(program(include_str!("../fixtures/fmt2r-base.program.hex"))),
        MAXIMUM_BPS,
    )
        .abi_encode();
    let registry = chain.create([unhex(REAL_REGISTRY_BIN), constructor].concat());
    let w = World::with_registry(chain, registry);
    let (statement, artifact) = v2("base/task-on-base.ndjson", "base/suffix-on-base.ndjson");
    let mut o = w.order(1);
    o.verifier = REAL_VERIFIER.into_array();
    o.program = program(include_str!("../fixtures/fmt2r-order.program.hex"));
    o.policy_hash = policy(&statement).hash();
    o.base = base::id(&base_v2());
    (w, o, statement, artifact)
}

#[test]
#[ignore = "writes the three guest inputs for the fixtures; run when regenerating the seals"]
fn emit() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let (w, o, statement, artifact) = order_world();
    let input = Input {
        form: vault::Form::Third,
        chain_id: CHAIN,
        vault: w.vault.into_array(),
        order: o,
        policy: policy(&statement),
        statement,
        artifact,
    };
    std::fs::write(format!("{dir}/fixtures/fmt2r-order.input"), input.encode()).unwrap();

    let base_bytes = base_v2();
    let base_input = base::Input {
        payee: BASE_PAYEE.into_array(),
        bps: BPS,
        permitted_axioms: vec![],
        base: base_bytes.clone(),
    };
    std::fs::write(
        format!("{dir}/fixtures/fmt2r-base.input"),
        base_input.encode(),
    )
    .unwrap();

    let (w, o, statement, artifact) = base_world();
    assert!(
        statement.starts_with(&base_bytes),
        "the v2 base is a prefix of the v2 statement"
    );
    let input = Input {
        form: vault::Form::Third,
        chain_id: CHAIN,
        vault: w.vault.into_array(),
        order: o,
        policy: policy(&statement),
        statement,
        artifact,
    };
    let witness = BaseWitness {
        length: base_bytes.len() as u32,
        payee: BASE_PAYEE.into_array(),
        bps: BPS,
    };
    std::fs::write(
        format!("{dir}/fixtures/fmt2r-order-on-base.input"),
        encode_with_base(&input, Some(&witness)),
    )
    .unwrap();
}

#[test]
fn a_v2_order_without_a_base_books_on_a_real_proof_and_only_for_its_artifact() {
    let (mut w, o, _, artifact) = order_world();
    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);
    let seal = unhex(include_str!("../fixtures/fmt2r-order.seal.hex"));
    assert_eq!(seal.len(), 260);
    let mut flipped = seal.clone();
    flipped[100] ^= 1;
    w.refused(1500, settle_with(&o, &artifact, flipped));
    w.refused(1500, settle_with(&o, b"not the artifact", seal.clone()));
    // The fmt2 order program's seal for the same v2 task is not a proof here.
    let earlier = unhex(include_str!("../fixtures/fmt2-order.seal.hex"));
    w.refused(1500, settle_with(&o, &artifact, earlier));
    assert_eq!(w.owed(SELLER, TOKEN), U256::ZERO);
    w.must(1500, settle_with(&o, &artifact, seal));
    assert_eq!(w.phase(vault::digest(&w.deployment(), &o)), 2);
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(997_500u64));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from(2_500u64));
}

#[test]
fn a_real_v2_base_proof_registers_and_a_real_composed_v2_order_books_the_royalty() {
    let (mut w, o, _, artifact) = base_world();
    let registry = w.registry;
    let (id, axioms) = (base::id(&base_v2()), base::axioms_hash(&[]));
    let base_seal = unhex(include_str!("../fixtures/fmt2r-base.seal.hex"));
    assert_eq!(base_seal.len(), 260);
    let other = Address::new([0x0f; 20]);
    for call in [
        register_call(id, axioms, other, BPS, base_seal.clone()),
        register_call(id, axioms, BASE_PAYEE, BPS + 1, base_seal.clone()),
    ] {
        w.chain.refused(other, registry, 1, call);
    }
    // The fmt2 base program's seal for the same v2 base registers nothing here.
    let earlier = unhex(include_str!("../fixtures/fmt2-base.seal.hex"));
    w.chain.refused(
        other,
        registry,
        1,
        register_call(id, axioms, BASE_PAYEE, BPS, earlier),
    );
    w.chain.must(
        other,
        registry,
        1,
        register_call(id, axioms, BASE_PAYEE, BPS, base_seal),
    );
    assert_eq!(entry(&mut w.chain, registry, id), (BASE_PAYEE, BPS));

    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);
    let seal = unhex(include_str!("../fixtures/fmt2r-order-on-base.seal.hex"));
    assert_eq!(seal.len(), 260);
    w.refused(1500, settle_with(&o, b"not the artifact", seal.clone()));
    w.must(1500, settle_with(&o, &artifact, seal));
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), U256::from(1_000u64));
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(996_500u64));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from(2_500u64));
}
