//! BaseRegistry (model proofs/commerce/Registry.lean): an entry is made only
//! on the base program's proof for exactly that base, axioms hash, payee and
//! rate; the first valid proof decides it; and a third vault naming the
//! registry books the royalty for an order that names a registered base.
//!
//! The first tests use the TEST verifier's publicly computable values. The
//! last uses the real verifier bytecode and two real seals: the base
//! program's, and an order proof made by composition on that base's receipt.
//! To regenerate the real fixtures after changing either guest:
//!
//!   cargo test --test registry -- --ignored emit
//!   HOST base-prove fixtures/real-base.input BR && HOST base-groth16 BR BG fixtures/real-base.seal.hex
//!   HOST vault3-prove fixtures/real-order-on-base.input R BR && HOST vault3-groth16 R G fixtures/real-order-on-base.seal.hex
//!   and put `HOST base-image` / `HOST vault3-image` in the two `.program.hex` files.

mod common;
use alloy_sol_types::{SolCall, SolValue, sol};
use common::third::*;
use common::{ADMIN, CHAIN, Chain, PRICE, RELAYER, SELLER, TOKEN, TREASURY, buyer, unhex};
use nucleus_proof_acceptance::{
    Policy, base,
    vault_program::{BaseWitness, Input, encode_with_base},
};
use nucleus_proof_commerce::vault;
use revm::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    state::{AccountInfo, Bytecode},
};
use sha2::{Digest, Sha256};

sol! {
    function register(bytes32 base, bytes32 axiomsHash, address payee, uint16 bps, bytes seal);
    function entryOf(bytes32 base) returns (address payee, uint16 bps);
    function axiomsOf(bytes32 base) returns (bytes32);
}

const REGISTRY_BIN: &str = include_str!("../../vault/out/BaseRegistry.bin");
const BASE_BYTES: &[u8] =
    include_bytes!("../../proof-acceptance/core/tests/fixtures/base/base.ndjson");
const STATEMENT: &[u8] =
    include_bytes!("../../proof-acceptance/core/tests/fixtures/base/task-on-base.ndjson");
const ARTIFACT: &[u8] =
    include_bytes!("../../proof-acceptance/core/tests/fixtures/base/suffix-on-base.ndjson");
const REAL_VERIFIER: Address = Address::new([
    0x8c, 0x91, 0x5b, 0x50, 0x71, 0x20, 0x6c, 0x6e, 0x32, 0x8b, 0xc1, 0x85, 0x29, 0x58, 0x6c, 0x51,
    0x34, 0x08, 0xab, 0x3b,
]);
/// The rate the fixture base was proved with, and the registry's ceiling.
const BPS: u16 = 10;
const MAXIMUM_BPS: u16 = 50;
const BASE_PROGRAM: [u8; 32] = [0xb0; 32];

fn registry(chain: &mut Chain, verifier: Address, program: [u8; 32]) -> Address {
    let constructor = (verifier, B256::from(program), MAXIMUM_BPS).abi_encode();
    chain.create([unhex(REGISTRY_BIN), constructor].concat())
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
/// What the TEST verifier accepts for a base journal under `program`.
fn test_base_seal(
    program: [u8; 32],
    base: [u8; 32],
    axioms: [u8; 32],
    payee: Address,
    bps: u16,
) -> Vec<u8> {
    let journal = base::journal(base, axioms, payee.into_array(), bps);
    let digest: [u8; 32] = Sha256::digest(journal).into();
    keccak256((B256::from(program), B256::from(digest)).abi_encode()).to_vec()
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

#[test]
fn an_entry_is_made_only_on_the_base_programs_proof_for_exactly_these_terms() {
    let mut chain = Chain::new();
    let verifier = chain.verifier;
    let registry = registry(&mut chain, verifier, BASE_PROGRAM);
    let (id, axioms) = (base::id(BASE_BYTES), base::axioms_hash(&[]));
    let seal = test_base_seal(BASE_PROGRAM, id, axioms, BASE_PAYEE, BPS);
    assert_eq!(entry(&mut chain, registry, id), (Address::ZERO, 0));

    // The proof is for one base, one axioms hash, one payee and one rate.
    let other = Address::new([0x0f; 20]);
    for call in [
        register_call([1; 32], axioms, BASE_PAYEE, BPS, seal.clone()),
        register_call(id, [2; 32], BASE_PAYEE, BPS, seal.clone()),
        register_call(id, axioms, other, BPS, seal.clone()),
        register_call(id, axioms, BASE_PAYEE, BPS + 1, seal.clone()),
        register_call(id, axioms, BASE_PAYEE, BPS, vec![0; 32]),
        // A proof by some other program.
        register_call(
            id,
            axioms,
            BASE_PAYEE,
            BPS,
            test_base_seal([0xb1; 32], id, axioms, BASE_PAYEE, BPS),
        ),
    ] {
        assert_eq!(chain.refused(other, registry, 1, call), "Refused");
    }
    // Terms the registry does not admit whatever the proof says.
    let over = test_base_seal(BASE_PROGRAM, id, axioms, BASE_PAYEE, MAXIMUM_BPS + 1);
    for call in [
        register_call(id, axioms, BASE_PAYEE, MAXIMUM_BPS + 1, over),
        register_call([0; 32], axioms, BASE_PAYEE, BPS, seal.clone()),
        register_call(id, axioms, Address::ZERO, BPS, seal.clone()),
    ] {
        assert_eq!(chain.refused(other, registry, 1, call), "InvalidEntry");
    }
    assert_eq!(entry(&mut chain, registry, id), (Address::ZERO, 0));

    // Anyone may submit the proof; the payee is the one the proof names.
    chain.must(
        other,
        registry,
        1,
        register_call(id, axioms, BASE_PAYEE, BPS, seal.clone()),
    );
    assert_eq!(entry(&mut chain, registry, id), (BASE_PAYEE, BPS));
    let recorded = chain.must(
        RELAYER,
        registry,
        1,
        axiomsOfCall { base: id.into() }.abi_encode(),
    );
    assert_eq!(recorded.as_ref(), axioms.as_slice());

    // The first valid proof decides: the same proof again, or a valid proof
    // of other terms for the same base, changes nothing.
    assert_eq!(
        chain.refused(
            other,
            registry,
            1,
            register_call(id, axioms, BASE_PAYEE, BPS, seal)
        ),
        "AlreadyRegistered"
    );
    let rival = test_base_seal(BASE_PROGRAM, id, axioms, other, 1);
    assert_eq!(
        chain.refused(
            other,
            registry,
            1,
            register_call(id, axioms, other, 1, rival)
        ),
        "AlreadyRegistered"
    );
    assert_eq!(entry(&mut chain, registry, id), (BASE_PAYEE, BPS));
}

#[test]
fn a_registry_without_a_verifier_or_program_or_with_a_ceiling_over_the_whole_cannot_be_created() {
    let mut chain = Chain::new();
    let verifier = chain.verifier;
    for constructor in [
        (Address::ZERO, B256::from(BASE_PROGRAM), MAXIMUM_BPS).abi_encode(),
        (verifier, B256::ZERO, MAXIMUM_BPS).abi_encode(),
        (verifier, B256::from(BASE_PROGRAM), 10_001u16).abi_encode(),
    ] {
        let code = [unhex(REGISTRY_BIN), constructor].concat();
        assert!(!matches!(
            chain.transact(ADMIN, revm::primitives::TxKind::Create, 1, code),
            revm::context_interface::result::ExecutionResult::Success { .. }
        ));
    }
}

/// Decision 22 (model: `ceilingWithinRoom` and `a_ceiling_past_the_room_strands_a_base`
/// in proofs/commerce/Vault3.lean): a vault refuses at construction a registry
/// whose ceiling does not fit in the room its fee leaves under its cap. With
/// fee 25 and cap 100 the room is 75 basis points.
#[test]
fn a_vault_refuses_a_registry_whose_ceiling_does_not_fit_under_its_fee_cap() {
    let mut chain = Chain::new();
    let verifier = chain.verifier;
    let vault_code = || unhex(VAULT3_BIN);
    for (ceiling, admitted) in [
        (0u16, true),
        (50, true),
        (75, true),
        (76, false),
        (10_000, false),
    ] {
        let constructor = (verifier, B256::from(BASE_PROGRAM), ceiling).abi_encode();
        let registry = chain.create([unhex(REGISTRY_BIN), constructor].concat());
        let deploy = (TREASURY, 25u16, 100u16, TERM, registry).abi_encode();
        let result = chain.transact(
            ADMIN,
            revm::primitives::TxKind::Create,
            1,
            [vault_code(), deploy].concat(),
        );
        let created = matches!(
            result,
            revm::context_interface::result::ExecutionResult::Success { .. }
        );
        assert_eq!(created, admitted, "ceiling {ceiling}: {result:?}");
    }
    // A registry that cannot say its ceiling (no code, or no `maximumBps`) is
    // refused too: the vault cannot check what it cannot read.
    for registry in [Address::new([0x77; 20]), chain.verifier] {
        let deploy = (TREASURY, 25u16, 100u16, TERM, registry).abi_encode();
        let result = chain.transact(
            ADMIN,
            revm::primitives::TxKind::Create,
            1,
            [vault_code(), deploy].concat(),
        );
        assert!(
            !matches!(
                result,
                revm::context_interface::result::ExecutionResult::Success { .. }
            ),
            "{registry}: {result:?}"
        );
    }
}

#[test]
fn a_vault_naming_the_registry_books_the_royalty_of_a_registered_base() {
    let mut chain = Chain::new();
    let verifier = chain.verifier;
    let registry = registry(&mut chain, verifier, BASE_PROGRAM);
    let mut w = World::with_registry(chain, registry);
    let (id, axioms) = (base::id(BASE_BYTES), base::axioms_hash(&[]));
    let mut o = w.order(1);
    o.base = id;

    // Before registration the base is unknown: the order funds with no royalty.
    let mut early = o.clone();
    early.salt = [2; 32];
    w.chain.mint(early.buyer.into(), PRICE);
    let call = w.fund_call(&early, &buyer());
    w.must(500, call);
    let call = w.settle_call(&early, b"work");
    w.must(600, call);
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), U256::ZERO);
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(997_500u64));

    let seal = test_base_seal(BASE_PROGRAM, id, axioms, BASE_PAYEE, BPS);
    w.chain.must(
        RELAYER,
        registry,
        1,
        register_call(id, axioms, BASE_PAYEE, BPS, seal),
    );
    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);
    let call = w.settle_call(&o, b"work");
    w.must(600, call);
    // 10 basis points of 1,000,000 to the base's payee, out of the seller's share.
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), U256::from(1_000u64));
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(997_500u64 + 996_500));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from(5_000u64));
    w.claim(700, BASE_PAYEE);
    assert_eq!(w.chain.balance(BASE_PAYEE), U256::from(1_000u64));
}

// ---- Real proofs.

fn policy() -> Policy {
    Policy {
        statement_sha256: Sha256::digest(STATEMENT).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
fn program(file: &str) -> [u8; 32] {
    unhex(file).try_into().unwrap()
}
/// The real verifier, a registry for the published base program, a vault
/// naming that registry, and the fixture order naming the fixture base.
fn real_world() -> (World, vault::Order) {
    let mut chain = Chain::new();
    let code = unhex(include_str!(
        "../../agents/fixtures/risc0-groth16-verifier-3.1.0.runtime.hex"
    ));
    chain.db.insert_account_info(
        REAL_VERIFIER,
        AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
    );
    let registry = registry(
        &mut chain,
        REAL_VERIFIER,
        program(include_str!("../fixtures/real-base.program.hex")),
    );
    let w = World::with_registry(chain, registry);
    let mut o = w.order(1);
    o.verifier = REAL_VERIFIER.into_array();
    o.program = program(include_str!("../fixtures/real-order-on-base.program.hex"));
    o.policy_hash = policy().hash();
    o.base = base::id(BASE_BYTES);
    (w, o)
}

#[test]
#[ignore = "writes the two guest inputs for the fixtures; run when regenerating the seals"]
fn emit() {
    let (w, o) = real_world();
    let base_input = base::Input {
        payee: BASE_PAYEE.into_array(),
        bps: BPS,
        permitted_axioms: vec![],
        base: BASE_BYTES.to_vec(),
    };
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/real-base.input"),
        base_input.encode(),
    )
    .unwrap();
    let input = Input {
        form: vault::Form::Third,
        chain_id: CHAIN,
        vault: w.vault.into_array(),
        order: o,
        policy: policy(),
        statement: STATEMENT.to_vec(),
        artifact: ARTIFACT.to_vec(),
    };
    let witness = BaseWitness {
        length: BASE_BYTES.len() as u32,
        payee: BASE_PAYEE.into_array(),
        bps: BPS,
    };
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/real-order-on-base.input"
        ),
        encode_with_base(&input, Some(&witness)),
    )
    .unwrap();
}

#[test]
fn a_real_base_proof_registers_and_a_real_composed_order_proof_books_the_royalty() {
    let (mut w, o) = real_world();
    let registry = w.registry;
    let (id, axioms) = (base::id(BASE_BYTES), base::axioms_hash(&[]));
    let base_seal = unhex(include_str!("../fixtures/real-base.seal.hex"));
    assert_eq!(base_seal.len(), 260);

    // The real base proof registers its own terms and no others.
    let other = Address::new([0x0f; 20]);
    for call in [
        register_call(id, axioms, other, BPS, base_seal.clone()),
        register_call(id, axioms, BASE_PAYEE, BPS + 1, base_seal.clone()),
        register_call([1; 32], axioms, BASE_PAYEE, BPS, base_seal.clone()),
        register_call(id, [2; 32], BASE_PAYEE, BPS, base_seal.clone()),
    ] {
        w.chain.refused(other, registry, 1, call);
    }
    let mut flipped = base_seal.clone();
    flipped[100] ^= 1;
    w.chain.refused(
        other,
        registry,
        1,
        register_call(id, axioms, BASE_PAYEE, BPS, flipped),
    );
    w.chain.must(
        other,
        registry,
        1,
        register_call(id, axioms, BASE_PAYEE, BPS, base_seal),
    );
    assert_eq!(entry(&mut w.chain, registry, id), (BASE_PAYEE, BPS));

    // The order names the base; funding reads the entry.
    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);

    let seal = unhex(include_str!("../fixtures/real-order-on-base.seal.hex"));
    assert_eq!(seal.len(), 260);
    // The order proof is for this order, base included: the same order
    // naming no base, or another base, is a different (unfunded) order, and
    // the seal is refused for another artifact.
    w.refused(1500, settle_with(&o, b"not the artifact", seal.clone()));
    let mut baseless = o.clone();
    baseless.base = [0; 32];
    assert_eq!(
        w.refused(1500, settle_with(&baseless, ARTIFACT, seal.clone())),
        "NotFunded"
    );
    // The base program's seal is not an order proof.
    let base_seal = unhex(include_str!("../fixtures/real-base.seal.hex"));
    w.refused(1500, settle_with(&o, ARTIFACT, base_seal));

    w.must(1500, settle_with(&o, ARTIFACT, seal));
    assert_eq!(w.phase(vault::digest(&w.deployment(), &o)), 2);
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), U256::from(1_000u64));
    assert_eq!(w.owed(SELLER, TOKEN), U256::from(996_500u64));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from(2_500u64));
    for payee in [SELLER, TREASURY, BASE_PAYEE] {
        w.claim(1600, payee);
    }
    assert_eq!(w.chain.balance(BASE_PAYEE), U256::from(1_000u64));
    let vault_address = w.vault;
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);
}
