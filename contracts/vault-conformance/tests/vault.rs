//! The compiled Solidity vault (contracts/vault/out, solc 0.8.38) in a local
//! EVM, with the real FiatToken bytecode as the payment token, compared with
//! the Rust reference `nucleus_proof_commerce::vault`.
//!
//! The vault is NucleusVault2 (model: proofs/commerce/Vault.lean): a
//! settlement books the fee and anyone may sweep a token's booked fees to the
//! treasury.
//!
//! Proofs here are the TEST verifier's publicly computable values; a real
//! proof is exercised in `real_proof.rs`. These tests are about the vault's
//! own rules.
mod common;
use alloy_sol_types::{SolCall, SolValue};
use common::*;
use k256::ecdsa::SigningKey;
use nucleus_proof_commerce::vault;
use revm::{
    context_interface::result::ExecutionResult,
    primitives::{Address, Bytes, TxKind, U256, keccak256},
};

#[test]
fn the_contract_computes_the_reference_digest_and_fee() {
    let mut chain = Chain::new();
    let vault = chain.vault;
    for salt in [0u8, 1, 0xff] {
        let mut o = order(&chain, salt);
        o.amount = keccak256([salt]).0;
        o.fund_by = u64::from(salt) * 7 + 1;
        o.deliver_by = u64::MAX - u64::from(salt);
        let on_chain = chain.must(RELAYER, vault, 1, digestCall { o: abi(&o) }.abi_encode());
        assert_eq!(on_chain.as_ref(), vault::digest(&chain.deployment(), &o));
    }
    let samples = [
        U256::from(1u64),
        U256::from(99u64),
        U256::from(9_999u64),
        U256::from(10_000u64),
        U256::from(10_001u64),
        U256::from(PRICE),
        U256::MAX,
    ]
    .into_iter()
    .chain((0u8..32).map(|n| U256::from_be_bytes(keccak256([n]).0)));
    for amount in samples {
        let mut o = order(&chain, 1);
        o.amount = amount.to_be_bytes();
        let on_chain = chain.must(RELAYER, vault, 1, feeOfCall { amount }.abi_encode());
        assert_eq!(
            on_chain.as_ref(),
            vault::payout(&chain.deployment(), &o).unwrap().protocol
        );
    }
}

#[test]
fn a_funded_order_settles_once_and_pays_seller_and_treasury() {
    let (mut chain, o) = funded(1);
    let (vault, digest) = (chain.vault, vault::digest(&chain.deployment(), &o));
    assert_eq!(chain.phase(digest), 1);
    assert_eq!(chain.balance(vault), U256::from(PRICE));
    assert_eq!(chain.balance(o.buyer.into()), U256::ZERO);

    let artifact = b"the delivered proof bytes";
    let seal = test_seal(&chain, &o, artifact);
    // A relayer settles; the caller is nobody in particular.
    chain.must(
        RELAYER,
        vault,
        1500,
        settle_call(&o, artifact, seal.clone()),
    );
    assert_eq!(chain.phase(digest), 2);
    assert_eq!(chain.balance(SELLER), U256::from(997_500u64));
    chain.collect(TOKEN);
    assert_eq!(chain.balance(TREASURY), U256::from(2_500u64));
    assert_eq!(chain.balance(vault), U256::ZERO);
    let recorded = chain.must(
        RELAYER,
        vault,
        1,
        artifactOfCall { d: digest.into() }.abi_encode(),
    );
    assert_eq!(recorded.as_ref(), keccak256(artifact).as_slice());

    assert_eq!(
        chain.refused(RELAYER, vault, 1500, settle_call(&o, artifact, seal)),
        "NotFunded"
    );
    assert_eq!(
        chain.refused(RELAYER, vault, 2001, refundCall { o: abi(&o) }.abi_encode()),
        "NotFunded"
    );
}

#[test]
fn settlement_needs_the_verifiers_acceptance_of_this_artifact_for_this_order() {
    let (mut chain, o) = funded(1);
    let vault = chain.vault;
    let artifact = b"the delivered proof bytes";
    let seal = test_seal(&chain, &o, artifact);
    assert_eq!(
        chain.refused(
            RELAYER,
            vault,
            1500,
            settle_call(&o, b"other bytes", seal.clone())
        ),
        "Refused"
    );
    assert_eq!(
        chain.refused(RELAYER, vault, 1500, settle_call(&o, artifact, vec![0; 32])),
        "Refused"
    );
    // A seal for another order of the same parties.
    let other = order(&chain, 2);
    assert_eq!(
        chain.refused(
            RELAYER,
            vault,
            1500,
            settle_call(&o, artifact, test_seal(&chain, &other, artifact))
        ),
        "Refused"
    );
    // An order altered after funding is a different, unfunded order.
    let mut redirected = o.clone();
    redirected.seller = [0x66; 20];
    let redirected_seal = test_seal(&chain, &redirected, artifact);
    assert_eq!(
        chain.refused(
            RELAYER,
            vault,
            1500,
            settle_call(&redirected, artifact, redirected_seal)
        ),
        "NotFunded"
    );
    // After the delivery deadline even a good seal is too late.
    assert_eq!(
        chain.refused(
            RELAYER,
            vault,
            2001,
            settle_call(&o, artifact, seal.clone())
        ),
        "DeliveryExpired"
    );
    assert_eq!(chain.balance(SELLER), U256::ZERO);
    chain.must(RELAYER, vault, 2000, settle_call(&o, artifact, seal));
    assert_eq!(chain.balance(SELLER), U256::from(997_500u64));
}

#[test]
fn an_undelivered_order_refunds_in_full_only_after_the_deadline() {
    let (mut chain, o) = funded(1);
    let (vault, digest) = (chain.vault, vault::digest(&chain.deployment(), &o));
    assert_eq!(
        chain.refused(RELAYER, vault, 2000, refundCall { o: abi(&o) }.abi_encode()),
        "DeadlineNotReached"
    );
    chain.must(RELAYER, vault, 2001, refundCall { o: abi(&o) }.abi_encode());
    assert_eq!(chain.phase(digest), 3);
    assert_eq!(chain.balance(o.buyer.into()), U256::from(PRICE));
    assert_eq!(chain.balance(TREASURY), U256::ZERO);
    assert_eq!(chain.balance(vault), U256::ZERO);
    assert_eq!(
        chain.refused(RELAYER, vault, 2002, refundCall { o: abi(&o) }.abi_encode()),
        "NotFunded"
    );
    let seal = test_seal(&chain, &o, b"late");
    assert_eq!(
        chain.refused(RELAYER, vault, 1500, settle_call(&o, b"late", seal)),
        "NotFunded"
    );
}

#[test]
fn funding_needs_the_buyers_authorization_for_exactly_this_order() {
    let mut chain = Chain::new();
    let vault = chain.vault;
    let o = order(&chain, 1);
    chain.mint(o.buyer.into(), 2 * PRICE);
    // Signed by someone else: the token refuses.
    let stranger = SigningKey::from_slice(&[2; 32]).unwrap();
    let forged = fund_call(&chain, &o, &stranger);
    assert_eq!(
        chain.refused(RELAYER, vault, 500, forged),
        "FiatTokenV2: invalid signature"
    );
    // The buyer's signature for this order does not fund a dearer one.
    let mut dearer = o.clone();
    dearer.amount = U256::from(2 * PRICE).to_be_bytes();
    let signature = sign(
        &buyer(),
        vault::authorization_digest(&chain.deployment(), &token_domain(), &o).unwrap(),
    );
    let swapped = fundCall {
        o: abi(&dearer),
        authorization: Bytes::copy_from_slice(&signature.0),
    }
    .abi_encode();
    assert_eq!(
        chain.refused(RELAYER, vault, 500, swapped),
        "FiatTokenV2: invalid signature"
    );
    // Past the funding deadline.
    let good = fund_call(&chain, &o, &buyer());
    assert_eq!(
        chain.refused(RELAYER, vault, 1001, good.clone()),
        "FundingExpired"
    );
    assert_eq!(chain.balance(vault), U256::ZERO);
    chain.must(RELAYER, vault, 1000, good.clone());
    assert_eq!(chain.refused(RELAYER, vault, 1000, good), "NotEmpty");
    assert_eq!(chain.balance(vault), U256::from(PRICE));
}

#[test]
fn the_contract_refuses_what_the_reference_refuses() {
    let mut chain = Chain::new();
    let vault = chain.vault;
    type Case = (fn(&mut vault::Order), &'static str);
    let cases: [Case; 7] = [
        (|o| o.amount = [0; 32], "InvalidOrder"),
        (|o| o.seller = [0; 20], "InvalidOrder"),
        (|o| o.verifier = [0; 20], "InvalidOrder"),
        (|o| o.program = [0; 32], "InvalidOrder"),
        (|o| o.policy_hash = [0; 32], "InvalidOrder"),
        (|o| o.deliver_by = o.fund_by, "InvalidOrder"),
        (
            |o| o.amount = U256::from(99u64).to_be_bytes(),
            "FeeExceedsCap",
        ),
    ];
    for (change, expected) in cases {
        let mut bad = order(&chain, 1);
        change(&mut bad);
        // The reference refuses it too.
        assert!(
            vault::admissible(&chain.deployment(), &bad, 500).is_err(),
            "{expected}"
        );
        let call = fundCall {
            o: abi(&bad),
            authorization: Bytes::copy_from_slice(&[0; 65]),
        }
        .abi_encode();
        assert_eq!(chain.refused(RELAYER, vault, 500, call), expected);
    }
    let mut to_self = order(&chain, 1);
    to_self.seller = vault.into_array();
    let call = fundCall {
        o: abi(&to_self),
        authorization: Bytes::copy_from_slice(&[0; 65]),
    }
    .abi_encode();
    assert_eq!(chain.refused(RELAYER, vault, 500, call), "InvalidOrder");
    let short = fundCall {
        o: abi(&order(&chain, 1)),
        authorization: Bytes::copy_from_slice(&[0; 64]),
    }
    .abi_encode();
    assert_eq!(
        chain.refused(RELAYER, vault, 500, short),
        "BadSignatureLength"
    );
}

#[test]
fn a_deployment_with_no_fee_or_an_excessive_cap_cannot_be_created() {
    let mut chain = Chain::new();
    let code = unhex(VAULT_BIN);
    for constructor in [
        (TREASURY, 0u16, 100u16).abi_encode(),
        (TREASURY, 101u16, 100u16).abi_encode(),
        (TREASURY, 25u16, 10_001u16).abi_encode(),
        (Address::ZERO, 25u16, 100u16).abi_encode(),
    ] {
        let result = chain.transact(
            ADMIN,
            TxKind::Create,
            1,
            [code.clone(), constructor].concat(),
        );
        assert!(
            matches!(result, ExecutionResult::Revert { .. }),
            "{result:?}"
        );
    }
}

// ---- Fees are booked by a settlement and swept by anyone.

fn accrued(chain: &mut Chain) -> U256 {
    let vault = chain.vault;
    U256::from_be_slice(&chain.must(RELAYER, vault, 1, accruedCall { asset: TOKEN }.abi_encode()))
}
fn sweep() -> Vec<u8> {
    sweepCall { asset: TOKEN }.abi_encode()
}
fn settle(chain: &mut Chain, o: &vault::Order) {
    let seal = test_seal(chain, o, b"work");
    let vault = chain.vault;
    chain.must(RELAYER, vault, 1500, settle_call(o, b"work", seal));
}

#[test]
fn a_settlement_books_the_fee_and_anyone_may_sweep_it_to_the_treasury() {
    let (mut chain, o) = funded(1);
    let vault = chain.vault;
    assert_eq!(
        chain.refused(RELAYER, vault, 1500, sweep()),
        "NothingAccrued"
    );
    settle(&mut chain, &o);
    assert_eq!(chain.balance(SELLER), U256::from(997_500u64));
    assert_eq!(chain.balance(TREASURY), U256::ZERO);
    assert_eq!(chain.balance(vault), U256::from(2_500u64));
    assert_eq!(accrued(&mut chain), U256::from(2_500u64));

    // The seller, a stranger, anyone.
    chain.must(SELLER, vault, 1600, sweep());
    assert_eq!(chain.balance(TREASURY), U256::from(2_500u64));
    assert_eq!(chain.balance(vault), U256::ZERO);
    assert_eq!(accrued(&mut chain), U256::ZERO);
    assert_eq!(
        chain.refused(RELAYER, vault, 1700, sweep()),
        "NothingAccrued"
    );
}

#[test]
fn fees_from_several_orders_accumulate_and_a_sweep_never_touches_a_deposit() {
    let mut chain = Chain::new();
    let vault = chain.vault;
    let orders: Vec<vault::Order> = (1..=3).map(|salt| order(&chain, salt)).collect();
    for o in &orders {
        chain.mint(o.buyer.into(), PRICE);
        let call = fund_call(&chain, o, &buyer());
        chain.must(RELAYER, vault, 500, call);
    }
    settle(&mut chain, &orders[0]);
    settle(&mut chain, &orders[1]);
    // Two fees booked; the third order's deposit is still held.
    assert_eq!(accrued(&mut chain), U256::from(5_000u64));
    assert_eq!(chain.balance(vault), U256::from(PRICE + 5_000));
    chain.must(RELAYER, vault, 1600, sweep());
    assert_eq!(chain.balance(TREASURY), U256::from(5_000u64));
    assert_eq!(chain.balance(vault), U256::from(PRICE));
    // The held order still refunds in full after its deadline.
    chain.must(
        RELAYER,
        vault,
        2001,
        refundCall { o: abi(&orders[2]) }.abi_encode(),
    );
    assert_eq!(chain.balance(orders[2].buyer.into()), U256::from(PRICE));
    assert_eq!(chain.balance(vault), U256::ZERO);
}

/// The finding this contract answers: the token refuses to pay the treasury.
/// Orders settle and refund regardless; only the sweep waits.
#[test]
fn a_treasury_the_token_refuses_to_pay_blocks_no_order() {
    let mut chain = Chain::new();
    let vault = chain.vault;
    let (paid, returned) = (order(&chain, 1), order(&chain, 2));
    for o in [&paid, &returned] {
        chain.mint(o.buyer.into(), PRICE);
        let call = fund_call(&chain, o, &buyer());
        chain.must(RELAYER, vault, 500, call);
    }
    chain.must(
        ADMIN,
        TOKEN,
        1,
        blacklistCall { account: TREASURY }.abi_encode(),
    );
    settle(&mut chain, &paid);
    assert_eq!(chain.balance(SELLER), U256::from(997_500u64));
    chain.must(
        RELAYER,
        vault,
        2001,
        refundCall { o: abi(&returned) }.abi_encode(),
    );
    assert_eq!(chain.balance(returned.buyer.into()), U256::from(PRICE));

    assert_eq!(
        chain.refused(RELAYER, vault, 2002, sweep()),
        "InexactPayout"
    );
    assert_eq!(accrued(&mut chain), U256::from(2_500u64));
    chain.must(
        ADMIN,
        TOKEN,
        1,
        unBlacklistCall { account: TREASURY }.abi_encode(),
    );
    chain.must(RELAYER, vault, 2003, sweep());
    assert_eq!(chain.balance(TREASURY), U256::from(2_500u64));
    assert_eq!(accrued(&mut chain), U256::ZERO);
}
