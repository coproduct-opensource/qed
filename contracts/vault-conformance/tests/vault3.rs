//! The compiled NucleusVault3 in a local EVM with real FiatToken bytecode,
//! compared with the Rust reference (`vault::Rules::Third`) and the model
//! (proofs/commerce/Vault3.lean). Proofs here are the TEST verifier's
//! publicly computable values; a real proof is in `real_proof3.rs`.
mod common;
use alloy_sol_types::{SolCall, SolValue};
use common::third::*;
use common::{
    ADMIN, PRICE, RELAYER, SELLER, TOKEN, TREASURY, blacklistCall, buyer, sign, token_domain,
    unBlacklistCall, unhex,
};
use k256::ecdsa::SigningKey;
use nucleus_proof_commerce::vault;
use revm::{
    context_interface::result::ExecutionResult,
    primitives::{Address, Bytes, TxKind, U256, keccak256},
};

fn units(n: u64) -> U256 {
    U256::from(n)
}
fn buyer_address(o: &vault::Order) -> Address {
    o.buyer.into()
}

#[test]
fn the_contract_computes_the_reference_digest_and_fee() {
    let mut w = World::new();
    for salt in [0u8, 1, 0xff] {
        let mut o = w.order(salt);
        o.amount = keccak256([salt]).0;
        o.base = if salt == 1 {
            [0; 32]
        } else {
            keccak256([salt, 1]).0
        };
        o.fund_by = u64::from(salt) * 7 + 1;
        o.deliver_by = u64::MAX - u64::from(salt);
        let on_chain = w.must(1, digestCall { o: abi(&o) }.abi_encode());
        assert_eq!(on_chain.as_ref(), vault::digest(&w.deployment(), &o));
        // Not the second form's digest for the same fields.
        let mut second = w.deployment();
        second.rules = vault::Rules::Second;
        assert_ne!(on_chain.as_ref(), vault::digest(&second, &o));
    }
    let samples = [1u64, 99, 9_999, 10_000, 10_001, PRICE]
        .map(U256::from)
        .into_iter()
        .chain([U256::MAX])
        .chain((0u8..32).map(|n| U256::from_be_bytes(keccak256([n]).0)));
    for amount in samples {
        let mut o = w.order(1);
        o.amount = amount.to_be_bytes();
        let on_chain = w.must(1, common::feeOfCall { amount }.abi_encode());
        assert_eq!(
            on_chain.as_ref(),
            vault::payout(&w.deployment(), &o).unwrap().protocol
        );
    }
}

#[test]
fn a_settlement_books_what_is_owed_and_only_a_claim_pays() {
    let (mut w, o) = World::funded(1);
    let (vault_address, digest) = (w.vault, vault::digest(&w.deployment(), &o));
    assert_eq!(w.phase(digest), 1);
    assert_eq!(w.chain.balance(vault_address), units(PRICE));
    assert_eq!(w.chain.balance(buyer_address(&o)), U256::ZERO);

    let artifact = b"the delivered proof bytes";
    let call = w.settle_call(&o, artifact);
    w.must(1500, call.clone());
    assert_eq!(w.phase(digest), 2);
    let recorded = w.must(1, common::artifactOfCall { d: digest.into() }.abi_encode());
    assert_eq!(recorded.as_ref(), keccak256(artifact).as_slice());
    // Booked, not paid: the vault still holds the whole deposit.
    assert_eq!(w.chain.balance(vault_address), units(PRICE));
    assert_eq!(w.chain.balance(SELLER), U256::ZERO);
    assert_eq!(w.chain.balance(TREASURY), U256::ZERO);
    let (split, payee) = vault::split(&w.deployment(), &o, None).unwrap();
    assert_eq!(payee, None);
    assert_eq!(w.owed(SELLER, TOKEN), U256::from_be_bytes(split.seller));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::from_be_bytes(split.protocol));
    assert_eq!(w.owed(SELLER, TOKEN), units(997_500));
    assert_eq!(w.owed(TREASURY, TOKEN), units(2_500));

    // Anyone claims for the seller; the seller is paid exactly once.
    w.claim(1600, SELLER);
    assert_eq!(w.chain.balance(SELLER), units(997_500));
    assert_eq!(w.owed(SELLER, TOKEN), U256::ZERO);
    assert_eq!(w.chain.balance(vault_address), units(2_500));
    let again = claimCall {
        payee: SELLER,
        asset: TOKEN,
    }
    .abi_encode();
    assert_eq!(w.refused(1600, again), "NothingOwed");
    w.claim(1700, TREASURY);
    assert_eq!(w.chain.balance(TREASURY), units(2_500));
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);

    // Settled is final.
    assert_eq!(w.refused(1500, call), "NotFunded");
    assert_eq!(w.refused(2001, refund_call(&o)), "NotFunded");
    assert_eq!(w.owed(buyer_address(&o), TOKEN), U256::ZERO);
}

#[test]
fn settlement_needs_the_verifiers_acceptance_of_this_artifact_for_this_order() {
    let (mut w, o) = World::funded(1);
    let artifact = b"the delivered proof bytes";
    let seal = w.test_seal(&o, artifact);
    assert_eq!(
        w.refused(1500, settle_with(&o, b"other bytes", seal.clone())),
        "Refused"
    );
    assert_eq!(
        w.refused(1500, settle_with(&o, artifact, vec![0; 32])),
        "Refused"
    );
    // A seal for another order of the same parties.
    let other = w.order(2);
    let other_seal = w.test_seal(&other, artifact);
    assert_eq!(
        w.refused(1500, settle_with(&o, artifact, other_seal)),
        "Refused"
    );
    // A seal made for the second form's digest of the same fields.
    let mut second = w.deployment();
    second.rules = vault::Rules::Second;
    let journal = vault::acceptance_journal(&second, &o, keccak256(artifact).0);
    let journal_digest: [u8; 32] = sha2::Sha256::digest(journal).into();
    use sha2::Digest as _;
    let second_seal = keccak256(
        (
            revm::primitives::B256::from(o.program),
            revm::primitives::B256::from(journal_digest),
        )
            .abi_encode(),
    )
    .to_vec();
    assert_eq!(
        w.refused(1500, settle_with(&o, artifact, second_seal)),
        "Refused"
    );
    // An order altered after funding is a different, unfunded order.
    let mut redirected = o.clone();
    redirected.seller = [0x66; 20];
    let call = w.settle_call(&redirected, artifact);
    assert_eq!(w.refused(1500, call), "NotFunded");
    // After the delivery deadline even a good seal is too late.
    assert_eq!(
        w.refused(2001, settle_with(&o, artifact, seal.clone())),
        "DeliveryExpired"
    );
    assert_eq!(w.owed(SELLER, TOKEN), U256::ZERO);
    w.must(2000, settle_with(&o, artifact, seal));
    assert_eq!(w.owed(SELLER, TOKEN), units(997_500));
}

#[test]
fn an_undelivered_order_is_booked_back_to_the_buyer_only_after_the_deadline() {
    let (mut w, o) = World::funded(1);
    let (vault_address, digest) = (w.vault, vault::digest(&w.deployment(), &o));
    let buyer_address = buyer_address(&o);
    assert_eq!(w.refused(2000, refund_call(&o)), "DeadlineNotReached");
    w.must(2001, refund_call(&o));
    assert_eq!(w.phase(digest), 3);
    // Booked, not paid.
    assert_eq!(w.chain.balance(buyer_address), U256::ZERO);
    assert_eq!(w.owed(buyer_address, TOKEN), units(PRICE));
    assert_eq!(w.owed(TREASURY, TOKEN), U256::ZERO);
    assert_eq!(w.owed(SELLER, TOKEN), U256::ZERO);
    w.claim(2002, buyer_address);
    assert_eq!(w.chain.balance(buyer_address), units(PRICE));
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);
    // Refunded is final.
    assert_eq!(w.refused(2002, refund_call(&o)), "NotFunded");
    let late = w.settle_call(&o, b"late");
    assert_eq!(w.refused(1500, late), "NotFunded");
}

#[test]
fn funding_needs_the_buyers_authorization_for_exactly_this_order() {
    let mut w = World::new();
    let vault_address = w.vault;
    let o = w.order(1);
    w.chain.mint(o.buyer.into(), 2 * PRICE);
    let stranger = SigningKey::from_slice(&[2; 32]).unwrap();
    let forged = w.fund_call(&o, &stranger);
    assert_eq!(w.refused(500, forged), "FiatTokenV2: invalid signature");
    // The buyer's signature for this order does not fund a dearer one, nor
    // the same order with a base added.
    let signature = sign(
        &buyer(),
        vault::authorization_digest(&w.deployment(), &token_domain(), &o).unwrap(),
    );
    for change in [
        (|x: &mut vault::Order| x.amount = U256::from(2 * PRICE).to_be_bytes())
            as fn(&mut vault::Order),
        |x| x.base = BASE,
    ] {
        let mut other = o.clone();
        change(&mut other);
        let swapped = fundCall {
            o: abi(&other),
            authorization: Bytes::copy_from_slice(&signature.0),
        }
        .abi_encode();
        assert_eq!(w.refused(500, swapped), "FiatTokenV2: invalid signature");
    }
    // An authorization signed for the second form's digest does not fund here.
    let mut second = w.deployment();
    second.rules = vault::Rules::Second;
    let for_second = sign(
        &buyer(),
        vault::authorization_digest(&second, &token_domain(), &o).unwrap(),
    );
    let cross = fundCall {
        o: abi(&o),
        authorization: Bytes::copy_from_slice(&for_second.0),
    }
    .abi_encode();
    assert_eq!(w.refused(500, cross), "FiatTokenV2: invalid signature");

    let good = w.fund_call(&o, &buyer());
    assert_eq!(w.refused(1001, good.clone()), "FundingExpired");
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);
    w.must(1000, good.clone());
    assert_eq!(w.refused(1000, good), "NotEmpty");
    assert_eq!(w.chain.balance(vault_address), units(PRICE));
}

#[test]
fn the_contract_refuses_what_the_reference_refuses() {
    let mut w = World::new();
    let vault_address = w.vault;
    type Case = (fn(&mut vault::Order), &'static str);
    let cases: [Case; 8] = [
        (|o| o.amount = [0; 32], "InvalidOrder"),
        (|o| o.buyer = [0; 20], "InvalidOrder"),
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
    let fund_unsigned = |o: &vault::Order| {
        fundCall {
            o: abi(o),
            authorization: Bytes::copy_from_slice(&[0; 65]),
        }
        .abi_encode()
    };
    for (change, expected) in cases {
        let mut bad = w.order(1);
        change(&mut bad);
        assert!(
            vault::admissible(&w.deployment(), &bad, 500).is_err(),
            "{expected}"
        );
        assert_eq!(w.refused(500, fund_unsigned(&bad)), expected);
    }
    for party in [
        (|o: &mut vault::Order, v: [u8; 20]| o.seller = v) as fn(&mut vault::Order, [u8; 20]),
        |o, v| o.buyer = v,
    ] {
        let mut to_self = w.order(1);
        party(&mut to_self, vault_address.into_array());
        assert!(vault::admissible(&w.deployment(), &to_self, 500).is_err());
        assert_eq!(w.refused(500, fund_unsigned(&to_self)), "InvalidOrder");
    }
}

#[test]
fn the_delivery_deadline_is_at_most_the_term_after_funding() {
    let mut w = World::new();
    let mut o = w.order(1);
    o.fund_by = 1000;
    o.deliver_by = 500 + TERM;
    w.chain.mint(o.buyer.into(), PRICE);
    let call = w.fund_call(&o, &buyer());
    // One second too early for this deadline; on the boundary it funds.
    assert_eq!(
        vault::admissible(&w.deployment(), &o, 499).err(),
        Some(vault::Error::TermTooLong)
    );
    assert_eq!(w.refused(499, call.clone()), "TermTooLong");
    assert!(vault::admissible(&w.deployment(), &o, 500).is_ok());
    w.must(500, call);
    // So the refund opens no later than the term after funding.
    assert_eq!(w.refused(500 + TERM, refund_call(&o)), "DeadlineNotReached");
    w.must(500 + TERM + 1, refund_call(&o));

    let mut forever = w.order(2);
    forever.deliver_by = u64::MAX;
    let call = fundCall {
        o: abi(&forever),
        authorization: Bytes::copy_from_slice(&[0; 65]),
    }
    .abi_encode();
    assert_eq!(w.refused(500, call), "TermTooLong");
}

#[test]
fn a_bad_deployment_cannot_be_created() {
    let mut w = World::new();
    let code = unhex(VAULT3_BIN);
    let registry = w.registry;
    for constructor in [
        (TREASURY, 0u16, 100u16, TERM, registry).abi_encode(),
        (TREASURY, 101u16, 100u16, TERM, registry).abi_encode(),
        (TREASURY, 25u16, 10_001u16, TERM, registry).abi_encode(),
        (Address::ZERO, 25u16, 100u16, TERM, registry).abi_encode(),
        (TREASURY, 25u16, 100u16, 0u64, registry).abi_encode(),
        (TREASURY, 25u16, 100u16, TERM, Address::ZERO).abi_encode(),
    ] {
        let result = w.chain.transact(
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

// ---- Nothing but a claim pays, and a payee the token refuses blocks only itself.

fn blacklist(w: &mut World, account: Address, on: bool) {
    let call = if on {
        blacklistCall { account }.abi_encode()
    } else {
        unBlacklistCall { account }.abi_encode()
    };
    w.chain.must(ADMIN, TOKEN, 1, call);
}

#[test]
fn a_payee_the_token_refuses_blocks_its_own_claim_and_nothing_else() {
    let mut w = World::new();
    w.set_entry(BASE, BASE_PAYEE, 50);
    let mut paid = w.order(1);
    paid.base = BASE;
    let returned = w.order(2);
    let later = w.order(3);
    let buyer_address = buyer_address(&paid);
    w.chain.mint(buyer_address, 3 * PRICE);
    for o in [&paid, &returned] {
        let call = w.fund_call(o, &buyer());
        w.must(500, call);
    }
    // Every payee of these orders is blacklisted after funding, the buyer too.
    for account in [SELLER, TREASURY, BASE_PAYEE, buyer_address] {
        blacklist(&mut w, account, true);
    }
    let call = w.settle_call(&paid, b"work");
    w.must(1500, call);
    w.must(2001, refund_call(&returned));
    assert_eq!(w.owed(SELLER, TOKEN), units(992_500));
    assert_eq!(w.owed(TREASURY, TOKEN), units(2_500));
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), units(5_000));
    assert_eq!(w.owed(buyer_address, TOKEN), units(PRICE));
    // Each one's claim, and only that, fails; what it is owed stays booked.
    for account in [SELLER, TREASURY, BASE_PAYEE, buyer_address] {
        let call = claimCall {
            payee: account,
            asset: TOKEN,
        }
        .abi_encode();
        assert_eq!(w.refused(2002, call), "InexactPayout");
    }
    assert_eq!(w.owed(SELLER, TOKEN), units(992_500));
    // One is cleared and claims; the others still cannot.
    blacklist(&mut w, SELLER, false);
    w.claim(2003, SELLER);
    assert_eq!(w.chain.balance(SELLER), units(992_500));
    let call = claimCall {
        payee: TREASURY,
        asset: TOKEN,
    }
    .abi_encode();
    assert_eq!(w.refused(2003, call), "InexactPayout");
    // A blacklisted buyer cannot fund (the token refuses the deposit), which
    // is the token's rule, not the vault's.
    let call = w.fund_call(&later, &buyer());
    assert!(w.refused(600, call).contains("blacklisted"));
    for account in [TREASURY, BASE_PAYEE, buyer_address] {
        blacklist(&mut w, account, false);
        w.claim(2004, account);
    }
    assert_eq!(w.chain.balance(TREASURY), units(2_500));
    assert_eq!(w.chain.balance(BASE_PAYEE), units(5_000));
    assert_eq!(w.chain.balance(buyer_address), units(2 * PRICE));
    let vault_address = w.vault;
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);
}

#[test]
fn what_coinciding_payees_are_owed_adds_up_and_held_deposits_are_untouched() {
    let mut w = World::new();
    // The seller is also the treasury and the base's payee.
    w.set_entry(BASE, TREASURY, 50);
    let mut all_one = w.order(1);
    all_one.seller = TREASURY.into_array();
    all_one.base = BASE;
    let held = w.order(2);
    w.chain.mint(all_one.buyer.into(), 2 * PRICE);
    for o in [&all_one, &held] {
        let call = w.fund_call(o, &buyer());
        w.must(500, call);
    }
    let call = w.settle_call(&all_one, b"work");
    w.must(1500, call);
    assert_eq!(w.owed(TREASURY, TOKEN), units(PRICE));
    w.claim(1600, TREASURY);
    assert_eq!(w.chain.balance(TREASURY), units(PRICE));
    // The other order's deposit is still there, and still refunds in full.
    let vault_address = w.vault;
    assert_eq!(w.chain.balance(vault_address), units(PRICE));
    w.must(2001, refund_call(&held));
    w.claim(2002, held.buyer.into());
    assert_eq!(w.chain.balance(held.buyer.into()), units(PRICE));
    assert_eq!(w.chain.balance(vault_address), U256::ZERO);
}

// ---- Royalty.

#[test]
fn a_registered_base_is_owed_a_royalty_out_of_the_sellers_share_inside_the_cap() {
    let mut w = World::new();
    let buyer_address: Address = wallet_of_buyer();
    w.chain.mint(buyer_address, 4 * PRICE);
    let entry = |bps| vault::Entry {
        payee: BASE_PAYEE.into_array(),
        bps,
    };
    // 75 bps with the 25 bps fee is exactly the 100 bps cap.
    w.set_entry(BASE, BASE_PAYEE, 75);
    let mut o = w.order(1);
    o.base = BASE;
    assert!(vault::admissible_with(&w.deployment(), &o, Some(&entry(75)), 500).is_ok());
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);
    let digest = vault::digest(&w.deployment(), &o);
    let stored = w.must(1, royaltyOfCall { d: digest.into() }.abi_encode());
    let (split, payee) = vault::split(&w.deployment(), &o, Some(&entry(75))).unwrap();
    assert_eq!(payee, Some(BASE_PAYEE.into_array()));
    assert_eq!(&stored[12..32], BASE_PAYEE.as_slice());
    assert_eq!(stored[32..], split.royalty);
    let call = w.settle_call(&o, b"work");
    w.must(1500, call);
    assert_eq!(w.owed(SELLER, TOKEN), U256::from_be_bytes(split.seller));
    assert_eq!(w.owed(SELLER, TOKEN), units(990_000));
    assert_eq!(w.owed(TREASURY, TOKEN), units(2_500));
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), units(7_500));

    // One basis point more and the order is not admitted.
    w.set_entry(BASE, BASE_PAYEE, 76);
    let mut over = w.order(2);
    over.base = BASE;
    assert_eq!(
        vault::admissible_with(&w.deployment(), &over, Some(&entry(76)), 500).err(),
        Some(vault::Error::FeeExceedsCap)
    );
    let call = w.fund_call(&over, &buyer());
    assert_eq!(w.refused(500, call), "FeeExceedsCap");

    // A base the registry does not know, a zero payee, or the vault as
    // payee: no royalty, and the order is otherwise ordinary.
    let vault_address = w.vault;
    for (salt, base, payee) in [
        (3u8, [0xcc; 32], None),
        (4, [0xdd; 32], Some(Address::ZERO)),
        (5, [0xee; 32], Some(vault_address)),
    ] {
        if let Some(payee) = payee {
            w.set_entry(base, payee, 75);
        }
        let mut plain = w.order(salt);
        plain.base = base;
        w.chain.mint(buyer_address, PRICE);
        let call = w.fund_call(&plain, &buyer());
        w.must(500, call);
        let d = vault::digest(&w.deployment(), &plain);
        let stored = w.must(1, royaltyOfCall { d: d.into() }.abi_encode());
        assert_eq!(stored.as_ref(), [0u8; 64]);
    }
}

fn wallet_of_buyer() -> Address {
    common::wallet(&buyer()).into()
}

#[test]
fn a_registry_can_fail_a_funding_but_cannot_touch_a_funded_order() {
    let mut w = World::new();
    w.chain.mint(wallet_of_buyer(), 3 * PRICE);
    w.set_entry(BASE, BASE_PAYEE, 50);
    let mut based = w.order(1);
    based.base = BASE;
    // Reverting, burning its gas, a short or long reply, a payee or rate out
    // of range, or a revert whose data looks like an entry: funding an order
    // that names a base fails, cleanly.
    for mode in 1u8..=7 {
        w.set_mode(mode);
        let call = w.fund_call(&based, &buyer());
        assert_eq!(w.refused(500, call), "RegistryFailed", "mode {mode}");
        // An order with no base never asks the registry.
        let plain = w.order(10 + mode);
        w.chain.mint(wallet_of_buyer(), PRICE);
        let call = w.fund_call(&plain, &buyer());
        w.must(500, call);
    }
    w.set_mode(0);
    let call = w.fund_call(&based, &buyer());
    w.must(500, call);
    // After funding: the entry changes, then the registry breaks. The order
    // settles on what was fixed at funding.
    w.set_entry(BASE, Address::new([0x99; 20]), 75);
    w.set_mode(1);
    let call = w.settle_call(&based, b"work");
    w.must(1500, call);
    assert_eq!(w.owed(BASE_PAYEE, TOKEN), units(5_000));
    assert_eq!(w.owed(Address::new([0x99; 20]), TOKEN), U256::ZERO);
    assert_eq!(w.owed(SELLER, TOKEN), units(992_500));
    // A second funded order refunds with the registry still broken.
    w.set_mode(0);
    let mut other = w.order(2);
    other.base = BASE;
    let call = w.fund_call(&other, &buyer());
    w.must(500, call);
    w.set_mode(2);
    w.must(2001, refund_call(&other));
    assert_eq!(w.owed(wallet_of_buyer(), TOKEN), units(PRICE));
    w.claim(2002, BASE_PAYEE);
    assert_eq!(w.chain.balance(BASE_PAYEE), units(5_000));
}

// ---- Contract-wallet buyers.

#[test]
fn a_contract_wallet_funds_with_a_signature_only_it_can_judge() {
    let mut w = World::new();
    let wallet_bin = unhex(include_str!("../../vault/out/TestWallet.bin"));
    // One wallet accepts a 40-byte blob, another a 65-byte one; neither is a
    // key signature. The 40 bytes reach the token as bytes. The 65 bytes
    // reach it as (r, s, v), which FiatToken v2.2 packs back together and
    // puts to the wallet, so the vault needs no rule of its own for it.
    for (salt, accepted) in [(1u8, vec![0xa5u8; 40]), (2, vec![0x5au8; 65])] {
        let constructor = (Bytes::from(accepted.clone()),).abi_encode_params();
        let wallet = w.chain.create([wallet_bin.clone(), constructor].concat());
        w.chain.mint(wallet, PRICE);
        let mut o = w.order(salt);
        o.buyer = wallet.into_array();
        let fund = |authorization: &[u8]| {
            fundCall {
                o: abi(&o),
                authorization: Bytes::copy_from_slice(authorization),
            }
            .abi_encode()
        };
        // A signature the wallet does not accept, and a real key's signature.
        let mut wrong = accepted.clone();
        wrong[0] ^= 1;
        assert_eq!(
            w.refused(500, fund(&wrong)),
            "FiatTokenV2: invalid signature"
        );
        let keyed = sign(
            &buyer(),
            vault::authorization_digest(&w.deployment(), &token_domain(), &o).unwrap(),
        );
        assert_eq!(
            w.refused(500, fund(&keyed.0)),
            "FiatTokenV2: invalid signature"
        );
        let vault_address = w.vault;
        let before = w.chain.balance(vault_address);
        w.must(500, fund(&accepted));
        assert_eq!(w.chain.balance(vault_address) - before, units(PRICE));
        assert_eq!(w.chain.balance(wallet), U256::ZERO);
        // The refund is booked to the wallet and claimable by anyone for it.
        w.must(2001, refund_call(&o));
        w.claim(2002, wallet);
        assert_eq!(w.chain.balance(wallet), units(PRICE));
    }
    // An ordinary account still funds with a 65-byte key signature only.
    let o = w.order(3);
    w.chain.mint(o.buyer.into(), PRICE);
    let short = fundCall {
        o: abi(&o),
        authorization: Bytes::copy_from_slice(&[0; 64]),
    }
    .abi_encode();
    // 64 bytes is not a key signature; the token, not the vault, says so.
    assert_eq!(w.refused(500, short), "ECRecover: invalid signature length");
    let call = w.fund_call(&o, &buyer());
    w.must(500, call);
    let _ = RELAYER;
}
