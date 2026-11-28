use super::*;
use crate::tests_support::{sign, wallet};
use crate::uint;
use base64::Engine;
use k256::ecdsa::SigningKey;

fn buyer() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}
fn deployment() -> Deployment {
    Deployment {
        chain_id: 84532,
        vault: [3; 20],
        treasury: [5; 20],
        fee_bps: 25,
        maximum_fee_bps: 100,
        rules: crate::vault::Rules::Second,
    }
}
fn token() -> TokenDomain {
    TokenDomain {
        name: "USDC".into(),
        version: "2".into(),
    }
}
fn order() -> Order {
    Order {
        buyer: wallet(&buyer()),
        seller: [2; 20],
        asset: [4; 20],
        amount: uint(1_000_000),
        verifier: [6; 20],
        program: [7; 32],
        policy_hash: [9; 32],
        base: [0; 32],
        fund_by: 1000,
        deliver_by: 2000,
        salt: [10; 32],
        context: [11; 32],
    }
}
fn intent() -> Intent {
    Intent {
        wallet: wallet(&buyer()),
        asset: [4; 20],
        policy_hash: [9; 32],
        context: [11; 32],
        maximum_amount: uint(1_000_000),
        verifiers: vec![[6; 20]],
        programs: vec![[7; 32]],
        fund_no_earlier_than: 100,
        deliver_no_later_than: 2000,
        bases: vec![],
    }
}
fn offer(order: &Order) -> String {
    required_header(
        serde_json::json!({"url": "https://seller.example/work"}),
        requirements(&deployment(), &token(), order, 60),
    )
    .unwrap()
}
fn reencode(header: &str, change: impl FnOnce(&mut serde_json::Value)) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut value: serde_json::Value =
        serde_json::from_slice(&engine.decode(header).unwrap()).unwrap();
    change(&mut value);
    engine.encode(serde_json::to_vec(&value).unwrap())
}
fn payment() -> String {
    let reviewed = review_offer(&deployment(), &token(), &offer(&order()), &intent(), 10).unwrap();
    let signature = sign(&buyer(), reviewed.signing_digest());
    signature_header(&deployment(), reviewed, &signature).unwrap()
}

#[test]
fn an_offer_reviewed_and_signed_by_the_buyer_is_admitted() {
    let funding = admit_header(&deployment(), &token(), &payment(), 60, 10).unwrap();
    assert_eq!(
        funding.digest(),
        crate::vault::digest(&deployment(), &order())
    );
    assert_eq!(funding.order(), &order());
}

#[test]
fn a_buyer_signs_only_what_it_asked_for_and_only_judges_it_allowed() {
    let review = |order: &Order, change: fn(&mut Intent)| {
        let mut mine = intent();
        change(&mut mine);
        review_offer(&deployment(), &token(), &offer(order), &mine, 10).unwrap_err()
    };
    let o = order();
    assert_eq!(review(&o, |i| i.wallet = [9; 20]), OfferError::NotMyOrder);
    assert_eq!(review(&o, |i| i.asset = [9; 20]), OfferError::NotMyOrder);
    assert_eq!(
        review(&o, |i| i.policy_hash = [8; 32]),
        OfferError::NotMyOrder
    );
    assert_eq!(review(&o, |i| i.context = [8; 32]), OfferError::NotMyOrder);
    // A seller that names its own always-yes verifier, or another program.
    assert_eq!(
        review(&o, |i| i.verifiers = vec![[0x66; 20]]),
        OfferError::UntrustedJudge
    );
    assert_eq!(
        review(&o, |i| i.programs = vec![[0x66; 32]]),
        OfferError::UntrustedJudge
    );
    assert_eq!(
        review(&o, |i| i.maximum_amount = uint(999_999)),
        OfferError::OverBudget
    );
    assert_eq!(
        review(&o, |i| i.fund_no_earlier_than = 1001),
        OfferError::Deadline
    );
    assert_eq!(
        review(&o, |i| i.deliver_no_later_than = 1999),
        OfferError::Deadline
    );
    // An inadmissible order is refused whatever the buyer wants.
    let mut tiny = order();
    tiny.amount = uint(99);
    assert_eq!(
        review(&tiny, |_| ()),
        OfferError::Vault(crate::vault::Error::FeeExceedsCap)
    );
    // An offer for another vault or chain does not match this deployment.
    let mut elsewhere = deployment();
    elsewhere.vault = [8; 20];
    assert_eq!(
        review_offer(&elsewhere, &token(), &offer(&o), &intent(), 10).unwrap_err(),
        OfferError::Wire(Error::RequirementsMismatch)
    );
    let exact = reencode(&offer(&o), |v| v["accepts"][0]["scheme"] = "exact".into());
    assert_eq!(
        review_offer(&deployment(), &token(), &exact, &intent(), 10).unwrap_err(),
        OfferError::NoSingleOffer
    );
}

#[test]
fn a_payment_altered_after_signing_is_refused() {
    let refuse = |header: &str| admit_header(&deployment(), &token(), header, 60, 10).unwrap_err();
    let good = payment();
    // Order changed consistently with the requirements: the signature no longer covers it.
    let cheaper = reencode(&good, |v| {
        v["accepted"]["amount"] = "999999".into();
        v["accepted"]["extra"]["order"]["amount"] = "999999".into();
    });
    assert_eq!(
        refuse(&cheaper),
        OfferError::Wire(Error::Authorization(crate::x402::Error::NotBound))
    );
    let redirected = reencode(&good, |v| {
        v["accepted"]["extra"]["order"]["seller"] =
            "0x6666666666666666666666666666666666666666".into()
    });
    assert_eq!(
        refuse(&redirected),
        OfferError::Wire(Error::Authorization(crate::x402::Error::NotBound))
    );
    for (key, value) in [
        ("validBefore", "999999"),
        ("value", "1"),
        ("validAfter", "1"),
    ] {
        let altered = reencode(&good, |v| v["payload"]["authorization"][key] = value.into());
        assert_eq!(
            refuse(&altered),
            OfferError::Wire(Error::Authorization(crate::x402::Error::NotBound)),
            "{key}"
        );
    }
    let requirement = reencode(&good, |v| {
        v["accepted"]["payTo"] = "0x0909090909090909090909090909090909090909".into()
    });
    assert_eq!(
        refuse(&requirement),
        OfferError::Wire(Error::RequirementsMismatch)
    );
    let unknown = reencode(&good, |v| v["payload"]["memo"] = "x".into());
    assert_eq!(refuse(&unknown), OfferError::Wire(Error::Malformed));
    let stranger = SigningKey::from_slice(&[2; 32]).unwrap();
    let reviewed = review_offer(&deployment(), &token(), &offer(&order()), &intent(), 10).unwrap();
    let forged = signature_header(
        &deployment(),
        reviewed,
        &sign(
            &stranger,
            crate::vault::authorization_digest(&deployment(), &token(), &order()).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        refuse(&forged),
        OfferError::Vault(crate::vault::Error::WrongSigner)
    );
    assert_eq!(
        admit_header(&deployment(), &token(), &good, 60, 1001).unwrap_err(),
        OfferError::Vault(crate::vault::Error::Expired)
    );
}

#[test]
fn a_base_has_one_wire_form_and_a_based_offer_is_not_reviewed() {
    let plain = WireOrder::from_order(&order());
    assert_eq!(plain.base, None);
    assert!(!serde_json::to_string(&plain).unwrap().contains("base"));
    let mut based = order();
    based.base = [13; 32];
    let wire = WireOrder::from_order(&based);
    assert_eq!(wire.to_order().unwrap(), based);
    // An explicit zero is not a second encoding of "none".
    let mut zero = plain.clone();
    zero.base = Some(format!("0x{}", "00".repeat(32)));
    assert_eq!(zero.to_order().err(), Some(Error::Encoding));

    let third = Deployment {
        rules: crate::vault::Rules::Third {
            maximum_term: 3600,
            registry: [12; 20],
        },
        ..deployment()
    };
    let header = |order: &Order| {
        required_header(
            serde_json::json!({}),
            requirements(&third, &token(), order, 60),
        )
        .unwrap()
    };
    assert!(review_offer(&third, &token(), &header(&order()), &intent(), 10).is_ok());
    assert_eq!(
        review_offer(&third, &token(), &header(&based), &intent(), 10).err(),
        Some(OfferError::UnsupportedBase)
    );
    // A base the buyer listed, with the entry it read, passes; the same base
    // listed with a rate that takes fee and royalty past the cap does not;
    // and listing another base does not admit this one.
    let listed = |bps: u16| Intent {
        bases: vec![(
            based.base,
            crate::vault::Entry {
                payee: [0xb5; 20],
                bps,
            },
        )],
        ..intent()
    };
    assert!(review_offer(&third, &token(), &header(&based), &listed(10), 10).is_ok());
    assert!(matches!(
        review_offer(&third, &token(), &header(&based), &listed(90), 10).err(),
        Some(OfferError::Vault(_))
    ));
    let mut other = listed(10);
    other.bases[0].0 = [0xee; 32];
    assert_eq!(
        review_offer(&third, &token(), &header(&based), &other, 10).err(),
        Some(OfferError::UnsupportedBase)
    );
}
