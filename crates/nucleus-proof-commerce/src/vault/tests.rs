use super::*;
use crate::tests_support::{sign, wallet};
use k256::ecdsa::SigningKey;

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
fn order(buyer: &SigningKey) -> Order {
    Order {
        buyer: wallet(buyer),
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
fn token() -> TokenDomain {
    TokenDomain {
        name: "USDC".into(),
        version: "2".into(),
    }
}

#[test]
fn every_order_field_and_the_vault_identity_change_the_digest() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let base = digest(&deployment(), &order(&buyer));
    let changes: [fn(&mut Order); 11] = [
        |o| o.buyer[0] ^= 1,
        |o| o.seller[0] ^= 1,
        |o| o.asset[0] ^= 1,
        |o| o.amount[31] ^= 1,
        |o| o.verifier[0] ^= 1,
        |o| o.program[0] ^= 1,
        |o| o.policy_hash[0] ^= 1,
        |o| o.fund_by += 1,
        |o| o.deliver_by += 1,
        |o| o.salt[0] ^= 1,
        |o| o.context[0] ^= 1,
    ];
    for change in changes {
        let mut other = order(&buyer);
        change(&mut other);
        assert_ne!(digest(&deployment(), &other), base);
    }
    let mut elsewhere = deployment();
    elsewhere.chain_id = 8453;
    assert_ne!(digest(&elsewhere, &order(&buyer)), base);
    let mut another = deployment();
    another.vault = [8; 20];
    assert_ne!(digest(&another, &order(&buyer)), base);
}

#[test]
fn the_buyers_signature_over_the_fixed_authorization_admits_funding() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let (deployment, order) = (deployment(), order(&buyer));
    let authorization = authorization(&deployment, &order).unwrap();
    assert_eq!(authorization.nonce, digest(&deployment, &order));
    assert_eq!(authorization.to, deployment.vault);
    assert_eq!(
        (authorization.valid_after, authorization.valid_before),
        (0, 1001)
    );
    let signature = sign(
        &buyer,
        authorization_digest(&deployment, &token(), &order).unwrap(),
    );
    let funding = admit_funding(&deployment, &token(), order.clone(), &signature, 10).unwrap();
    assert_eq!(funding.digest(), digest(&deployment, &order));
    // The same signature does not fund a different order, vault or token domain.
    let mut cheaper = order.clone();
    cheaper.amount = uint(999_999);
    assert_eq!(
        admit_funding(&deployment, &token(), cheaper, &signature, 10).err(),
        Some(Error::WrongSigner)
    );
    let mut other_vault = deployment.clone();
    other_vault.vault = [8; 20];
    assert_eq!(
        admit_funding(&other_vault, &token(), order.clone(), &signature, 10).err(),
        Some(Error::WrongSigner)
    );
    let other_token = TokenDomain {
        name: "USD Coin".into(),
        version: "2".into(),
    };
    assert_eq!(
        admit_funding(&deployment, &other_token, order.clone(), &signature, 10).err(),
        Some(Error::WrongSigner)
    );
    // Nobody but the buyer.
    let stranger = SigningKey::from_slice(&[2; 32]).unwrap();
    let forged = sign(
        &stranger,
        authorization_digest(&deployment, &token(), &order).unwrap(),
    );
    assert_eq!(
        admit_funding(&deployment, &token(), order, &forged, 10).err(),
        Some(Error::WrongSigner)
    );
}

#[test]
fn inadmissible_orders_and_deployments_are_refused_before_any_signature_check() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let refuse = |change: fn(&mut Order)| {
        let mut bad = order(&buyer);
        change(&mut bad);
        admissible(&deployment(), &bad, 10).err()
    };
    assert_eq!(refuse(|o| o.amount = [0; 32]), Some(Error::InvalidOrder));
    assert_eq!(refuse(|o| o.seller = [0; 20]), Some(Error::InvalidOrder));
    assert_eq!(refuse(|o| o.verifier = [0; 20]), Some(Error::InvalidOrder));
    assert_eq!(refuse(|o| o.program = [0; 32]), Some(Error::InvalidOrder));
    assert_eq!(refuse(|o| o.seller = [3; 20]), Some(Error::InvalidOrder));
    assert_eq!(
        refuse(|o| o.deliver_by = o.fund_by),
        Some(Error::InvalidOrder)
    );
    assert_eq!(refuse(|o| o.amount = uint(99)), Some(Error::FeeExceedsCap));
    assert_eq!(refuse(|o| o.amount = uint(100)), None);
    assert_eq!(
        admissible(&deployment(), &order(&buyer), 1001).err(),
        Some(Error::Expired)
    );
    let mut self_treasury = deployment();
    self_treasury.treasury = self_treasury.vault;
    assert_eq!(
        admissible(&self_treasury, &order(&buyer), 10).err(),
        Some(Error::InvalidDeployment)
    );
    let mut no_fee = deployment();
    no_fee.fee_bps = 0;
    assert_eq!(
        admissible(&no_fee, &order(&buyer), 10).err(),
        Some(Error::InvalidDeployment)
    );
}

#[test]
fn a_settlement_pays_seller_and_treasury_exactly_the_deposit() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let allocation = payout(&deployment(), &order(&buyer)).unwrap();
    assert_eq!(allocation.seller, uint(997_500));
    assert_eq!(allocation.protocol, uint(2_500));
}

#[test]
fn the_journal_names_chain_vault_order_and_artifact() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let (deployment, order) = (deployment(), order(&buyer));
    let journal = acceptance_journal(&deployment, &order, [0xaa; 32]);
    assert_eq!(journal[..32], hash(b"NucleusAcceptanceV1"));
    assert_eq!(journal[32..64], uint(84532));
    assert_eq!(journal[64..96], address([3; 20]));
    assert_eq!(journal[96..128], digest(&deployment, &order));
    assert_eq!(journal[128..], [0xaa; 32]);
}

// ---- Third form (model: proofs/commerce/Vault3.lean).

fn third() -> Deployment {
    Deployment {
        rules: Rules::Third {
            maximum_term: 30 * 24 * 3600,
            registry: [12; 20],
        },
        ..deployment()
    }
}

#[test]
fn the_two_forms_never_share_a_digest_and_only_the_third_covers_the_base() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let plain = order(&buyer);
    assert_ne!(digest(&deployment(), &plain), digest(&third(), &plain));
    let mut based = plain.clone();
    based.base = [13; 32];
    assert_ne!(digest(&third(), &based), digest(&third(), &plain));
    // The second form's contract has no base field, so its digest cannot
    // cover one; the order is refused instead.
    assert_eq!(digest(&deployment(), &based), digest(&deployment(), &plain));
    assert_eq!(
        admissible(&deployment(), &based, 10).err(),
        Some(Error::InvalidOrder)
    );
    assert!(admissible(&third(), &based, 10).is_ok());
}

#[test]
fn the_third_form_caps_the_term_from_funding_to_delivery() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let term = 30 * 24 * 3600;
    let mut long = order(&buyer);
    long.deliver_by = 10 + term;
    assert!(admissible(&third(), &long, 10).is_ok());
    assert_eq!(
        admissible(&third(), &long, 9).err(),
        Some(Error::TermTooLong)
    );
    // The second form has no such rule.
    long.deliver_by = u64::MAX;
    assert!(admissible(&deployment(), &long, 10).is_ok());
    assert_eq!(
        admissible(&third(), &long, 10).err(),
        Some(Error::TermTooLong)
    );
    let mut no_term = third();
    no_term.rules = Rules::Third {
        maximum_term: 0,
        registry: [12; 20],
    };
    assert_eq!(
        admissible(&no_term, &order(&buyer), 10).err(),
        Some(Error::InvalidDeployment)
    );
}

#[test]
fn a_registered_base_is_owed_a_royalty_inside_the_fee_cap() {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let mut based = order(&buyer);
    based.base = [13; 32];
    let entry = |bps| Entry {
        payee: [14; 20],
        bps,
    };
    // 25 bps fee + 75 bps royalty is exactly the 100 bps cap.
    let (split75, payee) = split(&third(), &based, Some(&entry(75))).unwrap();
    assert_eq!(payee, Some([14; 20]));
    assert_eq!(
        (split75.seller, split75.protocol, split75.royalty),
        (uint(990_000), uint(2_500), uint(7_500))
    );
    assert!(admissible_with(&third(), &based, Some(&entry(75)), 10).is_ok());
    assert_eq!(
        admissible_with(&third(), &based, Some(&entry(76)), 10).err(),
        Some(Error::FeeExceedsCap)
    );
    assert_eq!(
        split(&third(), &based, Some(&entry(76))).err(),
        Some(Error::FeeExceedsCap)
    );
    // No entry, an unusable payee, no base, or the second form: no royalty.
    let none = |deployment: &Deployment, order: &Order, entry: Option<&Entry>| {
        let (split, payee) = split(deployment, order, entry).unwrap();
        assert_eq!(payee, None);
        assert_eq!(split.royalty, [0; 32]);
        assert_eq!((split.seller, split.protocol), (uint(997_500), uint(2_500)));
    };
    none(&third(), &based, None);
    none(
        &third(),
        &based,
        Some(&Entry {
            payee: [0; 20],
            bps: 75,
        }),
    );
    none(
        &third(),
        &based,
        Some(&Entry {
            payee: [3; 20],
            bps: 75,
        }),
    );
    none(&third(), &order(&buyer), Some(&entry(75)));
    none(&deployment(), &order(&buyer), Some(&entry(75)));
    // A rate that rounds to nothing is owed to nobody.
    let mut tiny = based.clone();
    tiny.amount = uint(9_999);
    let (split_tiny, payee) = split(&third(), &tiny, Some(&entry(1))).unwrap();
    assert_eq!((split_tiny.royalty, payee), ([0; 32], None));
}
