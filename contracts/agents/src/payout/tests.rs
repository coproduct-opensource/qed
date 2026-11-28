//! The examples and mutants of proofs/commerce/Payout.lean against a fake
//! wallet and token.
#![allow(clippy::unwrap_used)]
use super::*;
use qed_savings::{Rule, split};
use std::collections::HashSet;

const DOMAIN: [u8; 32] = [0xd0; 32];

/// The token's used nonces and the wallet's balance, as the chain keeps
/// them: they outlive any one executor.
struct Fake {
    balance: u128,
    committed: u128,
    used: HashSet<Hash>,
    sent: Vec<Signed>,
    /// Ether and one transfer's gas, in wei.
    ether: u128,
    fee: u128,
}
impl Wallet for Fake {
    fn balance(&mut self) -> Res<u128> {
        Ok(self.balance)
    }
    fn committed(&mut self) -> Res<u128> {
        Ok(self.committed)
    }
    fn used(&mut self, nonce: &Hash) -> Res<bool> {
        Ok(self.used.contains(nonce))
    }
    fn gas(&mut self) -> Res<(u128, u128)> {
        Ok((self.ether, self.fee))
    }
    fn send(&mut self, t: &Signed) -> Res<String> {
        self.ether -= self.fee;
        // The token's own rules: an unused nonce, a signature by `from`.
        if !self.used.insert(t.authorization.nonce) {
            return Err("FiatTokenV2: authorization is used or canceled".into());
        }
        assert_eq!(t.signer(&DOMAIN), Some(t.authorization.from));
        self.balance -= t.authorization.value;
        self.sent.push(t.clone());
        Ok(format!("0x{:064x}", self.sent.len()))
    }
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn usdc(n: u128) -> u128 {
    n * 1_000_000
}
fn owed() -> Vec<Share> {
    // `Savings.Examples.s0006_split`: 40 cap, 25 paid, referred, one author.
    let s = split(&Rule::MODEL, usdc(40), usdc(25), true, 1);
    shares([0x06; 32], Some([0xf0; 20]), &[[0xa1; 20]], &s)
}

/// Driven red by skipping `authorizationState`: the retry was sent, and the
/// token refused the used nonce.
#[test]
fn the_s0006_split_is_paid_once_across_a_restart() {
    let owed = owed();
    assert_eq!(
        owed.iter().map(|s| s.amount).collect::<Vec<_>>(),
        [4_500_000, usdc(3)]
    );
    let mut chain = Fake {
        balance: usdc(50),
        committed: usdc(40),
        used: HashSet::new(),
        sent: vec![],
        ether: 1_000,
        fee: 10,
    };
    let first = pay(&owed, &mut chain, &key(), &DOMAIN, 1_000, 3_600).unwrap();
    assert!(first.iter().all(|(_, p)| matches!(p, Paid::Sent(_))));
    // A new executor (a restart) over the same chain pays nothing again.
    let again = pay(&owed, &mut chain, &key(), &DOMAIN, 2_000, 3_600).unwrap();
    assert!(again.iter().all(|(_, p)| *p == Paid::AlreadyPaid));
    assert_eq!(chain.sent.len(), 2);
    assert_eq!(chain.balance, usdc(50) - 7_500_000);
    assert_eq!(chain.sent[0].authorization.to, [0xf0; 20]);
}

/// `Payout.Examples.waits_for_cover`: 40 committed of 44; the 4.5 share
/// waits and the 3 is paid. Driven red by dropping the cover check: the
/// 4.5 was sent and the balance fell under the commitment.
#[test]
fn a_share_waits_while_the_open_rows_need_the_wallet() {
    let mut chain = Fake {
        balance: usdc(44),
        committed: usdc(40),
        used: HashSet::new(),
        sent: vec![],
        ether: 1_000,
        fee: 10,
    };
    let out = pay(&owed(), &mut chain, &key(), &DOMAIN, 1_000, 3_600).unwrap();
    assert_eq!(out[0].1, Paid::Waiting);
    assert!(matches!(out[1].1, Paid::Sent(_)));
    assert!(chain.committed <= chain.balance);
}

/// The nonce is the share's: another amount, party, role or order is
/// another nonce. Driven red by leaving the amount out of the nonce.
#[test]
fn each_share_has_its_own_nonce() {
    let s = owed()[0].clone();
    let n = nonce(&s);
    for other in [
        Share {
            amount: s.amount + 1,
            ..s.clone()
        },
        Share {
            party: [1; 20],
            ..s.clone()
        },
        Share {
            role: Role::Author,
            ..s.clone()
        },
        Share {
            order: [1; 32],
            ..s.clone()
        },
    ] {
        assert_ne!(nonce(&other), n);
    }
    // No shares for a split with no saving, or no referrer and no authors.
    let none = split(&Rule::MODEL, usdc(40), usdc(40), true, 1);
    assert!(shares([6; 32], Some([0xf0; 20]), &[[0xa1; 20]], &none).is_empty());
    let unreferred = split(&Rule::MODEL, usdc(40), usdc(25), false, 0);
    assert!(shares([6; 32], None, &[], &unreferred).is_empty());
}

/// `Payout.Examples.no_gas_no_send`: 5 wei of ether for a 10 wei transfer:
/// nothing is attempted and every share reads `NoGas`. Driven red by
/// dropping the gas check: the token was sent a transfer and the fake's
/// ether underflowed.
#[test]
fn a_payout_the_wallet_cannot_pay_gas_for_is_not_attempted() {
    let mut chain = Fake {
        balance: usdc(50),
        committed: usdc(40),
        used: HashSet::new(),
        sent: vec![],
        ether: 5,
        fee: 10,
    };
    let out = pay(&owed(), &mut chain, &key(), &DOMAIN, 1_000, 3_600).unwrap();
    assert!(out.iter().all(|(_, p)| *p == Paid::NoGas));
    assert!(chain.sent.is_empty());
}
