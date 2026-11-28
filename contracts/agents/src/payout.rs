//! Paying the shares of a saving, v1: off chain, by the buyer's desk, from
//! the buyer's wallet (proofs/commerce/Payout.lean;
//! docs/rfcs/qed-proof-carrying-savings-2026-11-28.md).
//!
//! Each share (an order, a role, a party, an amount) is one EIP-3009
//! `transferWithAuthorization` whose nonce is `nonce(share)`. The token
//! records a used nonce and refuses it again, so "exactly once" is the
//! token's state: after a restart the desk asks `authorizationState` and
//! pays only what is unpaid (`Payout.paid_once`, `restart_safe`). A share is
//! paid only when the wallet covers it on top of what the desk has committed
//! to open rows (`Payout.no_overcommit`, extending `LadderMulti`).
//!
//! The nonce is a function of the share, so anyone holding the split (the
//! market index and the settled artifact) recomputes it and can ask the
//! token whether it was paid: a missing payout reads as owed.
use crate::prelude::*;
use crate::relay::transfer::{Authorization, Signed, authorizationStateCall};
use nucleus_proof_commerce::Hash;
use qed_savings::Split;

/// Who a share is for (`Payout.Share.role`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Referrer = 0,
    Author = 1,
}

/// One share owed for one settled order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// The settled order's digest.
    pub order: Hash,
    pub role: Role,
    pub party: Address,
    pub amount: u128,
}

/// The shares a split names, each one with a positive amount: the
/// referrer's, then each author's. The buyer's share stays in its wallet.
pub fn shares(
    order: Hash,
    referrer: Option<Address>,
    authors: &[Address],
    split: &Split,
) -> Vec<Share> {
    let mut out = Vec::new();
    if let Some(party) = referrer
        && split.referrer > 0
    {
        out.push(Share {
            order,
            role: Role::Referrer,
            party,
            amount: split.referrer,
        });
    }
    if split.per_author > 0 {
        for party in authors {
            out.push(Share {
                order,
                role: Role::Author,
                party: *party,
                amount: split.per_author,
            });
        }
    }
    out
}

/// `Payout.nonce`: keccak256 of a tag, the order, the role, the party and
/// the amount.
pub fn nonce(share: &Share) -> Hash {
    let mut bytes = b"NucleusSavingsPayoutV1".to_vec();
    bytes.extend_from_slice(&share.order);
    bytes.push(share.role as u8);
    bytes.extend_from_slice(&share.party);
    bytes.extend_from_slice(&U256::from(share.amount).to_be_bytes::<32>());
    keccak(&bytes)
}

/// What the executor reads and does on chain. The live one is the buyer's
/// wallet and its token; tests use a fake.
pub trait Wallet {
    fn balance(&mut self) -> Res<u128>;
    /// What open rows could still be funded for (`ladder::exposure`, summed).
    fn committed(&mut self) -> Res<u128>;
    /// The token's `authorizationState(from, nonce)`.
    fn used(&mut self, nonce: &Hash) -> Res<bool>;
    /// Submit a signed transfer; its transaction hash.
    fn send(&mut self, transfer: &Signed) -> Res<String>;
}

/// How one share ended this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Paid {
    Sent(String),
    /// The token already holds this share's nonce.
    AlreadyPaid,
    /// The wallet does not cover it on top of the open rows; tried again
    /// on a later run.
    Waiting,
}

/// Pay every share in `owed` that is unpaid and covered (`Payout.step`,
/// `.pay`), each by a transfer authorization from `key` valid from `now`
/// for `valid_for` seconds.
pub fn pay(
    owed: &[Share],
    wallet: &mut dyn Wallet,
    key: &SigningKey,
    domain: &[u8; 32],
    now: u64,
    valid_for: u64,
) -> Res<Vec<(Share, Paid)>> {
    let from = address_of(key);
    let mut out = Vec::with_capacity(owed.len());
    for share in owed {
        let n = nonce(share);
        if wallet.used(&n)? {
            out.push((share.clone(), Paid::AlreadyPaid));
            continue;
        }
        let covered = share
            .amount
            .checked_add(wallet.committed()?)
            .is_some_and(|need| need <= wallet.balance().unwrap_or(0));
        if !covered {
            out.push((share.clone(), Paid::Waiting));
            continue;
        }
        let signed = Authorization {
            from,
            to: share.party,
            value: share.amount,
            valid_after: 0,
            valid_before: now.saturating_add(valid_for),
            nonce: n,
        }
        .sign(key, domain);
        let tx = wallet.send(&signed)?;
        out.push((share.clone(), Paid::Sent(tx)));
    }
    Ok(out)
}

/// The buyer's wallet on chain: its token balance, the token's
/// `authorizationState`, and a transfer sent by the buyer with its own gas.
pub struct ChainWallet<'a> {
    pub chain: &'a crate::chain::Chain,
    pub token: Address,
    pub key: &'a SigningKey,
    /// What open rows could still be funded for, from the ladder.
    pub committed: u128,
}
impl Wallet for ChainWallet<'_> {
    fn balance(&mut self) -> Res<u128> {
        let owner = address_of(self.key);
        let out = self.chain.call(
            owner,
            self.token,
            &crate::balanceOfCall {
                account: A::from(owner),
            }
            .abi_encode(),
        )?;
        u128::try_from(U256::from_be_slice(&out)).map_err(|_| "balance above u128".into())
    }
    fn committed(&mut self) -> Res<u128> {
        Ok(self.committed)
    }
    fn used(&mut self, nonce: &Hash) -> Res<bool> {
        let out = self.chain.call(
            [0; 20],
            self.token,
            &authorizationStateCall {
                authorizer: A::from(address_of(self.key)),
                nonce: (*nonce).into(),
            }
            .abi_encode(),
        )?;
        Ok(out.iter().any(|b| *b != 0))
    }
    fn send(&mut self, transfer: &Signed) -> Res<String> {
        let receipt = self
            .chain
            .send(self.key, Some(self.token), 0, &transfer.calldata())?;
        Ok(receipt.transaction)
    }
}

#[cfg(test)]
mod tests;
