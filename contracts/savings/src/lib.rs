//! Proof-carrying savings: what a settlement saved its buyer, and who is
//! owed a share of it. A mirror of proofs/commerce/Savings.lean, whose
//! split examples and mutants the tests below replay;
//! docs/rfcs/qed-proof-carrying-savings-2026-11-28.md.
//!
//! The saving of a settled order is the post's price (its `maximumAmount`)
//! minus the order's amount, 0 when the order paid the price or more. Of it:
//!
//! - the referrer bound into the funded order's `salt` gets 30 %, rounded
//!   down, and nothing is paid when the order names no referrer;
//! - the authors of the lemmas the settled proof reused share 20 %, divided
//!   equally among the distinct authors, each share rounded down;
//! - the buyer keeps the rest, at least half, with every rounding remainder.
//!
//! The authors are decided from the settled artifact's declarations and a
//! provenance index (declaration → the payee of the first settlement that
//! carried it), less the seller itself: [`authors_of`].
//!
//! Data only: nothing here moves funds or reads a chain.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(feature = "walk")]
pub mod walk;

/// The referrer's share of the saving, in basis points.
pub const REFERRER_BPS: u128 = 3000;
/// The authors' share of the saving, together, in basis points.
pub const AUTHORS_BPS: u128 = 2000;
const SCALE: u128 = 10_000;

/// The rules as switches (`Savings.Rule`): the model has every one in its
/// place; each mutant turns one. Only [`Rule::MODEL`] is used outside tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The saving is the price minus the amount (off: the amount itself).
    pub saving: bool,
    /// An unreferred order pays no referrer share.
    pub unref_to_buyer: bool,
    /// The authors' 20 % is divided among them (off: 20 % to each).
    pub divide: bool,
    /// The buyer takes the remainder (off: half, rounded down).
    pub remainder: bool,
    /// Only a funded order settles a split.
    pub phase: bool,
    /// Only a `Settled` event splits (off: a `Refunded` one too).
    pub on_settle: bool,
    /// The referrer is the one bound at funding (off: named at settlement).
    pub bound_ref: bool,
    /// The authors come from the artifact (off: the ones a settlement claims).
    pub from_artifact: bool,
    /// The seller is not its own author.
    pub not_seller: bool,
}

impl Rule {
    pub const MODEL: Rule = Rule {
        saving: true,
        unref_to_buyer: true,
        divide: true,
        remainder: true,
        phase: true,
        on_settle: true,
        bound_ref: true,
        from_artifact: true,
        not_seller: true,
    };
}

/// One split of one saving (`Savings.Split`). Amounts are in the token's
/// smallest unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Split {
    pub referrer: u128,
    pub per_author: u128,
    pub authors: u128,
    pub buyer: u128,
}

impl Split {
    /// Everything the split pays.
    pub fn total(&self) -> u128 {
        self.others().saturating_add(self.buyer)
    }
    /// What it pays to others than the buyer.
    pub fn others(&self) -> u128 {
        self.referrer
            .saturating_add(self.authors.saturating_mul(self.per_author))
    }
}

/// `Savings.split`: the saving of an order of `amount` on a post priced
/// `cap`, with or without a referrer, among `n` authors. The products
/// saturate only above 3.4 × 10³⁴ units, far past any USDC amount.
pub fn split(r: &Rule, cap: u128, amount: u128, referred: bool, n: u128) -> Split {
    let s = if r.saving {
        cap.saturating_sub(amount)
    } else {
        amount
    };
    let referrer = if referred || !r.unref_to_buyer {
        s.saturating_mul(REFERRER_BPS) / SCALE
    } else {
        0
    };
    let pool = s.saturating_mul(AUTHORS_BPS) / SCALE;
    let per_author = if n == 0 {
        0
    } else if r.divide {
        pool / n
    } else {
        pool
    };
    let buyer = if r.remainder {
        s.saturating_sub(referrer)
            .saturating_sub(n.saturating_mul(per_author))
    } else {
        s / 2
    };
    Split {
        referrer,
        per_author,
        authors: n,
        buyer,
    }
}

/// `Savings.lookup`: the first payee the index names for a declaration.
pub fn lookup<'a, D: PartialEq, P>(prov: &'a [(D, P)], d: &D) -> Option<&'a P> {
    prov.iter().find(|(k, _)| k == d).map(|(_, p)| p)
}

/// `Savings.authorsOf`: the payees the provenance index names for an
/// artifact's declarations, distinct and in first-seen order, less the
/// seller.
pub fn authors_of<D: PartialEq, P: PartialEq + Clone>(
    r: &Rule,
    prov: &[(D, P)],
    decls: &[D],
    seller: &P,
) -> Vec<P> {
    let mut out: Vec<P> = Vec::new();
    for d in decls {
        if let Some(p) = lookup(prov, d)
            && (!r.not_seller || p != seller)
            && !out.contains(p)
        {
            out.push(p.clone());
        }
    }
    out
}

/// `Savings.newProv`: the index after a settlement by `seller` whose
/// artifact carries `decls`. The first payee of a declaration stays.
pub fn extend<D: PartialEq + Clone, P: Clone>(prov: &mut Vec<(D, P)>, decls: &[D], seller: &P) {
    for d in decls {
        if lookup(prov, d).is_none() {
            prov.push((d.clone(), seller.clone()));
        }
    }
}

#[cfg(test)]
mod tests;
