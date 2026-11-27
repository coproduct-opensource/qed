//! The bootstrap promotion: which settlements earn a match, decided from
//! the market index alone. A mirror of proofs/commerce/Promotion.lean, whose
//! examples and mutants the tests below replay;
//! docs/rfcs/qed-bootstrap-matching-2026-11-27.md.
//!
//! A `Settled` event admits a match when its order was funded and joins a
//! post, the post's statement is on the reviewed list, the settlement's
//! block is at or after the start, and no order joined to any post of that
//! statement had settled before it. The match is the least of: the
//! fraction of the lesser of the order's amount and the post's price, the
//! per-statement cap, what is left of the pool, and what is left of the
//! poster's cap. It names the settled order's payee (its seller), never the
//! poster.
//!
//! The decision is made over the index it is given. On a filtered index
//! the authors' unpublished wallets all read `elided` and share one
//! per-poster cap; that is the index anyone can re-derive the page from.
use super::{Event, Index, Logged, Market, ModelEvent, Phase, Word, hx, model_event, word};
use crate::Res;
use serde::{Deserialize, Serialize};

/// The promotion's terms, from the site input (`mainnet.promotion`).
/// Amounts are in the token's smallest unit. Absent: no promotion.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionInput {
    /// The first block whose settlements count.
    pub start_block: u64,
    pub pool: u64,
    /// The most one poster's posts may draw, together.
    pub per_poster: u64,
    /// The match's cap as a fraction of the post's price, in basis points.
    pub fraction_bps: u64,
    pub per_statement: u64,
    /// The reviewed list: statement SHA-256 values, `0x` and 64 hex digits.
    pub listed: Vec<String>,
    /// The wallet that pays each match as a second order on the statement.
    /// Named on the pages only with `publish_wallets`.
    pub matching_buyer: String,
}

impl PromotionInput {
    pub fn check(&self) -> Res<()> {
        if self.fraction_bps > 10_000 {
            return Err("promotion: fractionBps above 10000".into());
        }
        for s in &self.listed {
            crate::word_shape(s, true).map_err(|e| format!("promotion: listed: {e}"))?;
        }
        crate::address_shape(&self.matching_buyer)
            .map_err(|e| format!("promotion: matchingBuyer: {e}"))?;
        Ok(())
    }
    pub fn params(&self) -> Params {
        Params {
            start: self.start_block,
            pool: u128::from(self.pool),
            per_poster: u128::from(self.per_poster),
            bps: u128::from(self.fraction_bps),
            per_statement: u128::from(self.per_statement),
            listed: self.listed.iter().map(|s| word(s)).collect(),
        }
    }
}

/// `Promotion.Params`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub start: u64,
    pub pool: u128,
    pub per_poster: u128,
    pub bps: u128,
    pub per_statement: u128,
    pub listed: Vec<Word>,
}

/// Which earlier settlement disqualifies one (`Promotion.First`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum First {
    Statement,
    Post,
    None,
}

/// The rules as switches (`Promotion.Rule`): the model has every one on;
/// each mutant turns one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub first: First,
    pub listed: bool,
    pub started: bool,
    pub fraction: bool,
    pub pool: bool,
    pub per_poster: bool,
    pub to_seller: bool,
}

impl Rule {
    pub const MODEL: Rule = Rule {
        first: First::Statement,
        listed: true,
        started: true,
        fraction: true,
        pool: true,
        per_poster: true,
        to_seller: true,
    };
}

/// One market event with its block and, for a post, its price.
#[derive(Clone, Debug)]
pub struct Entry {
    pub block: u64,
    pub event: ModelEvent,
    pub price: u128,
}

/// An admitted match. `seller` is the settled order's payee key (seller
/// and asset), as `0x` hex; `price` the post's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub post: Word,
    pub statement: Word,
    pub poster: String,
    pub digest: Word,
    pub seller: String,
    pub block: u64,
    pub price: u128,
    pub amount: u128,
}

#[derive(Clone, Debug, Default)]
pub struct State {
    pub market: Market,
    /// Post ID → price, first post of an ID first.
    pub prices: Vec<(Word, u128)>,
    pub granted: Vec<Match>,
}

pub fn paid(granted: &[Match]) -> u128 {
    granted.iter().map(|m| m.amount).sum()
}
pub fn paid_to(poster: &str, granted: &[Match]) -> u128 {
    granted
        .iter()
        .filter(|m| m.poster == poster)
        .map(|m| m.amount)
        .sum()
}

impl State {
    fn price_of(&self, id: &Word) -> u128 {
        self.prices
            .iter()
            .find(|(k, _)| k == id)
            .map_or(0, |(_, p)| *p)
    }

    /// `Promotion.candidate`.
    fn candidate(&self, r: &Rule, p: &Params, block: u64, d: &Word) -> Option<Match> {
        let o = self
            .market
            .orders
            .iter()
            .find(|o| o.digest == *d && o.phase == Phase::Funded)?;
        let post = self.market.posts.iter().find(|q| Market::joins(q, o))?;
        let fresh = match r.first {
            First::Statement => !self.market.taken(&post.statement),
            First::Post => self.market.rank_of(post) < 5,
            First::None => true,
        };
        let admits = (!r.listed || p.listed.contains(&post.statement))
            && (!r.started || p.start <= block)
            && fresh;
        let price = self.price_of(&post.id);
        let frac = if r.fraction {
            o.amount.min(price).saturating_mul(p.bps) / 10_000
        } else {
            p.per_statement
        };
        let mut a = frac.min(p.per_statement);
        if r.pool {
            a = a.min(p.pool.saturating_sub(paid(&self.granted)));
        }
        if r.per_poster {
            a = a.min(
                p.per_poster
                    .saturating_sub(paid_to(&post.poster, &self.granted)),
            );
        }
        (admits && a > 0).then(|| Match {
            post: post.id,
            statement: post.statement,
            poster: post.poster.clone(),
            digest: *d,
            seller: if r.to_seller {
                hx(&o.payee)
            } else {
                post.poster.clone()
            },
            block,
            price,
            amount: a,
        })
    }

    /// `Promotion.step`.
    pub fn step(&mut self, r: &Rule, p: &Params, x: &Entry) {
        let new = match &x.event {
            ModelEvent::Settled(d) => self.candidate(r, p, x.block, d),
            _ => None,
        };
        if let ModelEvent::Posted(post) = &x.event {
            self.prices.push((post.id, x.price));
        }
        self.market.apply(&x.event);
        self.granted.extend(new);
    }
}

/// `Promotion.run` from the empty market.
pub fn run<'a>(r: &Rule, p: &Params, entries: impl IntoIterator<Item = &'a Entry>) -> State {
    let mut s = State::default();
    for x in entries {
        s.step(r, p, x);
    }
    s
}

/// One logged event as an entry: its block, and a post's `maximumAmount`.
pub fn entry(l: &Logged) -> Entry {
    Entry {
        block: l.block,
        event: model_event(l),
        price: match &l.event {
            Event::Posted { maximum_amount, .. } => maximum_amount.parse().unwrap_or(0),
            _ => 0,
        },
    }
}

/// The matches the index admits under the input's terms.
pub fn decide(index: &Index, terms: &PromotionInput) -> Vec<Match> {
    let entries: Vec<Entry> = index.events.iter().map(entry).collect();
    run(&Rule::MODEL, &terms.params(), &entries).granted
}

#[cfg(test)]
#[path = "promotion_tests.rs"]
mod tests;
