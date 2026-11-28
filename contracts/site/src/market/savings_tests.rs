//! The event examples and mutants of proofs/commerce/Savings.lean,
//! replayed: the same entries, the same expected records. The Lean file's
//! `tctx` stands in for keccak there; here the contexts are the real
//! derivation.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use crate::market::{ModelPost, context, word};

fn usdc(n: u128) -> u128 {
    n * 1_000_000
}
fn n(x: u128) -> Word {
    let mut w = [0; 32];
    w[16..].copy_from_slice(&x.to_be_bytes());
    w
}
const S0006: &str = "0xfff47ea357d16945a265b84f905c991b1e1c64a593afcd571e9c6a76d191db37";
const BUYER: &str = "0xa";
const SELLER: u128 = 0xb0b;
const REFERRER: &str = "0xf00";
const AUTHOR_A: u128 = 0xa1;
const AUTHOR_B: u128 = 0xb1;
const M: Rule = Rule::MODEL;

fn sp(referrer: u128, per_author: u128, authors: u128, buyer: u128) -> Split {
    Split {
        referrer,
        per_author,
        authors,
        buyer,
    }
}

/// `Examples.trade`: post at `price`, fund at `amount` with a referral,
/// settle with an artifact's declarations.
#[allow(clippy::too_many_arguments)]
fn trade(
    id: u128,
    statement: Word,
    price: u128,
    amount: u128,
    payee: u128,
    referral: Option<&str>,
    decls: &[u128],
    blk: u64,
) -> Vec<Entry> {
    let p = ModelPost {
        id: n(id),
        key_binding: n(7),
        policy: n(50),
        statement,
        fund_by: 10_000,
        poster: BUYER.into(),
        block: blk,
    };
    let ctx = context(&p.id, &p.key_binding);
    vec![
        Entry {
            price,
            ..Entry::of(blk, ModelEvent::Posted(p))
        },
        Entry {
            referral: referral.map(str::to_string),
            ..Entry::of(
                blk + 1,
                ModelEvent::Funded {
                    digest: n(100 + id),
                    context: ctx,
                    policy: n(50),
                    payee: n(payee),
                    amount,
                },
            )
        },
        Entry {
            decls: decls.iter().map(|d| n(*d)).collect(),
            ..Entry::of(blk + 2, ModelEvent::Settled(n(100 + id)))
        },
    ]
}
fn records(r: &Rule, xs: &[Entry]) -> Vec<Record> {
    run(r, xs).records
}
fn first() -> Vec<Entry> {
    trade(5, n(5), usdc(10), usdc(10), AUTHOR_A, None, &[1, 2], 100)
}
fn second() -> Vec<Entry> {
    trade(
        6,
        word(S0006),
        usdc(40),
        usdc(25),
        SELLER,
        Some(REFERRER),
        &[2, 3],
        110,
    )
}
fn both() -> Vec<Entry> {
    [first(), second()].concat()
}
fn own_lemma() -> Vec<Entry> {
    [
        trade(5, n(5), usdc(10), usdc(10), SELLER, None, &[1], 100),
        trade(6, word(S0006), usdc(40), usdc(25), SELLER, None, &[1], 110),
    ]
    .concat()
}
fn replayed() -> Vec<Entry> {
    let mut xs = second();
    xs.push(Entry::of(200, ModelEvent::Settled(n(106))));
    xs
}
fn plain() -> Vec<Entry> {
    trade(6, word(S0006), usdc(40), usdc(25), SELLER, None, &[], 110)
}
fn late_referral() -> Vec<Entry> {
    let mut xs = plain();
    xs[2].referral = Some(REFERRER.into());
    xs
}
fn claims() -> Vec<Entry> {
    let mut xs = plain();
    xs[2].claimed = vec![n(AUTHOR_B)];
    xs
}
fn refunded() -> Vec<Entry> {
    let mut xs = trade(
        6,
        word(S0006),
        usdc(40),
        usdc(25),
        SELLER,
        Some(REFERRER),
        &[],
        110,
    );
    xs[2] = Entry::of(112, ModelEvent::Refunded(n(106)));
    xs
}
fn later() -> Vec<Entry> {
    [
        both(),
        trade(7, n(7), usdc(10), usdc(10), AUTHOR_B, None, &[1, 2], 120),
    ]
    .concat()
}

#[test]
fn both_records() {
    let got: Vec<_> = records(&M, &both())
        .into_iter()
        .map(|m| (m.digest, m.referrer, m.authors, m.split))
        .collect();
    assert_eq!(
        got,
        vec![
            (n(105), None, vec![], sp(0, 0, 0, 0)),
            (
                n(106),
                Some(REFERRER.to_string()),
                vec![n(AUTHOR_A)],
                sp(4_500_000, usdc(3), 1, 7_500_000)
            ),
        ]
    );
}

#[test]
fn self_referral_bounded() {
    let xs = trade(
        6,
        word(S0006),
        usdc(40),
        usdc(25),
        SELLER,
        Some("0xb0b"),
        &[],
        110,
    );
    let got: Vec<_> = records(&M, &xs)
        .into_iter()
        .map(|m| (m.referrer, m.split))
        .collect();
    assert_eq!(
        got,
        vec![(Some("0xb0b".to_string()), sp(4_500_000, 0, 0, 10_500_000))]
    );
}

#[test]
fn own_lemma_not_authored() {
    let got: Vec<_> = records(&M, &own_lemma())
        .into_iter()
        .map(|m| m.authors)
        .collect();
    assert_eq!(got, vec![Vec::<Word>::new(), vec![]]);
}

#[test]
fn replay_writes_nothing() {
    assert_eq!(records(&M, &replayed()), records(&M, &second()));
}

#[test]
fn late_referral_ignored() {
    let got: Vec<_> = records(&M, &late_referral())
        .into_iter()
        .map(|m| m.referrer)
        .collect();
    assert_eq!(got, vec![None]);
}

#[test]
fn refunded_records_nothing() {
    assert!(records(&M, &refunded()).is_empty());
}

fn digests(ms: &[Record]) -> Vec<Word> {
    ms.iter().map(|m| m.digest).collect()
}

/// S6–S10: each switch turned, each theorem's failure as in the Lean file.
#[test]
fn mutants() {
    // S6 `phase`, against `one_split_per_order`.
    assert_eq!(
        digests(&records(&Rule { phase: false, ..M }, &replayed())),
        vec![n(106), n(106)]
    );
    // S7 `on_settle`, against `no_split_without_settlement`.
    assert_eq!(
        digests(&records(
            &Rule {
                on_settle: false,
                ..M
            },
            &refunded()
        )),
        vec![n(106)]
    );
    // S8 `bound_ref`, against `referral_bound_before_funding`.
    let s8 = records(
        &Rule {
            bound_ref: false,
            ..M
        },
        &late_referral(),
    );
    assert_eq!(s8[0].referrer.as_deref(), Some(REFERRER));
    // S9 `from_artifact`, against `authors_from_artifact`.
    let s9 = records(
        &Rule {
            from_artifact: false,
            ..M
        },
        &claims(),
    );
    assert_eq!(s9[0].authors, vec![n(AUTHOR_B)]);
    assert!(records(&M, &claims())[0].authors.is_empty());
    // S10 `not_seller`, against `authors_from_artifact`.
    let s10: Vec<_> = records(
        &Rule {
            not_seller: false,
            ..M
        },
        &own_lemma(),
    )
    .into_iter()
    .map(|m| m.authors)
    .collect();
    assert_eq!(s10, vec![vec![], vec![n(SELLER)]]);
}

/// S11, against `monotone`: authors recomputed at read time from an index
/// where the last settlement carrying a declaration wins.
fn read_time(xs: &[Entry]) -> Vec<Vec<Word>> {
    let settled: Vec<&Entry> = xs
        .iter()
        .filter(|x| matches!(x.event, ModelEvent::Settled(_)))
        .collect();
    let recs = records(&M, xs);
    let mut last: Vec<(Word, Word)> = Vec::new();
    for (m, x) in recs.iter().zip(&settled) {
        let mut add: Vec<(Word, Word)> = x.decls.iter().map(|d| (*d, m.seller)).collect();
        add.append(&mut last);
        last = add;
    }
    recs.iter()
        .zip(&settled)
        .map(|(m, x)| authors_of(&M, &last, &x.decls, &m.seller))
        .collect()
}

#[test]
fn mutant_read_time_breaks_monotone() {
    assert_ne!(read_time(&later())[..2], read_time(&both())[..]);
    assert_eq!(records(&M, &later())[..2], records(&M, &both())[..]);
}
