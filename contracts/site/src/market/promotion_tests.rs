//! The examples and mutants of proofs/commerce/Promotion.lean, replayed:
//! the same entries, the same expected matches. The Lean file's `tctx`
//! stands in for keccak there; here the contexts are the real derivation.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use crate::market::{ModelPost, context};

const SECOND: u128 = 1_000_000;
fn usdc(n: u128) -> u128 {
    n * SECOND
}
/// A number as a big-endian word, as Lean's `Nat` reads one.
fn n(x: u128) -> Word {
    let mut w = [0; 32];
    w[16..].copy_from_slice(&x.to_be_bytes());
    w
}
const S0006: &str = "0xfff47ea357d16945a265b84f905c991b1e1c64a593afcd571e9c6a76d191db37";
const BOUNTY: &str = "0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c";
fn s0006() -> Word {
    word(S0006)
}
fn bounty() -> Word {
    word(BOUNTY)
}
fn sa() -> Word {
    n(0xa1)
}
fn sb() -> Word {
    n(0xb1)
}
const LADDER: &str = "0xa";
const STRANGER: &str = "0xc";
const SELLER: u128 = 0xb0b;

/// `Examples.P`: from block 100, a 100 USDC pool, 40 per poster, +50 %,
/// 20 per statement, three listed statements.
fn params() -> Params {
    Params {
        start: 100,
        pool: usdc(100),
        per_poster: usdc(40),
        bps: 5000,
        per_statement: usdc(20),
        listed: vec![s0006(), sa(), sb()],
    }
}
fn small() -> Params {
    Params {
        pool: usdc(30),
        ..params()
    }
}

/// `Examples.trade`: post, fund at the price, settle.
fn trade(
    id: u128,
    statement: Word,
    poster: &str,
    price: u128,
    payee: u128,
    post_block: u64,
    settle_block: u64,
) -> Vec<Entry> {
    let p = ModelPost {
        id: n(id),
        key_binding: n(7),
        policy: n(50),
        statement,
        fund_by: 10_000,
        poster: poster.into(),
        block: post_block,
    };
    let ctx = context(&p.id, &p.key_binding);
    vec![
        Entry {
            block: post_block,
            event: ModelEvent::Posted(p),
            price,
        },
        Entry {
            block: post_block + 1,
            event: ModelEvent::Funded {
                digest: n(100 + id),
                context: ctx,
                policy: n(50),
                payee: n(payee),
                amount: price,
            },
            price: 0,
        },
        Entry {
            block: settle_block,
            event: ModelEvent::Settled(n(100 + id)),
            price: 0,
        },
    ]
}
fn cat(parts: &[Vec<Entry>]) -> Vec<Entry> {
    parts.concat()
}
fn grants(r: &Rule, p: &Params, xs: &[Entry]) -> Vec<Match> {
    run(r, p, xs).granted
}
fn amounts(ms: &[Match]) -> Vec<u128> {
    ms.iter().map(|m| m.amount).collect()
}
fn with(f: impl FnOnce(&mut Rule)) -> Rule {
    let mut r = Rule::MODEL;
    f(&mut r);
    r
}

fn s0006_trade() -> Vec<Entry> {
    trade(6, s0006(), LADDER, usdc(40), SELLER, 110, 130)
}
fn self_deal() -> Vec<Entry> {
    trade(9, bounty(), STRANGER, usdc(40), 0xd, 110, 130)
}
fn second_post() -> Vec<Entry> {
    cat(&[
        s0006_trade(),
        trade(16, s0006(), STRANGER, usdc(40), 0xd, 140, 150),
    ])
}
fn three() -> Vec<Entry> {
    cat(&[
        trade(6, s0006(), LADDER, usdc(40), SELLER, 110, 130),
        trade(7, sa(), STRANGER, usdc(40), SELLER, 110, 131),
        trade(8, sb(), "0xe", usdc(40), SELLER, 110, 132),
    ])
}
fn one_poster() -> Vec<Entry> {
    cat(&[
        trade(6, s0006(), LADDER, usdc(40), SELLER, 110, 130),
        trade(7, sa(), LADDER, usdc(40), SELLER, 110, 131),
        trade(8, sb(), LADDER, usdc(40), SELLER, 110, 132),
    ])
}
fn cheap() -> Vec<Entry> {
    trade(6, s0006(), LADDER, usdc(10), SELLER, 110, 130)
}
fn early() -> Vec<Entry> {
    cat(&[
        trade(6, s0006(), LADDER, usdc(40), SELLER, 80, 90),
        trade(16, s0006(), STRANGER, usdc(40), 0xd, 120, 130),
    ])
}

// ---- Examples ---------------------------------------------------------------

#[test]
fn s0006_matched() {
    assert_eq!(
        grants(&Rule::MODEL, &params(), &s0006_trade()),
        [Match {
            post: n(6),
            statement: s0006(),
            poster: LADDER.into(),
            digest: n(106),
            seller: hx(&n(SELLER)),
            block: 130,
            price: usdc(40),
            amount: usdc(20),
        }]
    );
}

#[test]
fn self_dealing_gets_nothing() {
    assert_eq!(grants(&Rule::MODEL, &params(), &self_deal()), []);
}

#[test]
fn second_post_gets_nothing() {
    assert_eq!(
        grants(&Rule::MODEL, &params(), &second_post()),
        grants(&Rule::MODEL, &params(), &s0006_trade())
    );
}

#[test]
fn pool_exhausts() {
    let g = grants(&Rule::MODEL, &small(), &three());
    assert_eq!(amounts(&g), [usdc(20), usdc(10)]);
    assert_eq!(paid(&g), small().pool);
}

#[test]
fn poster_cap() {
    assert_eq!(
        amounts(&grants(&Rule::MODEL, &params(), &one_poster())),
        [usdc(20), usdc(20)]
    );
}

#[test]
fn half_the_price() {
    assert_eq!(
        amounts(&grants(&Rule::MODEL, &params(), &cheap())),
        [usdc(5)]
    );
}

#[test]
fn early_gets_nothing() {
    assert_eq!(grants(&Rule::MODEL, &params(), &early()), []);
}

// ---- Mutants P1-P9 ----------------------------------------------------------

#[test]
fn p1_no_first_check_matches_a_later_settlement() {
    let g = grants(&with(|r| r.first = First::None), &params(), &early());
    assert_eq!(g.iter().map(|m| m.post).collect::<Vec<_>>(), [n(16)]);
}

#[test]
fn p2_first_per_post_matches_twice() {
    let g = grants(&with(|r| r.first = First::Post), &params(), &second_post());
    assert_eq!(
        g.iter().map(|m| m.statement).collect::<Vec<_>>(),
        [s0006(), s0006()]
    );
}

#[test]
fn p3_no_pool_clamp_exceeds_the_pool() {
    let g = grants(&with(|r| r.pool = false), &small(), &three());
    assert!(paid(&g) > small().pool);
}

#[test]
fn p4_no_poster_clamp_exceeds_the_poster_cap() {
    let g = grants(&with(|r| r.per_poster = false), &params(), &one_poster());
    assert!(paid_to(LADDER, &g) > params().per_poster);
}

#[test]
fn p5_flat_match_exceeds_the_fraction() {
    let p = params();
    let g = grants(&with(|r| r.fraction = false), &p, &cheap());
    assert!(g.iter().any(|m| p.bps * m.price < m.amount * 10_000));
}

#[test]
fn p6_pays_the_poster() {
    let g = grants(&with(|r| r.to_seller = false), &params(), &s0006_trade());
    assert_eq!(
        g.iter().map(|m| m.seller.as_str()).collect::<Vec<_>>(),
        [LADDER]
    );
}

#[test]
fn p7_no_list_check_pays_self_dealing() {
    let g = grants(&with(|r| r.listed = false), &params(), &self_deal());
    assert_eq!(amounts(&g), [usdc(20)]);
}

#[test]
fn p8_no_start_check_pays_before_the_start() {
    let g = grants(&with(|r| r.started = false), &params(), &early());
    assert_eq!(g.iter().map(|m| m.block).collect::<Vec<_>>(), [90]);
}

/// P9: the pool split at read time revokes part of an admitted match.
fn prorata(p: &Params, ms: &[Match]) -> Vec<u128> {
    ms.iter()
        .map(|m| m.amount.min(p.pool / ms.len() as u128))
        .collect()
}

#[test]
fn p9_split_at_read_time_revokes() {
    let one = trade(6, s0006(), LADDER, usdc(40), SELLER, 110, 130);
    let two = cat(&[
        one.clone(),
        trade(7, sa(), STRANGER, usdc(40), SELLER, 110, 131),
    ]);
    let r = with(|r| r.pool = false);
    assert_eq!(prorata(&small(), &grants(&r, &small(), &one)), [usdc(20)]);
    assert_eq!(
        prorata(&small(), &grants(&r, &small(), &two)),
        [usdc(15), usdc(15)]
    );
    // The model: the first match stays as it was.
    assert_eq!(
        grants(&Rule::MODEL, &small(), &two)[..1],
        grants(&Rule::MODEL, &small(), &one)[..]
    );
}

/// Every prefix of every example: matches only ever extend, and the caps
/// hold at each step.
#[test]
fn invariants_over_every_prefix() {
    for (p, xs) in [
        (params(), second_post()),
        (small(), three()),
        (params(), one_poster()),
        (params(), early()),
        (params(), self_deal()),
    ] {
        let mut s = State::default();
        for x in &xs {
            let before = s.granted.clone();
            s.step(&Rule::MODEL, &p, x);
            assert_eq!(s.granted[..before.len()], before[..]);
            assert!(paid(&s.granted) <= p.pool);
            for m in &s.granted {
                assert!(paid_to(&m.poster, &s.granted) <= p.per_poster);
                assert!(m.amount <= p.per_statement && m.amount * 10_000 <= p.bps * m.price);
                assert!(p.listed.contains(&m.statement) && m.block >= p.start);
                assert_eq!(
                    s.granted
                        .iter()
                        .filter(|o| o.statement == m.statement)
                        .count(),
                    1
                );
            }
        }
    }
}
