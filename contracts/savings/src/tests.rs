//! The split examples and mutants of proofs/commerce/Savings.lean, replayed
//! with the same numbers, and its theorems checked over a grid.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

fn usdc(n: u128) -> u128 {
    n * 1_000_000
}
fn sp(referrer: u128, per_author: u128, authors: u128, buyer: u128) -> Split {
    Split {
        referrer,
        per_author,
        authors,
        buyer,
    }
}
const M: Rule = Rule::MODEL;

#[test]
fn examples() {
    // `s0006_split`: 40 cap, 25 paid, referred, one author.
    assert_eq!(
        split(&M, usdc(40), usdc(25), true, 1),
        sp(4_500_000, usdc(3), 1, 7_500_000)
    );
    // `two_authors`.
    assert_eq!(
        split(&M, usdc(40), usdc(25), true, 2),
        sp(4_500_000, 1_500_000, 2, 7_500_000)
    );
    // `unreferred`.
    assert_eq!(
        split(&M, usdc(40), usdc(25), false, 0),
        sp(0, 0, 0, usdc(15))
    );
    // `no_saving`.
    assert_eq!(split(&M, usdc(40), usdc(40), true, 3), sp(0, 0, 3, 0));
    assert_eq!(split(&M, usdc(40), usdc(41), true, 3), sp(0, 0, 3, 0));
    // `rounding`.
    assert_eq!(split(&M, 7, 0, true, 3), sp(2, 0, 3, 5));
}

#[test]
fn mutants() {
    // S1 `remainder`: one unit of an odd saving is paid to no one.
    assert_ne!(
        split(
            &Rule {
                remainder: false,
                ..M
            },
            7,
            0,
            true,
            0
        )
        .total(),
        7
    );
    // S2 `divide`: 20 % to each of three authors; the buyer under half.
    assert!(
        split(&Rule { divide: false, ..M }, usdc(40), usdc(25), true, 3).buyer
            < usdc(15).div_ceil(2)
    );
    // S3 `saving`: shares of the amount; a 40 USDC order costs 60.
    let s3 = split(&Rule { saving: false, ..M }, usdc(40), usdc(40), true, 1);
    assert!(usdc(40) < usdc(40) + s3.others());
    // S4 `saving`: a self-referring seller gains by raising its price.
    let at = |a| split(&Rule { saving: false, ..M }, usdc(40), a, true, 0).referrer;
    assert!(at(usdc(25)) < at(usdc(30)));
    // S5 `unref_to_buyer`: 30 % with no referrer.
    assert_eq!(
        split(
            &Rule {
                unref_to_buyer: false,
                ..M
            },
            usdc(40),
            usdc(25),
            false,
            0
        )
        .referrer,
        4_500_000
    );
}

/// `split_exact`, `buyer_keeps_half`, `buyer_net_le_cap`,
/// `seller_revenue_monotone` and `unreferred_goes_to_buyer`, on every
/// price, amount and author count of a grid.
#[test]
fn theorems_on_a_grid() {
    for cap in 0..60u128 {
        for amount in 0..60u128 {
            for n in 0..6u128 {
                for referred in [false, true] {
                    let x = split(&M, cap, amount, referred, n);
                    let s = cap.saturating_sub(amount);
                    assert_eq!(x.total(), s, "split_exact {cap} {amount} {n}");
                    assert!(x.buyer >= s.div_ceil(2), "buyer_keeps_half");
                    assert!(x.others() <= s, "buyer_net_le_cap");
                    if amount <= cap {
                        assert!(amount + x.others() <= cap);
                    }
                    if !referred {
                        assert_eq!(x.referrer, 0);
                        assert_eq!(x.buyer, s - n * x.per_author);
                    }
                    let y = split(&M, cap, amount + 1, referred, n);
                    assert!(y.referrer <= x.referrer && y.per_author <= x.per_author);
                    assert!(y.others() <= x.others(), "seller_revenue_monotone");
                }
            }
        }
    }
}

#[test]
fn authors_are_distinct_first_seen_and_not_the_seller() {
    let mut prov: Vec<(u32, &str)> = Vec::new();
    extend(&mut prov, &[1, 2], &"a");
    extend(&mut prov, &[2, 3], &"seller");
    extend(&mut prov, &[1, 4], &"b");
    // The first payee of a declaration stays.
    assert_eq!(prov, vec![(1, "a"), (2, "a"), (3, "seller"), (4, "b")]);
    assert_eq!(
        authors_of(&M, &prov, &[4, 1, 2, 3, 9], &"seller"),
        vec!["b", "a"]
    );
    // `mutant_notSeller_breaks_authors_from_artifact`.
    assert_eq!(
        authors_of(
            &Rule {
                not_seller: false,
                ..M
            },
            &prov,
            &[3],
            &"seller"
        ),
        vec!["seller"]
    );
}

#[test]
fn large_amounts_do_not_wrap() {
    let x = split(&M, u128::MAX, 0, true, 7);
    assert_eq!(x.total(), u128::MAX);
}
