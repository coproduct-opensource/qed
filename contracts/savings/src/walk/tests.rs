//! The provenance index and the library exclusion set on real exports.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use super::*;

const STATEMENT: &[u8] =
    include_bytes!("../../../proof-acceptance/core/tests/fixtures/task.ndjson");
const ARTIFACT: &[u8] =
    include_bytes!("../../../proof-acceptance/core/tests/fixtures/suffix.ndjson");
const BOUNTY: &[u8] = include_bytes!(
    "../../../site/input/statements/9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c.v2"
);
const BOUNTY_ARTIFACT: &[u8] = include_bytes!(
    "../../../site/input/artifacts/ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin"
);

fn policy(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: sha256(statement),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}

/// The bounty's 285-byte artifact, settled four times on Base, carries
/// `rfl` and `Nat.add_succ` from the Lean library: the exclusion set leaves
/// both out, and only the seller's own two declarations can earn a share.
/// Driven red by an empty set: all four were attributable.
#[test]
fn the_bounty_artifacts_library_declarations_are_excluded() {
    assert_eq!(library_size(), 57_425);
    let d = declarations(&policy(BOUNTY), BOUNTY, BOUNTY_ARTIFACT).unwrap();
    assert_eq!(
        d.names,
        ["rfl", "Nat.add_succ", "Nucleus.helper", "Nucleus.proof"]
    );
    assert_eq!(d.excluded_names(), ["rfl", "Nat.add_succ"]);
    assert_eq!(d.attributable().len(), 2);
    // The first carrier is credited with the helper and the proof only.
    let (a, b) = ([0xa1; 20], [0xb1; 20]);
    let mut index = Provenance::default();
    assert!(index.settle(&d, a, &[0xbb; 20]).is_empty());
    assert_eq!(index.settle(&d, b, &[0xbb; 20]), vec![a]);
    assert_eq!(index.first.len(), 2);
}

/// The Nucleus fixture was exported with Lean 4.35.0, not 4.30.0. Its `rfl`
/// and `Nat.add_succ` are the same terms, so the 4.30.0 set leaves them out
/// too. A declaration whose statement or proof changed between versions
/// would not be; a change of the statements' toolchain needs a new set.
#[test]
fn the_4_35_fixtures_library_declarations_are_the_same_terms() {
    let d = declarations(&policy(STATEMENT), STATEMENT, ARTIFACT).unwrap();
    let excluded = d.excluded_names();
    assert_eq!(excluded, ["rfl", "Nat.add_succ"]);
}

/// The first seller to settle is owed nothing; a second seller settling the
/// same artifact names it as the one author; a seller is never its own
/// author; a key a statement carried is attributed to no one.
#[test]
fn the_first_carrier_is_the_author_and_statement_keys_are_nobodys() {
    let d = declarations(&policy(BOUNTY), BOUNTY, BOUNTY_ARTIFACT).unwrap();
    let (a, b) = ([0xa1; 20], [0xb1; 20]);
    let mut index = Provenance::default();
    assert!(index.settle(&d, a, &[0xbb; 20]).is_empty());
    assert!(index.settle(&d, a, &[0xbb; 20]).is_empty());
    let mut later = index.clone();
    later.settle(
        &Declarations {
            statement: d.seller.clone(),
            seller: vec![],
            names: vec![],
        },
        [0xc1; 20],
        &[0xbb; 20],
    );
    assert!(later.settle(&d, b, &[0xbb; 20]).is_empty());
    // The buyer of B's order is A: A is not credited (`Savings.no_self_credit`).
    assert!(index.clone().settle(&d, b, &a).is_empty());
    assert_eq!(index.settle(&d, b, &[0xbb; 20]), vec![a]);
}

#[test]
fn a_refused_artifact_has_no_declarations() {
    assert!(declarations(&policy(STATEMENT), STATEMENT, b"{}\n").is_err());
}

#[test]
fn the_set_is_sorted_distinct_keys() {
    assert_eq!(LIBRARY.len() % 32, 0);
    let keys: Vec<&[u8]> = LIBRARY.chunks(32).collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]));
    assert!(is_library(keys[0].try_into().unwrap()));
    assert!(!is_library(&[0; 32]));
}

/// A declaration public before its first carrier settled is credited to
/// no one (`Savings.no_credit_for_public`): with the bounty proof's keys
/// public, B's settlement after A's names nobody. Driven red by ignoring
/// the public set in both the index and the lookup: A was credited.
#[test]
fn a_public_declaration_is_credited_to_no_one() {
    let d = declarations(&policy(BOUNTY), BOUNTY, BOUNTY_ARTIFACT).unwrap();
    let public: HashSet<Key> = d.seller.iter().copied().collect();
    let settled = |order: u8, payee: [u8; 20]| Settled {
        order: [order; 32],
        block: u64::from(order) * 10,
        payee,
        buyer: Some([0xbb; 20]),
        declarations: Some(d.clone()),
    };
    let out = attribute_all(
        &[settled(1, [0xa1; 20]), settled(2, [0xb1; 20])],
        &public,
        &[],
    );
    assert_eq!(out[1].1, Attributed::Authors(vec![]));
    let open = attribute_all(
        &[settled(1, [0xa1; 20]), settled(2, [0xb1; 20])],
        &HashSet::new(),
        &[],
    );
    assert_eq!(open[1].1, Attributed::Authors(vec![[0xa1; 20]]));
    // Published from block 5, before the first carrier (block 10): no credit.
    // Published from block 15, after it: the first carrier is credited.
    let early = attribute_all(
        &[settled(1, [0xa1; 20]), settled(2, [0xb1; 20])],
        &HashSet::new(),
        &[(5, public.clone())],
    );
    assert_eq!(early[1].1, Attributed::Authors(vec![]));
    let late = attribute_all(
        &[settled(1, [0xa1; 20]), settled(2, [0xb1; 20])],
        &HashSet::new(),
        &[(15, public.clone())],
    );
    assert_eq!(late[1].1, Attributed::Authors(vec![[0xa1; 20]]));
}
