//! The provenance index on the real Nucleus fixture.
#![allow(clippy::unwrap_used)]
use super::*;

const STATEMENT: &[u8] =
    include_bytes!("../../../proof-acceptance/core/tests/fixtures/task.ndjson");
const ARTIFACT: &[u8] =
    include_bytes!("../../../proof-acceptance/core/tests/fixtures/suffix.ndjson");

fn policy() -> Policy {
    Policy {
        statement_sha256: sha256(STATEMENT),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}

/// The first seller to settle the artifact is owed nothing (it reused no
/// one's lemma); a second seller settling the same artifact reused all four
/// of the first's declarations and names it as the one author. A key a
/// statement carried is attributed to no one.
#[test]
fn the_first_carrier_is_the_author_and_statement_keys_are_nobodys() {
    let d = declarations(&policy(), STATEMENT, ARTIFACT).unwrap();
    assert_eq!(
        d.names,
        ["rfl", "Nat.add_succ", "Nucleus.helper", "Nucleus.proof"]
    );
    assert!(!d.statement.is_empty());
    let (a, b) = ([0xa1; 20], [0xb1; 20]);
    let mut index = Provenance::default();
    assert!(index.settle(&d, a).is_empty());
    assert_eq!(index.settle(&d, b), vec![a]);
    // A itself settling again is not its own author.
    assert!(index.settle(&d, a).is_empty());
    // Once a statement carries every one of these keys, none is attributed.
    let mut library = d.clone();
    library.statement = d.seller.clone();
    let mut later = index.clone();
    later.settle(
        &Declarations {
            seller: vec![],
            names: vec![],
            ..library
        },
        [0xc1; 20],
    );
    assert!(later.settle(&d, b).is_empty());
}

#[test]
fn a_refused_artifact_has_no_declarations() {
    assert!(declarations(&policy(), STATEMENT, b"{}\n").is_err());
}
