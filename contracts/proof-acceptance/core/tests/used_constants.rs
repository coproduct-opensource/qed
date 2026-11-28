//! The savings attribution walk (`nanoda_lib::acceptance::used_constants`)
//! on real exports: the Nucleus fixture, the same proof on a checked base,
//! and the bounty's 285-byte artifact as it was settled on Base.
//! docs/rfcs/qed-proof-carrying-savings-2026-11-28.md.
use nanoda_lib::acceptance::{Walked, is_kernel_reserved, used_constants};
use nucleus_proof_acceptance::{Policy, accept};
use sha2::{Digest, Sha256};

const STATEMENT: &[u8] = include_bytes!("fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/suffix.ndjson");
const ON_BASE: &[u8] = include_bytes!("fixtures/base/task-on-base.ndjson");
const ARTIFACT_ON_BASE: &[u8] = include_bytes!("fixtures/base/suffix-on-base.ndjson");
const BOUNTY: &[u8] = include_bytes!(
    "../../../site/input/statements/9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c.v2"
);
const BOUNTY_ARTIFACT: &[u8] = include_bytes!(
    "../../../site/input/artifacts/ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin"
);

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn policy_for(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: sha256(statement),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
/// Accept, then walk from the accepted proof, on a deep stack as the
/// acceptance host does.
fn walk(statement: &'static [u8], artifact: &'static [u8]) -> (String, Walked) {
    let proof = accept(&policy_for(statement), statement, artifact).unwrap().proof;
    let root = proof.clone();
    let walked = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            used_constants(&[statement, artifact], &[], &[statement.len()], &root, &mut sha256)
        })
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
    (proof, walked)
}
fn seller_side(w: &Walked) -> Vec<String> {
    w.used
        .iter()
        .filter(|u| u.position >= w.counts[0])
        .map(|u| u.name.clone())
        .collect()
}

/// The proof reuses its helper, and the helper `Nat.add_succ`; the walk
/// reaches every seller declaration and stops at no reserved name.
///
/// The seller side is four declarations, not two: the artifact re-exports
/// `rfl` and `Nat.add_succ`, Lean library declarations the statement did
/// not carry. A first-carrier provenance rule would name the first seller
/// as their author (docs/rfcs/qed-proof-carrying-savings-2026-11-28.md,
/// "Library declarations").
/// Driven red by not following the constants a value names (the helper was
/// missing) and by keeping reserved names (`Nat` appeared).
#[test]
fn the_walk_reaches_the_helper_through_the_proof_and_leaves_out_reserved_names() {
    let (proof, w) = walk(STATEMENT, ARTIFACT);
    assert_eq!(proof, "Nucleus.proof");
    assert_eq!(
        seller_side(&w),
        ["rfl", "Nat.add_succ", "Nucleus.helper", "Nucleus.proof"]
    );
    let names: Vec<&str> = w.used.iter().map(|u| u.name.as_str()).collect();
    assert!(names.contains(&"Nucleus.Claim"), "{names:?}");
    assert!(names.contains(&"Nat.add_succ"), "{names:?}");
    assert!(w.used.iter().all(|u| !is_kernel_reserved(&u.name)), "{names:?}");
    assert!(!names.contains(&"Nat"));
    // Theorems and definitions have values; the rest do not.
    let helper = w.used.iter().find(|u| u.name == "Nucleus.helper").unwrap();
    assert!(helper.value.is_some());
}

/// The same proof exported over a checked base: other back-references, the
/// same digests for the declarations the two exports share.
#[test]
fn the_same_term_in_another_export_has_the_same_digests() {
    let (_, plain) = walk(STATEMENT, ARTIFACT);
    let (_, based) = walk(ON_BASE, ARTIFACT_ON_BASE);
    assert_ne!(STATEMENT, ON_BASE);
    let helper = |w: &Walked| w.used.iter().find(|u| u.name == "Nucleus.helper").cloned().unwrap();
    let (a, b) = (helper(&plain), helper(&based));
    assert_eq!((a.ty, a.value), (b.ty, b.value));
}

/// The bounty's statement and the 285-byte artifact settled for it four
/// times on Base: the same four seller-side declarations as the fixture, in
/// export v2.
#[test]
fn the_settled_bounty_artifact_carries_the_same_four_declarations() {
    let (proof, w) = walk(BOUNTY, BOUNTY_ARTIFACT);
    assert_eq!(BOUNTY_ARTIFACT.len(), 285);
    assert_eq!(proof, "Nucleus.proof");
    assert_eq!(
        seller_side(&w),
        ["rfl", "Nat.add_succ", "Nucleus.helper", "Nucleus.proof"]
    );
    // The same terms as the NDJSON fixture's, by digest.
    let (_, plain) = walk(STATEMENT, ARTIFACT);
    let digests = |w: &Walked| -> Vec<_> {
        w.used.iter().filter(|u| u.position >= w.counts[0]).map(|u| (u.ty, u.value)).collect()
    };
    assert_eq!(digests(&w), digests(&plain));
}
