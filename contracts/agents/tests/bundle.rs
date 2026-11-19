//! A ladder seller's build end to end: a git repository, Lean 4.30.0 and
//! `lean4export` 3.1.0. Ignored by default; run with
//!
//!   QED_LEAN4EXPORT=/path/to/lean4export cargo test --test bundle -- --ignored
use k256::ecdsa::SigningKey;
use nucleus_commerce_agents::{
    bundle::{Built, Committed, Refusal, Toolchain, build, read_files},
    chain::address_of,
    statement::{PERMITTED_AXIOMS, Row},
};
use nucleus_proof_acceptance::{Policy, accept, export_v2_from_ndjson};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/statement");

fn exporter() -> PathBuf {
    std::env::var_os("QED_LEAN4EXPORT")
        .map(PathBuf::from)
        .expect("set QED_LEAN4EXPORT to a lean4export 3.1.0 binary built for Lean 4.30.0")
}

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn key() -> SigningKey {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    SigningKey::from_slice(&secret).unwrap()
}

/// A repository with the fixture package's statement S0001 only, a proof
/// directory with the fixture proof, and the policy for the statement.
fn setup(name: &str) -> (PathBuf, String, PathBuf, Policy) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bundle-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let package = root.join("repo/lean");
    fs::create_dir_all(package.join("Statements")).unwrap();
    for file in ["lakefile.toml", "lean-toolchain", "Statements/S0001.lean"] {
        fs::copy(Path::new(FIXTURE).join(file), package.join(file)).unwrap();
    }
    git(&root.join("repo"), &["init", "-q"]);
    git(&root.join("repo"), &["add", "."]);
    git(&root.join("repo"), &["commit", "-q", "-m", "statement"]);
    let commit = git(&root.join("repo"), &["rev-parse", "HEAD"]);
    let proofs = root.join("proofs/Statements/S0001");
    fs::create_dir_all(&proofs).unwrap();
    fs::copy(
        Path::new(FIXTURE).join("Statements/S0001/Proof.lean"),
        proofs.join("Proof.lean"),
    )
    .unwrap();
    let statement = fs::read(Path::new(FIXTURE).join("s0001.ndjson")).unwrap();
    let policy = Policy {
        statement_sha256: Sha256::digest(export_v2_from_ndjson(&statement, true).unwrap()).into(),
        claim: "Statements.S0001.claim".into(),
        permitted_axioms: PERMITTED_AXIOMS.iter().map(|a| (*a).to_owned()).collect(),
        maximum_artifact_bytes: 90_000,
    };
    let proofs = root.join("proofs");
    (root, commit, proofs, policy)
}

fn lean<'a>(root: &'a Path, commit: &'a str, work: &'a Path) -> Toolchain<'a> {
    Toolchain {
        repo: Box::leak(root.join("repo").into_boxed_path()),
        commit,
        package: "lean",
        lean4export: Box::leak(exporter().into_boxed_path()),
        work,
        lake: "lake",
    }
}

#[test]
#[ignore = "needs Lean 4.30.0 and QED_LEAN4EXPORT"]
fn a_build_reproduces_the_fixture_artifact_and_survives_a_reload() {
    let (root, commit, proofs, policy) = setup("good");
    let row = Row::parse("S0001").unwrap();
    let committed = Committed::new(&row, address_of(&key()), read_files(&proofs).unwrap()).unwrap();
    let built = build(committed, &policy, &lean(&root, &commit, &root.join("w1")))
        .unwrap()
        .unwrap();
    // The committed fixture's suffix, byte for byte: the build is the one the
    // unit tests check.
    let full = fs::read(Path::new(FIXTURE).join("s0001-full.ndjson")).unwrap();
    let statement = fs::read(Path::new(FIXTURE).join("s0001.ndjson")).unwrap();
    assert_eq!(
        built.artifact(),
        export_v2_from_ndjson(&full[statement.len()..], false).unwrap()
    );
    assert_eq!(
        accept(&policy, built.statement(), built.artifact())
            .unwrap()
            .proof,
        "Statements.S0001.proof"
    );
    let saved = root.join("build");
    built.save(&saved).unwrap();
    let again = Built::load(&saved, &policy).unwrap().unwrap();
    assert_eq!(again.artifact(), built.artifact());

    // A changed byte in the saved proof, or in the saved artifact, is refused
    // on reload.
    let proof = saved.join("Statements/S0001/Proof.lean");
    let original = fs::read(&proof).unwrap();
    fs::write(&proof, [&original[..], b"\n"].concat()).unwrap();
    assert!(matches!(
        Built::load(&saved, &policy).unwrap().unwrap_err(),
        Refusal::Manifest(_)
    ));
    fs::write(&proof, &original).unwrap();
    let artifact = saved.join("artifact.v2");
    let mut bytes = fs::read(&artifact).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&artifact, &bytes).unwrap();
    assert!(matches!(
        Built::load(&saved, &policy).unwrap().unwrap_err(),
        Refusal::Manifest(_)
    ));
}

#[test]
#[ignore = "needs Lean 4.30.0 and QED_LEAN4EXPORT"]
fn one_changed_byte_in_the_proof_is_another_artifact() {
    let (root, commit, proofs, policy) = setup("byte");
    let row = Row::parse("S0001").unwrap();
    let first = build(
        Committed::new(&row, address_of(&key()), read_files(&proofs).unwrap()).unwrap(),
        &policy,
        &lean(&root, &commit, &root.join("w1")),
    )
    .unwrap()
    .unwrap();
    // A comment changes no declaration, but it changes the manifest, so the
    // commitment, so the artifact: a settlement for one is not for the other.
    let path = proofs.join("Statements/S0001/Proof.lean");
    let mut text = fs::read(&path).unwrap();
    text.extend_from_slice(b"-- a comment\n");
    fs::write(&path, text).unwrap();
    let second = build(
        Committed::new(&row, address_of(&key()), read_files(&proofs).unwrap()).unwrap(),
        &policy,
        &lean(&root, &commit, &root.join("w2")),
    )
    .unwrap()
    .unwrap();
    assert_ne!(first.manifest().sha256(), second.manifest().sha256());
    assert_ne!(first.artifact(), second.artifact());
}

#[test]
#[ignore = "needs Lean 4.30.0 and QED_LEAN4EXPORT"]
fn a_proof_at_another_path_or_against_another_statement_is_refused() {
    let (root, commit, proofs, policy) = setup("refused");
    let row = Row::parse("S0001").unwrap();
    // The path is part of the terms: a proof elsewhere is not this row's.
    assert_eq!(
        Committed::new(
            &row,
            address_of(&key()),
            vec![("Statements/Proof.lean".into(), b"x".to_vec())]
        )
        .unwrap_err(),
        Refusal::Path("Statements/Proof.lean".into())
    );
    let mut other = policy.clone();
    other.statement_sha256 = [7; 32];
    assert_eq!(
        build(
            Committed::new(&row, address_of(&key()), read_files(&proofs).unwrap()).unwrap(),
            &other,
            &lean(&root, &commit, &root.join("w1")),
        )
        .unwrap()
        .unwrap_err(),
        Refusal::StatementMismatch
    );
}
