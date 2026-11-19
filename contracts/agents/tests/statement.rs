//! `nucleus-buyer statement` end to end: a git repository, Lean 4.30.0 and
//! `lean4export` 3.1.0. Ignored by default because it needs those tools;
//! run with
//!
//!   QED_LEAN4EXPORT=/path/to/lean4export cargo test --test statement -- --ignored
//!
//! It fails, rather than passes, when `QED_LEAN4EXPORT` is unset.
use nucleus_commerce_agents::statement::{Refusal, Request, Row, generate};
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
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A repository whose package `lean/` holds the fixture statements, plus one
/// whose closure uses `sorry`.
fn repository(name: &str) -> (PathBuf, String) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("statement-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let package = root.join("repo/lean");
    fs::create_dir_all(package.join("Statements")).unwrap();
    for file in ["lakefile.toml", "lean-toolchain"] {
        fs::copy(Path::new(FIXTURE).join(file), package.join(file)).unwrap();
    }
    for id in ["S0001", "S0003", "S0004"] {
        fs::copy(
            Path::new(FIXTURE).join(format!("Statements/{id}.lean")),
            package.join(format!("Statements/{id}.lean")),
        )
        .unwrap();
    }
    fs::write(
        package.join("Statements/S0002.lean"),
        "def Statements.S0002.k : Prop := sorry\n\
         def Statements.S0002.claim : Prop := Statements.S0002.k → Statements.S0002.k\n",
    )
    .unwrap();
    let repo = root.join("repo");
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "fixture"]);
    let commit = git(&repo, &["rev-parse", "HEAD"]);
    (root, commit)
}

fn request(root: &Path, commit: &str, row: &str, work: &str) -> Request {
    Request {
        repo: root.join("repo"),
        commit: commit.to_owned(),
        package: "lean".into(),
        row: Row::parse(row).unwrap(),
        lean4export: exporter(),
        work: root.join(work),
        lake: "lake".into(),
    }
}

#[test]
#[ignore = "needs Lean 4.30.0 and QED_LEAN4EXPORT"]
fn a_statement_is_generated_from_the_commit_and_is_the_same_twice() {
    let (root, commit) = repository("good");
    let first = generate(&request(&root, &commit, "S0001", "w1"))
        .unwrap()
        .unwrap();
    assert_eq!(first.commit, commit);
    // The same statement fixture the unit tests screen, byte for byte.
    assert_eq!(
        first.screened.ndjson(),
        fs::read(Path::new(FIXTURE).join("s0001.ndjson")).unwrap()
    );
    // An uncommitted edit does not reach the statement: it comes from the
    // commit, not the working tree.
    fs::write(
        root.join("repo/lean/Statements/S0001.lean"),
        "def Statements.S0001.claim : Prop := True\n",
    )
    .unwrap();
    let second = generate(&request(&root, &commit, "S0001", "w2"))
        .unwrap()
        .unwrap();
    assert_eq!(
        first.screened.statement_sha256(),
        second.screened.statement_sha256()
    );
    assert_eq!(
        first.screened.statement_sha256(),
        <[u8; 32]>::from(Sha256::digest(second.screened.v2()))
    );
    // Committing the edit is another statement.
    git(&root.join("repo"), &["commit", "-q", "-am", "weaker claim"]);
    let next = git(&root.join("repo"), &["rev-parse", "HEAD"]);
    let third = generate(&request(&root, &next, "S0001", "w3"))
        .unwrap()
        .unwrap();
    assert_ne!(
        first.screened.statement_sha256(),
        third.screened.statement_sha256()
    );
}

#[test]
#[ignore = "needs Lean 4.30.0 and QED_LEAN4EXPORT"]
fn sorry_axioms_and_theorem_claims_are_refused() {
    let (root, commit) = repository("refused");
    assert_eq!(
        generate(&request(&root, &commit, "S0002", "w1"))
            .unwrap()
            .unwrap_err(),
        Refusal::Axiom("sorryAx".into())
    );
    assert_eq!(
        generate(&request(&root, &commit, "S0003", "w2"))
            .unwrap()
            .unwrap_err(),
        Refusal::Axiom("Statements.S0003.cheat".into())
    );
    assert!(matches!(
        generate(&request(&root, &commit, "S0004", "w3"))
            .unwrap()
            .unwrap_err(),
        Refusal::Claim(_)
    ));
    // A row with no module at the commit.
    assert_eq!(
        generate(&request(&root, &commit, "S0009", "w4"))
            .unwrap()
            .unwrap_err(),
        Refusal::ModuleMissing("lean/Statements/S0009.lean".into())
    );
}

#[test]
#[ignore = "needs Lean 4.30.0 and QED_LEAN4EXPORT"]
fn another_toolchain_or_a_bad_commit_is_refused_before_lean_runs() {
    let (root, _) = repository("toolchain");
    fs::write(
        root.join("repo/lean/lean-toolchain"),
        "leanprover/lean4:v4.31.0\n",
    )
    .unwrap();
    git(
        &root.join("repo"),
        &["commit", "-q", "-am", "another toolchain"],
    );
    let moved = git(&root.join("repo"), &["rev-parse", "HEAD"]);
    assert!(matches!(
        generate(&request(&root, &moved, "S0001", "w1"))
            .unwrap()
            .unwrap_err(),
        Refusal::Toolchain(_)
    ));
    assert!(matches!(
        generate(&request(&root, "0123456789abcdef", "S0001", "w2"))
            .unwrap()
            .unwrap_err(),
        Refusal::Commit(_)
    ));
    let mut outside = request(&root, &moved, "S0001", "w3");
    outside.package = "../lean".into();
    assert!(matches!(
        generate(&outside).unwrap().unwrap_err(),
        Refusal::Package(_)
    ));
}
