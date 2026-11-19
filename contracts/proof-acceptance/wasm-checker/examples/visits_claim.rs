//! Export the claim `/visits` checks in the browser, and check it natively.
//!
//!   cargo run --example visits_claim -- PACKAGE_DIR LEAN4EXPORT OUT_DIR
//!
//! `PACKAGE_DIR` is `contracts/analytics/browser-check` (Lean core only).
//! The statement is `lean4export QedVisits.Statement -- propext
//! QedVisits.claim`; the artifact is the rest of `lean4export
//! QedVisits.Statement QedVisits.Proof -- … QedVisits.claim QedVisits.proof`
//! after the statement's bytes, both in export format v2, as the QED
//! acceptance rule reads a buyer's statement and a seller's artifact.
//!
//! Screened as the ladder's statements are (`contracts/agents/src/statement.rs`):
//! the exporter exits 0 and writes nothing to standard error (it exits 0
//! after panicking on a missing root), its meta line names lean4export 3.1.0,
//! format 3.1.0 and Lean 4.30.0, the statement export is a byte prefix of the
//! whole, and the acceptance rule accepts the pair with `QedVisits.proof` as
//! the proof. Writes `statement.v2`, `artifact.v2`, `policy.json` and
//! `record.json` to `OUT_DIR`.
use nucleus_proof_acceptance::{Policy, accept, export_v2_from_ndjson};
use serde_json::json;
use sha2::Digest as _;
use std::error::Error;
use std::path::Path;
use std::process::{Command, Stdio};

const CLAIM: &str = "QedVisits.claim";
const PROOF: &str = "QedVisits.proof";
/// The axioms the proof uses (`#print axioms QedVisits.proof`).
const AXIOMS: [&str; 1] = ["propext"];
const MAXIMUM_ARTIFACT_BYTES: u32 = 1_048_576;
const META: &str = "{\"meta\":{\"exporter\":{\"name\":\"lean4export\",\"version\":\"3.1.0\"},\"format\":{\"version\":\"3.1.0\"},\"lean\":{\"githash\":\"d024af099ca4bf2c86f649261ebf59565dc8c622\",\"version\":\"4.30.0\"}}}";

type Res<T> = Result<T, Box<dyn Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

fn export(package: &Path, lean4export: &Path, modules: &[&str], roots: &[&str]) -> Res<Vec<u8>> {
    let out = Command::new("lake")
        .arg("env")
        .arg(lean4export)
        .args(modules)
        .arg("--")
        .args(roots)
        .current_dir(package)
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() || !out.stderr.is_empty() {
        return Err(format!(
            "lean4export {modules:?}: {} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    if out.stdout.split(|b| *b == b'\n').next() != Some(META.as_bytes()) {
        return Err("the export's meta line is not lean4export 3.1.0 on Lean 4.30.0".into());
    }
    Ok(out.stdout)
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [package, lean4export, out] = args.as_slice() else {
        return Err("usage: visits_claim PACKAGE_DIR LEAN4EXPORT OUT_DIR".into());
    };
    let (package, lean4export, out) = (Path::new(package), Path::new(lean4export), Path::new(out));
    let built = Command::new("lake")
        .args(["build", "QedVisits.Statement", "QedVisits.Proof"])
        .current_dir(package)
        .stdin(Stdio::null())
        .status()?;
    if !built.success() {
        return Err(format!("lake build: {built}").into());
    }
    let mut roots: Vec<&str> = AXIOMS.to_vec();
    roots.push(CLAIM);
    let statement_ndjson = export(package, lean4export, &["QedVisits.Statement"], &roots)?;
    roots.push(PROOF);
    let full_ndjson = export(
        package,
        lean4export,
        &["QedVisits.Statement", "QedVisits.Proof"],
        &roots,
    )?;
    let suffix = full_ndjson
        .strip_prefix(statement_ndjson.as_slice())
        .ok_or("the statement export is not a prefix of the whole")?;
    let statement = export_v2_from_ndjson(&statement_ndjson, true).map_err(|e| format!("{e:?}"))?;
    let artifact = export_v2_from_ndjson(suffix, false).map_err(|e| format!("{e:?}"))?;
    let whole = export_v2_from_ndjson(&full_ndjson, true).map_err(|e| format!("{e:?}"))?;
    if [statement.as_slice(), artifact.as_slice()].concat() != whole {
        return Err("v2(statement) ++ v2(rest) is not v2(whole)".into());
    }
    let policy = Policy {
        statement_sha256: sha256(&statement),
        claim: CLAIM.into(),
        permitted_axioms: AXIOMS.iter().map(|a| (*a).to_owned()).collect(),
        maximum_artifact_bytes: MAXIMUM_ARTIFACT_BYTES,
    };
    let accepted = accept(&policy, &statement, &artifact).map_err(|e| format!("{e:?}"))?;
    if accepted.proof != PROOF {
        return Err(format!("accepted with {}, not {PROOF}", accepted.proof).into());
    }
    let source = |name: &str| -> Res<String> {
        Ok(hex(&sha256(&std::fs::read(
            package.join("QedVisits").join(name),
        )?)))
    };
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("statement.v2"), &statement)?;
    std::fs::write(out.join("artifact.v2"), &artifact)?;
    let policy_json = json!({
        "statementSha256": hex(&policy.statement_sha256),
        "claim": policy.claim,
        "permittedAxioms": policy.permitted_axioms,
        "maximumArtifactBytes": policy.maximum_artifact_bytes,
    });
    std::fs::write(
        out.join("policy.json"),
        serde_json::to_vec_pretty(&policy_json)?,
    )?;
    let record = json!({
        "claim": CLAIM,
        "proof": PROOF,
        "permittedAxioms": AXIOMS,
        "statementSha256": hex(&sha256(&statement)),
        "statementBytes": statement.len(),
        "artifactSha256": hex(&sha256(&artifact)),
        "artifactBytes": artifact.len(),
        "declarations": accepted.declarations,
        "policyHash": format!("0x{}", hex(&policy.hash())),
        "sources": {
            "QedVisits/Statement.lean": source("Statement.lean")?,
            "QedVisits/Proof.lean": source("Proof.lean")?,
        },
        "toolchain": "leanprover/lean4:v4.30.0",
        "exporter": {
            "name": "lean4export",
            "version": "3.1.0",
            "binarySha256": hex(&sha256(&std::fs::read(lean4export)?)),
        },
    });
    std::fs::write(out.join("record.json"), serde_json::to_vec_pretty(&record)?)?;
    println!(
        "accepted: {} proves {CLAIM}, {} declarations; statement {} bytes, artifact {} bytes",
        accepted.proof,
        accepted.declarations,
        statement.len(),
        artifact.len()
    );
    Ok(())
}
