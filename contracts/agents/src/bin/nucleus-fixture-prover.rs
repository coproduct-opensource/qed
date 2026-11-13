//! A stand-in prover for tests and demonstrations. It "proves" exactly one
//! statement: given a statement whose SHA-256 equals that of KNOWN_STATEMENT,
//! it writes KNOWN_ARTIFACT; for anything else it fails. It shows the
//! interface a real prover command must meet, and nothing about proving.
//!
//!   nucleus-fixture-prover KNOWN_STATEMENT KNOWN_ARTIFACT STATEMENT_PATH ARTIFACT_OUT
//!
//! The seller appends the last two arguments.
use sha2::{Digest, Sha256};
use std::{fs, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [known_statement, known_artifact, statement, out] = args.as_slice() else {
        eprintln!(
            "usage: nucleus-fixture-prover KNOWN_STATEMENT KNOWN_ARTIFACT STATEMENT_PATH ARTIFACT_OUT"
        );
        return ExitCode::from(2);
    };
    let read = |path: &String| fs::read(path).map_err(|e| format!("{path}: {e}"));
    let work = || -> Result<(), String> {
        if Sha256::digest(read(statement)?) != Sha256::digest(read(known_statement)?) {
            return Err("no proof known for this statement".into());
        }
        fs::write(out, read(known_artifact)?).map_err(|e| e.to_string())
    };
    match work() {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("{why}");
            ExitCode::FAILURE
        }
    }
}
