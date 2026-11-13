//! Measures one statement/artifact pair through the acceptance rule and writes
//! the vault program input for it, around fixed unsigned order fields.
//!
//!   cargo run --release --example measure -- STATEMENT ARTIFACT OUT [PERMITTED_AXIOM...]
use nucleus_proof_acceptance::{Policy, accept, vault_program::Input};
use nucleus_proof_commerce::vault::Order;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [statement, artifact, out, axioms @ ..] = args.as_slice() else {
        return Err("usage: measure STATEMENT ARTIFACT OUT [PERMITTED_AXIOM...]".into());
    };
    let statement = fs::read(statement)?;
    let artifact = fs::read(artifact)?;
    let policy = Policy {
        statement_sha256: Sha256::digest(&statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: axioms.to_vec(),
        // 65,536 unless NUCLEUS_MEASURE_MAX_ARTIFACT names another cap.
        maximum_artifact_bytes: match std::env::var("NUCLEUS_MEASURE_MAX_ARTIFACT") {
            Ok(text) => text.parse()?,
            Err(_) => 65_536,
        },
    };
    let started = Instant::now();
    let verdict = accept(&policy, &statement, &artifact);
    println!("statement_bytes {}", statement.len());
    println!("artifact_bytes {}", artifact.len());
    println!("native_seconds {:.3}", started.elapsed().as_secs_f64());
    println!("verdict {verdict:?}");
    let input = Input {
        // The second form unless NUCLEUS_MEASURE_FORM is "third".
        form: match std::env::var("NUCLEUS_MEASURE_FORM").as_deref() {
            Ok("third") => nucleus_proof_commerce::vault::Form::Third,
            _ => nucleus_proof_commerce::vault::Form::Second,
        },
        chain_id: 421614,
        vault: [3; 20],
        order: Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [4; 20],
            amount: [9; 32],
            verifier: [5; 20],
            program: [6; 32],
            policy_hash: policy.hash(),
            base: [0; 32],
            fund_by: 1000,
            deliver_by: 2000,
            salt: [7; 32],
            context: [8; 32],
        },
        policy,
        statement,
        artifact,
    };
    fs::write(out, input.encode())?;
    Ok(())
}
