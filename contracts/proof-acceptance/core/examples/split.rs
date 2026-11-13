//! Where the acceptance rule's time goes on one statement/artifact pair:
//! parsing the statement alone, parsing the whole export, and parsing plus
//! type-checking the whole export. Native timings; a guide to proportions,
//! not to zkVM cycle counts.
//!
//!   cargo run --release --example split -- STATEMENT ARTIFACT [PERMITTED_AXIOM...]
use nanoda_lib::acceptance::inspect;
use std::{error::Error, fs, time::Instant};

fn timed(
    label: &str,
    export: Vec<u8>,
    axioms: Vec<String>,
    check: bool,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let entries = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || inspect(&export, &axioms, check))?
        .join()
        .map_err(|_| "the checker aborted")??;
    println!(
        "{label}: {:.1} ms, {} declarations",
        started.elapsed().as_secs_f64() * 1000.0,
        entries.len()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [statement, artifact, axioms @ ..] = args.as_slice() else {
        return Err("usage: split STATEMENT ARTIFACT [PERMITTED_AXIOM...]".into());
    };
    let statement = fs::read(statement)?;
    let whole = [statement.clone(), fs::read(artifact)?].concat();
    println!(
        "statement {} bytes, whole {} bytes",
        statement.len(),
        whole.len()
    );
    for _ in 0..3 {
        timed("parse statement", statement.clone(), axioms.to_vec(), false)?;
        timed("parse whole", whole.clone(), axioms.to_vec(), false)?;
        timed(
            "parse and check whole",
            whole.clone(),
            axioms.to_vec(),
            true,
        )?;
    }
    Ok(())
}
