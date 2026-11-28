//! `qed-library-keys EXPORT.ndjson OUT.keys [AXIOM]...`: the library
//! exclusion set of proof-carrying savings. Parses the export once (no
//! kernel check), keys every declaration as `qed_savings::walk::key` does,
//! and writes the keys sorted and distinct, 32 bytes each. Prints the
//! export's SHA-256, the declaration count and the set's SHA-256.
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [export, out, axioms @ ..] = args.as_slice() else {
        eprintln!("usage: qed-library-keys EXPORT.ndjson OUT.keys [AXIOM]...");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(export) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{export}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let export_sha = qed_savings::walk::sha256(&bytes);
    let keys = match qed_savings::walk::library_keys(bytes, axioms.to_vec()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{export}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let flat: Vec<u8> = keys.iter().flatten().copied().collect();
    if let Err(e) = std::fs::write(out, &flat) {
        eprintln!("{out}: {e}");
        return ExitCode::FAILURE;
    }
    let hex = |h: &[u8]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("export sha256 {}", hex(&export_sha));
    println!("keys {}", keys.len());
    println!("set sha256 {}", hex(&qed_savings::walk::sha256(&flat)));
    ExitCode::SUCCESS
}
