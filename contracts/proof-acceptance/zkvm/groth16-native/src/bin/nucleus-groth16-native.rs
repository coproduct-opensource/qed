//! Measure or use the native wrap on its own.
//!
//!   nucleus-groth16-native INPUT_JSON DATA_DIR OUT_PROOF_HEX
use std::{path::Path, process::ExitCode, time::Instant};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, data, out] = args.as_slice() else {
        eprintln!("usage: nucleus-groth16-native INPUT_JSON DATA_DIR OUT_PROOF_HEX");
        return ExitCode::from(2);
    };
    let started = Instant::now();
    let result = std::fs::read_to_string(input)
        .map_err(|e| e.to_string())
        .and_then(|json| {
            nucleus_groth16_native::wrap(&json, Path::new(data)).map_err(|e| e.to_string())
        });
    match result {
        Ok((proof, timing)) => {
            let hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();
            if let Err(error) = std::fs::write(out, &hex) {
                eprintln!("refused: {error}");
                return ExitCode::FAILURE;
            }
            println!("nodes {} variables {}", timing.nodes, timing.variables);
            println!("graph_load_seconds {:.1}", timing.graph_load);
            println!("witness_seconds {:.1}", timing.witness);
            println!("quotient_seconds {:.1}", timing.prove.quotient);
            println!(
                "load_and_multiply_seconds {:.1}",
                timing.prove.load_and_multiply
            );
            println!("self_check_seconds {:.1}", timing.prove.check);
            println!("total_seconds {:.1}", started.elapsed().as_secs_f64());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("refused: {error}");
            ExitCode::FAILURE
        }
    }
}
