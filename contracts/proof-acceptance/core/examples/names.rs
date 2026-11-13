//! Lists the declarations of an export, one per line: kind, then the dotted
//! name. For choosing the roots of a base. Parses only; nothing is checked.
//!
//!   cargo run --release --example names -- EXPORT [PERMITTED_AXIOM...]
use nanoda_lib::acceptance::inspect;
use std::{error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [export, axioms @ ..] = args.as_slice() else {
        return Err("usage: names EXPORT [PERMITTED_AXIOM...]".into());
    };
    let export = fs::read(export)?;
    let axioms = axioms.to_vec();
    let entries = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || inspect(&export, &axioms, false))?
        .join()
        .map_err(|_| "the parser aborted")??;
    for entry in entries {
        println!("{:?} {}", entry.kind, entry.name);
    }
    Ok(())
}
