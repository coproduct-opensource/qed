//! The last step of a settlement proof, without the x86 prover container:
//! from the `input.json` RISC Zero derives from an `identity_p254` seal, to
//! the 256 proof bytes of a Groth16 seal for the `stark_verify` circuit.
//!
//! Two data files are needed, both published by RISC Zero in its `rzup`
//! component `risc0-groth16` 0.2.0: `stark_verify_graph.bin` (how to compute
//! the witness) and `stark_verify_final.zkey` (the proving key from the
//! trusted setup). Neither is trusted for soundness here: a wrong graph or key
//! gives a proof that the on-chain verifier refuses.
pub mod graph;
pub mod inputs;
pub mod prove;
mod seal_layout;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use std::{path::Path, time::Instant};

pub use prove::ProofBytes;

/// Where the data files are looked for when the caller names no directory.
pub const DATA_DIR_ENV: &str = "NUCLEUS_GROTH16_DATA";
pub const GRAPH_FILE: &str = "stark_verify_graph.bin";
pub const KEY_FILE: &str = "stark_verify_final.zkey";

#[derive(Debug, Default, Clone, Copy)]
pub struct Timing {
    pub graph_load: f64,
    pub witness: f64,
    pub prove: prove::Timing,
    pub nodes: usize,
    pub variables: usize,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Graph(graph::Error),
    Prove(prove::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(error) => write!(f, "{error}"),
            Error::Graph(error) => write!(f, "{error}"),
            Error::Prove(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {}

/// Proof bytes for the circuit inputs in `input_json`, using the two data
/// files in `data_dir`.
pub fn wrap(input_json: &str, data_dir: &Path) -> Result<(ProofBytes, Timing), Error> {
    let mut timing = Timing::default();
    let started = Instant::now();
    let bytes = std::fs::read(data_dir.join(GRAPH_FILE)).map_err(Error::Io)?;
    let graph = graph::Graph::parse(&bytes).map_err(Error::Graph)?;
    drop(bytes);
    timing.graph_load = started.elapsed().as_secs_f64();
    timing.nodes = graph.nodes();

    let started = Instant::now();
    let witness: Vec<Fr> = graph
        .witness(input_json)
        .map_err(Error::Graph)?
        .into_iter()
        .map(|v| Fr::from_le_bytes_mod_order(&v.to_le_bytes::<32>()))
        .collect();
    drop(graph);
    timing.witness = started.elapsed().as_secs_f64();
    timing.variables = witness.len();

    let (proof, proving) =
        prove::prove(&data_dir.join(KEY_FILE), &witness).map_err(Error::Prove)?;
    timing.prove = proving;
    Ok((proof, timing))
}
