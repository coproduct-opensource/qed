//! The whole native wrap on real circuit data. Ignored by default because it
//! needs RISC Zero's `risc0-groth16` 0.2.0 files (4.2 GB: the witness graph
//! and the proving key) and about 7 GB of memory:
//!
//!   NUCLEUS_GROTH16_DATA=/dir/with/the/two/files \
//!     cargo test --release -p nucleus-groth16-native --test prove -- --ignored
//!
//! Whether the deployed verifier accepts the result is tested where the
//! verifier's bytecode is: contracts/vault-conformance/tests/real_proof3.rs.
use nucleus_groth16_native::{prove, wrap, Error, DATA_DIR_ENV};
use std::path::PathBuf;

fn data() -> PathBuf {
    PathBuf::from(
        std::env::var_os(DATA_DIR_ENV).expect("NUCLEUS_GROTH16_DATA names the data directory"),
    )
}

#[test]
#[ignore = "needs RISC Zero's 4.2 GB Groth16 data; see this file's header"]
fn real_inputs_prove_and_altered_inputs_do_not() {
    let inputs = include_str!("fixtures/input.json");
    let (first, timing) = wrap(inputs, &data()).expect("the fixture inputs prove");
    assert_eq!(timing.variables, 6_257_165);
    // Proofs are randomised: the same inputs give different bytes.
    let (second, _) = wrap(inputs, &data()).expect("the fixture inputs prove again");
    assert_ne!(first, second);

    // The seal's first element, changed. The witness no longer satisfies the
    // circuit, so the proof fails the key's own check and nothing is returned.
    let altered = inputs.replacen("\"334495462\"", "\"334495463\"", 1);
    assert_ne!(altered, inputs);
    match wrap(&altered, &data()) {
        Err(Error::Prove(prove::Error::SelfCheck)) => {}
        other => panic!("altered inputs must not prove: {:?}", other.map(|_| ())),
    }
}
