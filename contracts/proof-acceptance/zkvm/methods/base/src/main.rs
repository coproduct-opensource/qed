//! Proof guest for a base library: read one encoded input, parse and
//! type-check the base in the kernel checker under the stated axioms, and
//! commit the 160-byte base journal (base id, axioms hash, payee, rate).
//! Every refusal is a panic, so a base that does not check yields nothing a
//! verifier would accept.
use nucleus_proof_acceptance::base::{check_aborting, Input};
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let mut bytes = Vec::new();
    env::stdin().read_to_end(&mut bytes).expect("input unreadable");
    // The base is read in place from `bytes`, not copied out.
    let input = Input::decode_borrowed(&bytes).expect("input refused");
    env::commit_slice(&check_aborting(&input).expect("base refused"));
}
