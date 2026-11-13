//! Seller and buyer agents for the thin vault, and operations on a deployment.
//!
//! - `nucleus-seller`: takes a statement from a buyer, runs a configured
//!   prover command on it, and offers an order only once it holds an artifact
//!   the Lean checker accepts. Then relays `fund`, proves, relays `settle`.
//! - `nucleus-buyer`: asks one seller for one proof, reviews the offer against
//!   its own limits, signs one token authorization, and checks the delivered
//!   artifact and the chain itself.
//! - `nucleus-vault-ops`: deploy, preflight, sweep, gas.
//!
//! Model of the seller's job states: `job.rs`. Transport-independent messages:
//! `message.rs`. Adapters: `iroh_net.rs` (default) and `http.rs`.
pub mod a2a;
pub mod a2a_iroh;
pub mod blobs;
pub mod board;
pub mod bounty;
pub mod buyer;
pub mod chain;
pub mod deploy;
pub mod desk;
pub mod dpop;
pub mod http;
pub mod iroh_net;
pub mod job;
pub mod message;
pub mod ops;
pub mod post;
pub mod seller;
pub mod support;
pub mod tasks;
pub mod watch;
pub mod worker;
pub mod world;

/// What every module here uses.
pub(crate) mod prelude {
    pub(crate) use crate::chain::{Address, Chain, Res, address_of, hex, keccak, unhex};
    pub(crate) use crate::support::{B64, B64URL, Keys, random32};
    pub(crate) use alloy_primitives::{Address as A, Bytes, U256};
    pub(crate) use alloy_sol_types::{SolCall, SolValue, sol};
    pub(crate) use base64::Engine;
    pub(crate) use k256::ecdsa::SigningKey;
    pub(crate) use nucleus_proof_acceptance::Policy;
    pub(crate) use nucleus_proof_commerce::{WalletSignature, vault, x402};
    pub(crate) use serde_json::{Value, json};
    pub(crate) use sha2::{Digest, Sha256};
    pub(crate) use std::{fs, path::Path};
}
use prelude::*;

sol! {
    function initialize(string tokenName, string tokenSymbol, string tokenCurrency, uint8 tokenDecimals, address newMasterMinter, address newPauser, address newBlacklister, address newOwner);
    function initializeV2(string newName);
    function initializeV2_1(address lostAndFound);
    function initializeV2_2(address[] accountsToBlacklist, string newSymbol);
    function configureMinter(address minter, uint256 minterAllowedAmount) returns (bool);
    function mint(address to, uint256 amount) returns (bool);
    function balanceOf(address account) returns (uint256);
}

pub fn sign(key: &SigningKey, digest: [u8; 32]) -> WalletSignature {
    let (signature, recovery) = key.sign_prehash_recoverable(&digest);
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte() + 27;
    WalletSignature(bytes)
}

/// Run a command's `main`, printing a refusal and failing the process.
pub fn exit(result: chain::Res<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
