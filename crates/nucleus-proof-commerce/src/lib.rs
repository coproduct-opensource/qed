//! Reference semantics for proof-gated agent commerce: order digests, token
//! authorizations, fee arithmetic and proof statements. Data and checks only:
//! no network, no storage, no transfer. A value from this crate is evidence
//! about bytes and signatures, never a funded balance or payment authority.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub type Hash = [u8; 32];
pub type Address = [u8; 20];
pub const BPS_SCALE: u16 = 10_000;
pub mod amounts;
pub mod journals;
mod primitives;
pub mod vault;
pub mod x402;

/// Untrusted signature bytes, with canonical low-s and v=27/28 required.
pub struct WalletSignature(pub [u8; 65]);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid or noncanonical wallet signature")]
    InvalidSignature,
}

fn hash(bytes: &[u8]) -> Hash {
    primitives::keccak(bytes)
}
fn words(words: impl IntoIterator<Item = Hash>) -> Hash {
    let mut bytes = Vec::new();
    for word in words {
        bytes.extend_from_slice(&word);
    }
    hash(&bytes)
}
fn uint(value: u64) -> Hash {
    let mut word = [0; 32];
    let (_, tail) = word.split_at_mut(24);
    tail.copy_from_slice(&value.to_be_bytes());
    word
}
fn address(value: Address) -> Hash {
    let mut word = [0; 32];
    let (_, tail) = word.split_at_mut(12);
    tail.copy_from_slice(&value);
    word
}
#[cfg(test)]
fn domain(name: &str, version: &str, chain_id: u64, contract: Address) -> Hash {
    words([
        hash(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        hash(name.as_bytes()),
        hash(version.as_bytes()),
        uint(chain_id),
        address(contract),
    ])
}
fn typed_digest(domain: Hash, message: Hash) -> Hash {
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(&[0x19, 0x01]);
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&message);
    hash(&bytes)
}
fn recover(digest: Hash, signature: &WalletSignature) -> Result<Address, Error> {
    let recovery = primitives::canonical(&signature.0).ok_or(Error::InvalidSignature)?;
    let (rs, _) = signature.0.split_at(64);
    let rs: &[u8; 64] = rs.try_into().map_err(|_| Error::InvalidSignature)?;
    primitives::recover(&digest, recovery, rs).ok_or(Error::InvalidSignature)
}

#[cfg(test)]
mod tests;

/// Signing helpers shared by this crate's test modules.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{Address, Hash, WalletSignature, hash};
    use k256::ecdsa::SigningKey;

    pub fn wallet(key: &SigningKey) -> Address {
        let point = key.verifying_key().to_sec1_point(false);
        hash(&point.as_bytes()[1..])[12..].try_into().unwrap()
    }
    pub fn sign(key: &SigningKey, digest: Hash) -> WalletSignature {
        let (signature, recovery) = key.sign_prehash_recoverable(&digest);
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = recovery.to_byte() + 27;
        WalletSignature(bytes)
    }
}
