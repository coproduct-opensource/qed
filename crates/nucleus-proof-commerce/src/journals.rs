//! Public statement encodings shared by proof programs and settlement.
//! Encoding a statement grants no authority and verifies no proof.
use super::{Address, Hash};

/// Exact public output required from a Lean acceptance proof program.
/// The program must check the order's policy against the delivered artifact
/// before emitting this statement; an order digest alone is not an acceptance
/// check.
pub struct Acceptance {
    pub chain_id: u64,
    pub escrow: Address,
    pub order_digest: Hash,
    pub artifact_hash: Hash,
}

fn chain_word(chain: u64) -> Hash {
    let mut word = [0; 32];
    for (target, source) in word.iter_mut().skip(24).zip(chain.to_be_bytes()) {
        *target = source;
    }
    word
}

fn address_word(address: Address) -> Hash {
    let mut word = [0; 32];
    for (target, source) in word.iter_mut().skip(12).zip(address) {
        *target = source;
    }
    word
}

impl Acceptance {
    /// ABI encoding of (bytes32 domain, uint64 chain, address vault,
    /// bytes32 orderDigest, bytes32 deliveredArtifactHash).
    /// The verifier receives SHA-256 of these exact 160 journal bytes.
    pub fn encode(&self) -> [u8; 160] {
        let Self {
            chain_id,
            escrow,
            order_digest,
            artifact_hash,
        } = self;
        let words = [
            crate::hash(b"NucleusAcceptanceV1"),
            chain_word(*chain_id),
            address_word(*escrow),
            *order_digest,
            *artifact_hash,
        ];
        let mut output = [0; 160];
        for (target, source) in output.iter_mut().zip(words.into_iter().flatten()) {
            *target = source;
        }
        output
    }
}
