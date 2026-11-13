//! The EIP-3009 receive authorization that funds an order, as data. The vault
//! module fixes every field of it from the order; this module holds the type
//! and the token's domain strings.
//!
//! The token honours a receive authorization only when the payee calls, so a
//! relayer cannot move the buyer's funds without the vault recording the
//! order. A facilitator for the standard `exact` scheme submits
//! `TransferWithAuthorization`, a different type hash; it has nothing to send.
use crate::{Address, Hash};

pub const RECEIVE_TYPE: &str = "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
pub const TRANSFER_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// The token contract's own EIP-712 domain strings. Chain and contract address
/// come from the deployment and the order, never from a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenDomain {
    pub name: String,
    pub version: String,
}

/// Untrusted wire value until the vault module returns it inside a witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub from: Address,
    pub to: Address,
    pub value: Hash,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: Hash,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("authorization differs from the one this order admits")]
    NotBound,
}

#[cfg(feature = "x402-wire")]
pub mod wire;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;

    fn bytes<const N: usize>(hexadecimal: &str) -> [u8; N] {
        hex::decode(hexadecimal).unwrap().try_into().unwrap()
    }

    #[test]
    fn type_hashes_equal_the_constants_published_in_eip_3009() {
        // Independent vectors: https://eips.ethereum.org/EIPS/eip-3009
        assert_eq!(
            hash(RECEIVE_TYPE.as_bytes()),
            bytes("d099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8")
        );
        assert_eq!(
            hash(TRANSFER_TYPE.as_bytes()),
            bytes("7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267")
        );
    }
}
