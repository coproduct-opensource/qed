//! Strict x402 v2 wire helpers shared with the `nucleus-vault` scheme
//! (`crate::vault::wire`). Parsing only: no network, no storage, no settlement.
//!
//! Spec read 2026-11-11: x402-foundation/x402 `specs/x402-specification-v2.md`
//! and `specs/transports-v2/http.md` on `main`. The revision is not pinned;
//! the GitHub API refused the lookup. `contracts/x402-interop` reads our
//! headers with an independent implementation's types.
use crate::Hash;
use base64::Engine;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

pub const REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";
pub const SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";
/// Decoded header bytes. Larger input is refused before JSON parsing.
pub const MAXIMUM_BYTES: usize = 16_384;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("header exceeds the size limit")]
    TooLarge,
    #[error("header is not canonical base64 of one JSON object of this scheme")]
    Malformed,
    #[error("x402Version must be 2")]
    Version,
    #[error("a hex or decimal field is not in canonical form")]
    Encoding,
    #[error("payment requirements differ from the ones the order fixes")]
    RequirementsMismatch,
    #[error(transparent)]
    Authorization(#[from] super::Error),
}

pub(crate) fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2).saturating_add(2));
    out.push_str("0x");
    for byte in bytes {
        for nibble in [byte >> 4, byte & 15] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    out
}
/// Lowercase only, exact length. Checksummed mixed case is refused so that one
/// value has one spelling.
pub(crate) fn unhex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let digits = text.strip_prefix("0x").ok_or(Error::Encoding)?;
    if digits.len() != N.saturating_mul(2) {
        return Err(Error::Encoding);
    }
    let mut out = [0u8; N];
    let mut nibbles = digits.chars().map(|c| match c {
        '0'..='9' | 'a'..='f' => c.to_digit(16).and_then(|d| u8::try_from(d).ok()),
        _ => None,
    });
    for slot in &mut out {
        let high = nibbles.next().flatten().ok_or(Error::Encoding)?;
        let low = nibbles.next().flatten().ok_or(Error::Encoding)?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}
pub(crate) fn decimal_of(word: Hash) -> String {
    U256::from_be_bytes(word).to_string()
}
/// Canonical decimal: digits only, no sign, no leading zero except "0".
pub(crate) fn undecimal(text: &str) -> Result<Hash, Error> {
    let value = U256::from_str_radix(text, 10).map_err(|_| Error::Encoding)?;
    if value.to_string() != text {
        return Err(Error::Encoding);
    }
    Ok(value.to_be_bytes())
}
pub(crate) fn undecimal_u64(text: &str) -> Result<u64, Error> {
    let value: u64 = text.parse().map_err(|_| Error::Encoding)?;
    if value.to_string() != text {
        return Err(Error::Encoding);
    }
    Ok(value)
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<String, Error> {
    let json = serde_json::to_vec(value).map_err(|_| Error::Malformed)?;
    if json.len() > MAXIMUM_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}
pub(crate) fn decode<T: for<'a> Deserialize<'a>>(header: &str) -> Result<T, Error> {
    // Four base64 characters carry three bytes.
    if header.len()
        > MAXIMUM_BYTES
            .saturating_mul(4)
            .div_ceil(3)
            .saturating_add(4)
    {
        return Err(Error::TooLarge);
    }
    let json = base64::engine::general_purpose::STANDARD
        .decode(header)
        .map_err(|_| Error::Malformed)?;
    if json.len() > MAXIMUM_BYTES {
        return Err(Error::TooLarge);
    }
    serde_json::from_slice(&json).map_err(|_| Error::Malformed)
}

/// The digest of a request, as both sides compute it for `Order.request_hash`.
pub fn request_hash(method: &str, uri: &str, body: &[u8]) -> Hash {
    crate::words([
        crate::hash(b"NucleusRequestV1"),
        crate::hash(method.as_bytes()),
        crate::hash(uri.as_bytes()),
        crate::hash(body),
    ])
}

pub const BUYER_HEADER: &str = "NUCLEUS-BUYER";
pub const RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";

/// Sent by the buyer with its first request so the seller can name it in an
/// order. A declaration is a claim. The seller honours it only for the key
/// that proved possession on that same request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BuyerDeclaration {
    pub wallet: String,
    pub key_binding: String,
}

/// The 32-byte key binding of an RFC 7638 SHA-256 JWK thumbprint, as a DPoP
/// verifier reports it (unpadded base64url).
pub fn key_binding(thumbprint: &str) -> Result<Hash, Error> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(thumbprint)
        .map_err(|_| Error::Encoding)?;
    bytes.try_into().map_err(|_| Error::Encoding)
}

pub fn declaration_header(wallet: [u8; 20], key_binding: Hash) -> Result<String, Error> {
    encode(&BuyerDeclaration {
        wallet: hex_of(&wallet),
        key_binding: hex_of(&key_binding),
    })
}

#[cfg(test)]
mod tests;
