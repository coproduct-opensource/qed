//! Keccak-256 and secp256k1 public-key recovery, from the `sha3` and `k256`
//! crates (feature `software`, on by default).
//!
//! Signature canonicality (low `s`, `v` of 27 or 28, `r` and `s` in range) is
//! checked here, before the backend is called.
use crate::{Address, Hash};

/// secp256k1 group order `n`, big-endian.
const ORDER: Hash = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// `n / 2`, big-endian. A canonical signature has `s` at most this.
const HALF_ORDER: Hash = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// `Some(recovery bit)` when the 65-byte signature is in the one accepted form.
pub(crate) fn canonical(signature: &[u8; 65]) -> Option<u8> {
    let (r, rest) = signature.split_at(32);
    let (s, v) = rest.split_at(32);
    let v = v.first()?.checked_sub(27).filter(|v| *v <= 1)?;
    let zero = [0u8; 32];
    // Big-endian byte strings of equal length compare like the integers.
    (r != zero.as_slice()
        && r < ORDER.as_slice()
        && s != zero.as_slice()
        && s <= HALF_ORDER.as_slice())
    .then_some(v)
}

#[cfg(feature = "software")]
mod backend {
    use super::{Address, Hash};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    pub fn keccak(bytes: &[u8]) -> Hash {
        Keccak256::digest(bytes).into()
    }
    pub fn recover(digest: &Hash, recovery: u8, rs: &[u8; 64]) -> Option<Address> {
        let signature = Signature::from_slice(rs).ok()?;
        let key = VerifyingKey::recover_from_prehash(
            digest,
            &signature,
            RecoveryId::try_from(recovery).ok()?,
        )
        .ok()?;
        let point = key.to_sec1_point(false);
        let (_, coordinates) = point.as_bytes().split_first()?;
        keccak(coordinates).get(12..)?.try_into().ok()
    }
}

pub(crate) use backend::{keccak, recover};
