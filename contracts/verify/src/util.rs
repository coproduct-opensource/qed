//! Hex, hashes, base58 and the IPFS hash solc puts in a contract's metadata.

use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn unhex(s: &str) -> Res<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex ({} digits)", s.len()).into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex at {i}: {e}").into())
        })
        .collect()
}

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A 20-byte address from text, lowercased for comparison.
pub fn address(s: &str) -> Res<[u8; 20]> {
    let bytes = unhex(s)?;
    bytes
        .try_into()
        .map_err(|_| format!("{s} is not a 20-byte address").into())
}

pub fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for _ in 0..zeros {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(ALPHABET[*d as usize] as char);
    }
    out
}

fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The sha2-256 multihash of `content` as a single-block UnixFS file: what
/// solc writes into a contract's CBOR as `ipfs` for its metadata JSON. Only
/// files that fit one 256 KiB block are hashed this way; larger ones are
/// refused rather than hashed wrongly.
pub fn ipfs_multihash(content: &[u8]) -> Res<Vec<u8>> {
    if content.len() > 256 * 1024 {
        return Err("metadata larger than one IPFS block; not hashed".into());
    }
    let mut unixfs = vec![0x08, 0x02, 0x12];
    varint(content.len(), &mut unixfs);
    unixfs.extend_from_slice(content);
    unixfs.push(0x18);
    varint(content.len(), &mut unixfs);
    let mut node = vec![0x0a];
    varint(unixfs.len(), &mut node);
    node.extend_from_slice(&unixfs);
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(&sha256(&node));
    Ok(multihash)
}

/// A 32-byte big-endian word as a decimal string.
pub fn decimal(word: &[u8]) -> String {
    let mut n: Vec<u8> = word.to_vec();
    let mut out = Vec::new();
    while n.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        for b in n.iter_mut() {
            let cur = (rem << 8) | *b as u32;
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        out.push(b'0' + rem as u8);
    }
    if out.is_empty() {
        return "0".into();
    }
    out.reverse();
    String::from_utf8(out).expect("digits")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metadata_hash_is_the_one_solc_put_in_the_committed_board() {
        // fixtures/NucleusBoard.metadata.json is solc 0.8.38's metadata output
        // for contracts/board/src/NucleusBoard.sol with the build's settings;
        // the committed runtime ends with the CBOR solc wrote for it.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let meta = std::fs::read(root.join("fixtures/NucleusBoard.metadata.json")).unwrap();
        let runtime = unhex(
            &std::fs::read_to_string(root.join("../board/out/NucleusBoard.bin-runtime")).unwrap(),
        )
        .unwrap();
        let cbor = crate::evm::metadata(&runtime).expect("metadata");
        let ipfs = cbor.ipfs().expect("ipfs");
        assert_eq!(base58(&ipfs_multihash(&meta).unwrap()), ipfs);
        // One byte changed in the metadata: a different hash.
        let mut changed = meta.clone();
        changed[10] ^= 1;
        assert_ne!(base58(&ipfs_multihash(&changed).unwrap()), ipfs);
    }

    #[test]
    fn decimal_of_words() {
        let mut w = [0u8; 32];
        assert_eq!(decimal(&w), "0");
        w[31] = 0x19;
        assert_eq!(decimal(&w), "25");
        w[29] = 0x27;
        w[30] = 0x8d;
        w[31] = 0x00;
        assert_eq!(decimal(&w), "2592000");
    }
}
