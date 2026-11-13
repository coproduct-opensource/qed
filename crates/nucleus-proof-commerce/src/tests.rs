use super::*;
use crate::tests_support::sign;
use k256::ecdsa::{Signature, SigningKey};

fn bytes<const N: usize>(hexadecimal: &str) -> [u8; N] {
    hex::decode(hexadecimal).unwrap().try_into().unwrap()
}

#[test]
fn recovers_the_official_eip712_mail_example() {
    // Primary external vector: https://eips.ethereum.org/EIPS/eip-712#example
    // This is not a round trip through our own signer.
    let person = |name: &str, address_hex: &str| {
        words([
            hash(b"Person(string name,address wallet)"),
            hash(name.as_bytes()),
            address(bytes(address_hex)),
        ])
    };
    let message = words([
        hash(b"Mail(Person from,Person to,string contents)Person(string name,address wallet)"),
        person("Cow", "CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"),
        person("Bob", "bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
        hash(b"Hello, Bob!"),
    ]);
    let digest = typed_digest(
        domain(
            "Ether Mail",
            "1",
            1,
            bytes("CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
        ),
        message,
    );
    let signature = WalletSignature(bytes(
        "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c",
    ));
    assert_eq!(
        recover(digest, &signature).unwrap(),
        bytes("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")
    );
}

#[test]
fn noncanonical_signature_representations_are_refused() {
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let digest = hash(b"any 32-byte digest");
    let signature = sign(&key, digest);
    assert!(recover(digest, &signature).is_ok());
    let parsed = Signature::from_slice(&signature.0[..64]).unwrap();
    let (r, s) = parsed.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    let mut altered = signature.0;
    altered[..64].copy_from_slice(&high.to_bytes());
    assert_eq!(
        recover(digest, &WalletSignature(altered)).err(),
        Some(Error::InvalidSignature)
    );
    let mut altered = signature.0;
    altered[64] = 0;
    assert_eq!(
        recover(digest, &WalletSignature(altered)).err(),
        Some(Error::InvalidSignature)
    );
}
