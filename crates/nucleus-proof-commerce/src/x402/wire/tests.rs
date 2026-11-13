use super::*;

#[test]
fn both_sides_compute_the_same_request_hash_and_it_separates_its_parts() {
    let base = request_hash("POST", "https://seller.example/work", b"{}");
    assert_ne!(
        base,
        request_hash("GET", "https://seller.example/work", b"{}")
    );
    assert_ne!(
        base,
        request_hash("POST", "https://seller.example/work2", b"{}")
    );
    assert_ne!(
        base,
        request_hash("POST", "https://seller.example/work", b"{ }")
    );
    assert_ne!(
        request_hash("POST", "ab", b"c"),
        request_hash("POST", "a", b"bc")
    );
}

#[test]
fn hex_and_decimal_fields_have_one_spelling() {
    assert_eq!(unhex::<2>("0x0a1b"), Ok([0x0a, 0x1b]));
    assert_eq!(hex_of(&[0x0a, 0x1b]), "0x0a1b");
    for bad in ["0a1b", "0x0A1b", "0x0a1", "0x0a1b00", "0x0a1g"] {
        assert_eq!(unhex::<2>(bad), Err(Error::Encoding), "{bad}");
    }
    let mut word = [0u8; 32];
    word[29..].copy_from_slice(&[0x0f, 0x42, 0x40]);
    assert_eq!(undecimal("1000000"), Ok(word));
    assert_eq!(decimal_of(word), "1000000");
    assert_eq!(undecimal("0"), Ok([0; 32]));
    for bad in ["01000000", "+1", "-1", "1e6", "", " 1", "0x10"] {
        assert_eq!(undecimal(bad), Err(Error::Encoding), "{bad}");
    }
    assert_eq!(undecimal_u64("1001"), Ok(1001));
    for bad in ["01001", "+1", "18446744073709551616", ""] {
        assert_eq!(undecimal_u64(bad), Err(Error::Encoding), "{bad}");
    }
}

#[test]
fn a_header_must_be_bounded_canonical_base64_of_the_expected_object() {
    let declaration = BuyerDeclaration {
        wallet: hex_of(&[1; 20]),
        key_binding: hex_of(&[2; 32]),
    };
    let header = declaration_header([1; 20], [2; 32]).unwrap();
    assert_eq!(decode::<BuyerDeclaration>(&header), Ok(declaration));
    let engine = base64::engine::general_purpose::STANDARD;
    let with_extra = engine.encode(br#"{"wallet":"0x01","keyBinding":"0x02","memo":"x"}"#);
    assert_eq!(
        decode::<BuyerDeclaration>(&with_extra),
        Err(Error::Malformed)
    );
    assert_eq!(
        decode::<BuyerDeclaration>("not base64 !"),
        Err(Error::Malformed)
    );
    assert_eq!(
        decode::<BuyerDeclaration>(&"A".repeat(40_000)),
        Err(Error::TooLarge)
    );
    let large = serde_json::json!({"wallet": "x".repeat(20_000), "keyBinding": "0x02"});
    assert_eq!(encode(&large), Err(Error::TooLarge));
}

#[test]
fn a_key_binding_is_exactly_a_sha256_thumbprint() {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    assert_eq!(key_binding(&engine.encode([7u8; 32])), Ok([7; 32]));
    assert_eq!(key_binding(&engine.encode([7u8; 31])), Err(Error::Encoding));
    assert_eq!(key_binding("not base64url !"), Err(Error::Encoding));
}
