//! Signing the A2A Agent Card, per A2A 1.0.1 §8.4: remove default-valued
//! fields (§8.4.1 rule 1), exclude `signatures`, canonicalize with the JSON
//! Canonicalization Scheme (RFC 8785), and sign the JWS signing input
//! (RFC 7515) with ES256. The protected header carries `alg`, `typ`
//! (`JOSE`), `kid` (the key's RFC 7638 thumbprint) and `jku` (where the
//! JWKS is served).
//!
//! The same canonical form is used for the receipts the site serves.
use crate::Res;
use base64::Engine;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Largest integer RFC 8785 serializes exactly (IEEE 754 double).
const MAX_SAFE: u64 = (1 << 53) - 1;

fn jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn jcs_into(value: &Value, out: &mut String) -> Res<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Only integers this generator writes; a float or an integer a
            // double cannot hold exactly is refused rather than rounded.
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE {
                    return Err(format!("integer {u} is beyond 2^53 - 1").into());
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE {
                    return Err(format!("integer {i} is beyond 2^53 - 1").into());
                }
                out.push_str(&i.to_string());
            } else {
                return Err(format!("non-integer number {n} in a canonical object").into());
            }
        }
        Value::String(s) => jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                jcs_into(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: sort by the keys' UTF-16 code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (n, key) in keys.into_iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                jcs_string(key, out);
                out.push(':');
                jcs_into(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 canonical JSON.
pub fn jcs(value: &Value) -> Res<String> {
    let mut out = String::new();
    jcs_into(value, &mut out)?;
    Ok(out)
}

/// A2A 1.0.1 §8.4.1 rule 1, for the fields this generator writes:
/// `AgentExtension.required` is a plain `bool`, so `false` is its default
/// and is omitted; a repeated field that is not REQUIRED is omitted when
/// empty. `streaming` and `pushNotifications` are `optional` and are kept
/// when present.
pub fn strip_defaults(card: &Value) -> Value {
    let mut card = card.clone();
    if let Some(map) = card.as_object_mut() {
        map.remove("signatures");
        for key in ["securityRequirements", "securitySchemes"] {
            let empty = map.get(key).is_some_and(|v| {
                v.as_array().is_some_and(Vec::is_empty) || v.as_object().is_some_and(Map::is_empty)
            });
            if empty {
                map.remove(key);
            }
        }
        if let Some(caps) = map.get_mut("capabilities").and_then(Value::as_object_mut) {
            if caps
                .get("extensions")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            {
                caps.remove("extensions");
            }
            if let Some(exts) = caps.get_mut("extensions").and_then(Value::as_array_mut) {
                for ext in exts {
                    if let Some(ext) = ext.as_object_mut()
                        && ext.get("required") == Some(&Value::Bool(false))
                    {
                        ext.remove("required");
                    }
                }
            }
        }
        if let Some(skills) = map.get_mut("skills").and_then(Value::as_array_mut) {
            for skill in skills {
                if let Some(skill) = skill.as_object_mut() {
                    for key in [
                        "examples",
                        "inputModes",
                        "outputModes",
                        "securityRequirements",
                    ] {
                        if skill
                            .get(key)
                            .and_then(Value::as_array)
                            .is_some_and(Vec::is_empty)
                        {
                            skill.remove(key);
                        }
                    }
                }
            }
        }
    }
    card
}

/// The card-signing key: 32 bytes of P-256 scalar as hex, one line.
pub fn load_key(path: &Path) -> Res<SigningKey> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes = crate::unhex(text.trim())?;
    Ok(SigningKey::from_slice(&bytes).map_err(|_| "not a P-256 private scalar")?)
}

/// Create a new key file, readable by its owner only. Refuses to overwrite.
pub fn create_key(path: &Path) -> Res<()> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let mut seed = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let key = SigningKey::from_slice(&seed).map_err(|_| "random bytes were not a valid scalar")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(format!("{}\n", crate::hex(&key.to_bytes())).as_bytes())?;
    Ok(())
}

fn coordinates(key: &VerifyingKey) -> (String, String) {
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    (B64URL.encode(&bytes[1..33]), B64URL.encode(&bytes[33..65]))
}

/// RFC 7638 thumbprint of the public key, used as `kid`.
pub fn thumbprint(key: &VerifyingKey) -> String {
    let (x, y) = coordinates(key);
    let members = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    B64URL.encode(Sha256::digest(members.as_bytes()))
}

/// The JWKS served at `/.well-known/jwks.json`.
pub fn jwks(key: &VerifyingKey) -> Value {
    let (x, y) = coordinates(key);
    json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "kid": thumbprint(key), "use": "sig", "alg": "ES256",
    }]})
}

/// The bytes signed for a card: the canonical form of the card with its
/// defaults removed and without `signatures`.
pub fn payload(card: &Value) -> Res<String> {
    jcs(&strip_defaults(card))
}

/// Add one `signatures` entry to `card`.
pub fn sign(card: &Value, key: &SigningKey, jku: &str) -> Res<Value> {
    let verifying = key.verifying_key();
    let header = json!({ "alg": "ES256", "typ": "JOSE", "kid": thumbprint(verifying), "jku": jku });
    let protected = B64URL.encode(jcs(&header)?);
    let input = format!("{protected}.{}", B64URL.encode(payload(card)?));
    let signature: Signature = key.sign(input.as_bytes());
    let mut signed = card.clone();
    signed["signatures"] = json!([{
        "protected": protected,
        "signature": B64URL.encode(signature.to_bytes()),
    }]);
    Ok(signed)
}

/// Check a card's first signature against a JWKS: §8.4.3 steps 1 to 6.
/// Returns the `kid` that verified.
pub fn verify(card: &Value, jwks: &Value) -> Res<String> {
    let entry = card["signatures"]
        .as_array()
        .and_then(|s| s.first())
        .ok_or("the card carries no signature")?;
    let protected = entry["protected"].as_str().ok_or("no protected header")?;
    let header: Value = serde_json::from_slice(&B64URL.decode(protected)?)?;
    if header["alg"] != "ES256" {
        return Err(format!("alg {} is not ES256", header["alg"]).into());
    }
    let kid = header["kid"].as_str().ok_or("no kid")?;
    let jwk = jwks["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["kid"] == kid))
        .ok_or("no key with that kid in the JWKS")?;
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err("the JWKS key is not an EC P-256 key".into());
    }
    let x = B64URL.decode(jwk["x"].as_str().ok_or("x")?)?;
    let y = B64URL.decode(jwk["y"].as_str().ok_or("y")?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("key coordinates are not 32 bytes".into());
    }
    let mut point = vec![4u8];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| "not a point on P-256")?;
    if thumbprint(&key) != kid {
        return Err("the key's thumbprint is not its kid".into());
    }
    let signature =
        Signature::from_slice(&B64URL.decode(entry["signature"].as_str().ok_or("no signature")?)?)
            .map_err(|_| "signature is not 64 bytes of r and s")?;
    let input = format!("{protected}.{}", B64URL.encode(payload(card)?));
    key.verify(input.as_bytes(), &signature)
        .map_err(|_| "the signature does not verify")?;
    Ok(kid.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn jcs_sorts_keys_and_escapes_as_rfc_8785_says() {
        let v = json!({"b": [1, "\u{1}\n\"é"], "a": {"d": true, "c": null}});
        assert_eq!(
            jcs(&v).unwrap(),
            "{\"a\":{\"c\":null,\"d\":true},\"b\":[1,\"\\u0001\\n\\\"é\"]}"
        );
        assert!(jcs(&json!({"x": 1.5})).is_err());
        assert!(jcs(&json!({"x": 1u64 << 60})).is_err());
    }

    /// RFC 8785 §3.2.3 example of UTF-16 key ordering.
    #[test]
    fn jcs_orders_keys_by_utf16_code_units() {
        let v = json!({"\u{20ac}": 1, "\r": 2, "\u{fb33}": 3, "1": 4, "\u{1f600}": 5, "\u{80}": 6, "\u{f6}": 7});
        let s = jcs(&v).unwrap();
        let order: Vec<usize> = [
            "\\r",
            "\"1\"",
            "\u{80}",
            "\u{f6}",
            "\u{20ac}",
            "\u{1f600}",
            "\u{fb33}",
        ]
        .iter()
        .map(|k| s.find(k).unwrap())
        .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{s}");
    }

    #[test]
    fn a_signed_card_verifies_and_a_changed_one_does_not() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let card = json!({"name": "x", "capabilities": {"extensions": [{"uri": "u", "required": false}]}, "skills": []});
        let signed = sign(&card, &key, "https://example.test/.well-known/jwks.json").unwrap();
        let keys = jwks(key.verifying_key());
        assert_eq!(
            verify(&signed, &keys).unwrap(),
            thumbprint(key.verifying_key())
        );
        let mut changed = signed.clone();
        changed["name"] = json!("y");
        assert!(verify(&changed, &keys).is_err());
        // Removing a default-valued field does not change what was signed.
        let mut same = signed.clone();
        same["capabilities"]["extensions"][0]
            .as_object_mut()
            .unwrap()
            .remove("required");
        assert!(verify(&same, &keys).is_ok());
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        assert!(verify(&signed, &jwks(other.verifying_key())).is_err());
    }
}
