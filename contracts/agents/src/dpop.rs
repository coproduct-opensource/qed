//! Proof of possession on every request between the agents (RFC 9449 shape,
//! ES256), over iroh and over HTTP.
use crate::prelude::*;
use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Signer, Verifier},
};
use std::collections::HashSet;

pub fn dpop_coordinates(key: &p256::ecdsa::SigningKey) -> ([u8; 32], [u8; 32]) {
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    (
        bytes[1..33].try_into().expect("x"),
        bytes[33..65].try_into().expect("y"),
    )
}
pub fn dpop_binding_of(key: &p256::ecdsa::SigningKey) -> [u8; 32] {
    let (x, y) = dpop_coordinates(key);
    key_binding(&x, &y)
}

/// RFC 7638 thumbprint of the key: SHA-256 of the required members in
/// lexicographic order with no whitespace.
pub fn key_binding(key_x: &[u8; 32], key_y: &[u8; 32]) -> [u8; 32] {
    let jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        B64URL.encode(key_x),
        B64URL.encode(key_y)
    );
    Sha256::digest(jwk.as_bytes()).into()
}

/// ES256 verification of `message` under the key with these coordinates.
pub fn verify_es256(
    key_x: &[u8; 32],
    key_y: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Res<()> {
    let mut point = [4u8; 65];
    point[1..33].copy_from_slice(key_x);
    point[33..].copy_from_slice(key_y);
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| "key refused")?;
    let signature = Signature::from_slice(signature).map_err(|_| "signature malformed")?;
    key.verify(message, &signature)
        .map_err(|_| "signature refused".into())
}

/// A fresh proof for this method and URI. `node`, when given, is the caller's
/// iroh node ID: the receiver compares it with the node the transport
/// authenticated, so a proof lifted off one connection is refused on another.
pub fn dpop_make(
    key: &p256::ecdsa::SigningKey,
    method: &str,
    uri: &str,
    now: u64,
    node: Option<&str>,
) -> Res<String> {
    proof_make(key, DPOP_TYP, method, uri, now, node, None)
}

/// The JWS `typ` of an RFC 9449 proof.
pub const DPOP_TYP: &str = "dpop+jwt";
/// The JWS `typ` of a proof under the A2A-over-iroh binding
/// (docs/specs/a2a-iroh-transport-binding.md §7). Same shape and the same
/// verifier as a DPoP proof; a different `typ`, so neither is accepted as the
/// other, and it also names the SHA-256 of the request it travels with.
pub const BINDING_TYP: &str = nucleus_a2a_iroh_card::BINDING_TYP;

/// A fresh proof of the given type. `request`, when given, is the exact bytes
/// of the request the proof travels with; the proof names their SHA-256.
pub fn proof_make(
    key: &p256::ecdsa::SigningKey,
    typ: &str,
    method: &str,
    uri: &str,
    now: u64,
    node: Option<&str>,
    request: Option<&[u8]>,
) -> Res<String> {
    let (x, y) = dpop_coordinates(key);
    let header = json!({"typ": typ, "alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": B64URL.encode(x), "y": B64URL.encode(y)}});
    let mut claims = json!({"jti": hex(&random32()?), "htm": method, "htu": uri, "iat": now});
    if let Some(node) = node {
        claims["nid"] = json!(node);
    }
    if let Some(request) = request {
        claims["rqh"] = json!(B64URL.encode(Sha256::digest(request)));
    }
    let signing = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header)?),
        B64URL.encode(serde_json::to_vec(&claims)?)
    );
    let signature: p256::ecdsa::Signature = key.sign(signing.as_bytes());
    Ok(format!("{signing}.{}", B64URL.encode(signature.to_bytes())))
}
/// What a verified proof establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proved {
    /// RFC 7638 thumbprint of the key that signed, unpadded base64url.
    pub thumbprint: String,
    /// The node ID the proof says it was made for use from, if it says.
    pub node: Option<String>,
}

/// Verify a DPoP proof for this method and URI.
/// Replay protection here is an in-memory set: it forgets on restart.
pub fn dpop_check(
    proof: &str,
    method: &str,
    uri: &str,
    now: u64,
    seen: &mut HashSet<String>,
) -> Res<Proved> {
    proof_check(proof, DPOP_TYP, method, uri, None, now, seen)
}

/// Verify a proof of the given type for this method and URI. When `request`
/// is given the proof must name the SHA-256 of exactly those bytes. One
/// verifier for every adapter: only the names a proof must carry differ.
pub fn proof_check(
    proof: &str,
    typ: &str,
    method: &str,
    uri: &str,
    request: Option<&[u8]>,
    now: u64,
    seen: &mut HashSet<String>,
) -> Res<Proved> {
    let mut parts = proof.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("DPoP proof is not three parts".into());
    };
    let header_json: Value = serde_json::from_slice(&B64URL.decode(header)?)?;
    let claims_json: Value = serde_json::from_slice(&B64URL.decode(claims)?)?;
    if header_json["typ"] != typ || header_json["alg"] != "ES256" {
        return Err("DPoP header refused".into());
    }
    let coordinate = |name: &str| -> Res<[u8; 32]> {
        B64URL
            .decode(
                header_json["jwk"][name]
                    .as_str()
                    .ok_or("jwk coordinate missing")?,
            )?
            .try_into()
            .map_err(|_| "jwk coordinate length".into())
    };
    if header_json["jwk"]["kty"] != "EC" || header_json["jwk"]["crv"] != "P-256" {
        return Err("DPoP key type refused".into());
    }
    let (x, y) = (coordinate("x")?, coordinate("y")?);
    let signature: [u8; 64] = B64URL
        .decode(signature)?
        .try_into()
        .map_err(|_| "DPoP signature length")?;
    verify_es256(&x, &y, format!("{header}.{claims}").as_bytes(), &signature)
        .map_err(|_| "DPoP signature refused")?;
    if claims_json["htm"] != method || claims_json["htu"] != uri {
        return Err("DPoP proof is for another method or URI".into());
    }
    if let Some(request) = request
        && claims_json["rqh"] != json!(B64URL.encode(Sha256::digest(request)))
    {
        return Err("proof is for another request body".into());
    }
    let issued = claims_json["iat"].as_u64().ok_or("DPoP iat missing")?;
    if issued.abs_diff(now) > 120 {
        return Err("DPoP proof is stale".into());
    }
    let jti = claims_json["jti"]
        .as_str()
        .ok_or("DPoP jti missing")?
        .to_owned();
    if !seen.insert(jti) {
        return Err("DPoP proof replayed".into());
    }
    Ok(Proved {
        thumbprint: B64URL.encode(key_binding(&x, &y)),
        node: claims_json["nid"].as_str().map(str::to_owned),
    })
}

/// Proof of possession for exactly this request, bound to the node the
/// transport authenticated when it authenticated one. Returns the key's
/// thumbprint as 32 bytes, or the status and reason to refuse with.
///
/// Used by whoever answers requests: the seller's harness and the buyer's
/// desk run the same check.
pub fn authenticate(
    via: &crate::message::Via,
    request: &crate::message::Request,
    now: u64,
    seen: &mut HashSet<String>,
) -> Result<[u8; 32], (u16, String)> {
    // An adapter whose proof names something other than this request's own
    // method and path has verified it already (`possession`).
    if let Some(owner) = via.owner {
        return Ok(owner);
    }
    let Some(proof) = request.headers.get("dpop") else {
        return Err((401, "DPoP proof missing".to_owned()));
    };
    let uri = format!("{}{}", via.base, request.path);
    let proved = dpop_check(proof, &request.method, &uri, now, seen)
        .map_err(|error| (401, error.to_string()))?;
    bound(via.peer.as_deref(), &proved).map_err(|why| (401, why))
}

/// The thumbprint a verified proof establishes, once the proof is bound to
/// the node the transport authenticated (when it authenticated one).
fn bound(peer: Option<&str>, proved: &Proved) -> Result<[u8; 32], String> {
    match (peer, &proved.node) {
        (Some(peer), Some(node)) if peer == node => {}
        (Some(_), _) => {
            return Err("DPoP proof is not bound to this connection's node".to_owned());
        }
        // Plain HTTP authenticates no node, so there is nothing to bind to.
        (None, _) => {}
    }
    B64URL
        .decode(&proved.thumbprint)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "thumbprint length".to_owned())
}

/// Proof of possession under a binding that names its own operation and
/// target (the A2A-over-iroh binding): the same verifier and the same node
/// binding as `authenticate`, with the proof also naming the request bytes.
/// `peer` is the node the transport authenticated; it is required.
pub fn possession(
    peer: &str,
    proof: &str,
    method: &str,
    target: &str,
    request: &[u8],
    now: u64,
    seen: &mut HashSet<String>,
) -> Result<[u8; 32], String> {
    let proved = proof_check(proof, BINDING_TYP, method, target, Some(request), now, seen)
        .map_err(|error| error.to_string())?;
    bound(Some(peer), &proved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid test key")
    }
    fn refusal(result: Res<Proved>) -> String {
        result.expect_err("must be refused").to_string()
    }

    #[test]
    fn es256_verification_accepts_the_rfc_7515_appendix_a3_example() {
        // Independent vector: https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3
        let coordinate =
            |text: &str| -> [u8; 32] { B64URL.decode(text).unwrap().try_into().unwrap() };
        let x = coordinate("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        let y = coordinate("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        let message = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let signature: [u8; 64] = B64URL
            .decode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_es256(&x, &y, message.as_bytes(), &signature).is_ok());
        let other = format!("{message}A");
        assert!(verify_es256(&x, &y, other.as_bytes(), &signature).is_err());
        // SHA-256 of the canonical JWK text for this key, computed with shasum.
        assert_eq!(
            hex(&key_binding(&x, &y)),
            "0xa0a232c2f194a53553cb1310ddbc0821e414b9d7ebfc290b323084d7d1020fe5"
        );
    }

    #[test]
    fn a_fresh_proof_is_accepted_once_and_names_its_key() {
        let mut seen = HashSet::new();
        let proof = dpop_make(&key(7), "POST", "http://seller/work", 1000, None).unwrap();
        let thumbprint = dpop_check(&proof, "POST", "http://seller/work", 1000, &mut seen)
            .unwrap()
            .thumbprint;
        assert_eq!(thumbprint, B64URL.encode(dpop_binding_of(&key(7))));
        assert_ne!(thumbprint, B64URL.encode(dpop_binding_of(&key(8))));
        assert_eq!(
            refusal(dpop_check(
                &proof,
                "POST",
                "http://seller/work",
                1000,
                &mut seen
            )),
            "DPoP proof replayed"
        );
    }

    #[test]
    fn a_proof_for_another_method_uri_or_time_is_refused() {
        let proof = dpop_make(&key(7), "POST", "http://seller/work", 1000, None).unwrap();
        for (method, uri, now, expected) in [
            (
                "GET",
                "http://seller/work",
                1000,
                "DPoP proof is for another method or URI",
            ),
            (
                "POST",
                "http://seller/other",
                1000,
                "DPoP proof is for another method or URI",
            ),
            ("POST", "http://seller/work", 1121, "DPoP proof is stale"),
            ("POST", "http://seller/work", 879, "DPoP proof is stale"),
        ] {
            assert_eq!(
                refusal(dpop_check(&proof, method, uri, now, &mut HashSet::new())),
                expected
            );
        }
    }

    #[test]
    fn a_proof_signed_by_a_key_other_than_the_one_it_presents_is_refused() {
        let mine = dpop_make(&key(7), "POST", "http://seller/work", 1000, None).unwrap();
        let theirs = dpop_make(&key(8), "POST", "http://seller/work", 1000, None).unwrap();
        let part = |proof: &str, n: usize| proof.split('.').nth(n).unwrap().to_owned();
        // Their header (and so their key), my claims and my signature.
        let spliced = format!("{}.{}.{}", part(&theirs, 0), part(&mine, 1), part(&mine, 2));
        assert_eq!(
            refusal(dpop_check(
                &spliced,
                "POST",
                "http://seller/work",
                1000,
                &mut HashSet::new()
            )),
            "DPoP signature refused"
        );
        // Altered claims under my signature.
        let claims =
            B64URL.encode(br#"{"jti":"x","htm":"POST","htu":"http://seller/work","iat":1000}"#);
        let altered = format!("{}.{claims}.{}", part(&mine, 0), part(&mine, 2));
        assert_eq!(
            refusal(dpop_check(
                &altered,
                "POST",
                "http://seller/work",
                1000,
                &mut HashSet::new()
            )),
            "DPoP signature refused"
        );
        assert_eq!(
            refusal(dpop_check(
                "only.two",
                "POST",
                "http://seller/work",
                1000,
                &mut HashSet::new()
            )),
            "DPoP proof is not three parts"
        );
    }
}
