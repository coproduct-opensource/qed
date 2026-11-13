//! Identifiers of the A2A-over-iroh binding (docs/specs/a2a-iroh-transport-binding.md)
//! and the Agent Card a seller serves under it.
//!
//! One place for these values: the agents serve the card built here, and the
//! static site prints an example built by the same function.
use serde_json::{Value, json};

/// The A2A protocol version this binding carries (`Major.Minor`).
pub const VERSION: &str = "1.0";

/// Identifier of the transport binding, the `protocolBinding` value
/// (specification §3.1). A2A 1.0 §5.8: a breaking change uses a new URI.
pub const BINDING: &str = "https://coproduct.one/a2a/ext/iroh-binding/v1";

/// Identifier of the per-request proof-of-possession profile (specification §7).
pub const POSSESSION_EXTENSION: &str = "https://coproduct.one/a2a/ext/iroh-possession/v1";

/// Identifier of the extension a deployment's service card carries: where
/// the contracts are and how agents talk to them.
pub const SETTLEMENT_EXTENSION: &str = "https://coproduct.one/a2a/ext/proof-settlement/v1";

/// Identifiers used by binding version 0.1, before the binding had a home.
/// Superseded; listed so a reader of an old card can tell what it was.
pub const SUPERSEDED: [(&str, &str); 3] = [
    ("binding", "urn:uuid:8637676d-c305-4eb3-b2b2-25dbec1c0cda"),
    (
        "possession",
        "urn:uuid:80bced81-d7b8-49a5-9031-a0793c1e5f8d",
    ),
    ("settlement", "urn:x-nucleus-commerce:proof-settlement:v1"),
];

/// The A2A x402 payments extension, v0.2.
pub const X402_EXTENSION: &str =
    "https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2";

/// The ALPN identifier. It names the wire format, which is unchanged since
/// binding version 0.1.
pub const ALPN: &str = "x-a2a-jsonrpc/draft-0.1";

/// The JWS `typ` of a proof under this binding (specification §7.1).
pub const BINDING_TYP: &str = "a2a-iroh-pop+jwt";

/// Media type of the part that carries a work request.
pub const WORK_MEDIA_TYPE: &str = "application/vnd.nucleus.work-request+json";
/// Media type of a delivered artifact (a Lean export continuation).
pub const ARTIFACT_MEDIA_TYPE: &str = "application/x-ndjson";

/// The interface URL of an agent at `node` (64 hex digits), with no hints.
pub fn interface_url(node: &str) -> String {
    format!("iroh://{node}")
}

/// The Agent Card of a seller reachable under this binding at `node`.
pub fn card(node: &str, name: &str, description: &str, version: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "version": version,
        "supportedInterfaces": [{
            "url": interface_url(node),
            "protocolBinding": BINDING,
            "protocolVersion": VERSION,
        }],
        "capabilities": {
            "streaming": true,
            "pushNotifications": false,
            "extendedAgentCard": false,
            "extensions": [
                {
                    "uri": POSSESSION_EXTENSION,
                    "description": "Every request carries a fresh proof of possession (ES256 JWS, typ a2a-iroh-pop+jwt) naming the operation, this interface, the caller's node and the request bytes.",
                    "required": true,
                    "params": {"alg": ["ES256"], "typ": BINDING_TYP, "maximumSkewSeconds": 120},
                },
                {
                    "uri": X402_EXTENSION,
                    "description": "Payment is requested, submitted and receipted with x402 objects in message metadata.",
                    "required": true,
                },
            ],
        },
        "securitySchemes": {
            "node": {"mtlsSecurityScheme": {"description": "The QUIC handshake authenticates both nodes by their public keys (TLS 1.3, raw public keys). The interface URL names the agent's key."}},
        },
        "securityRequirements": [{"schemes": {"node": {"list": []}}}],
        "defaultInputModes": [WORK_MEDIA_TYPE],
        "defaultOutputModes": [ARTIFACT_MEDIA_TYPE],
        "skills": [{
            "id": "lean-proof",
            "name": "Prove a pinned Lean statement",
            "description": "Takes a Lean export ending in a claim and a policy for it; returns a continuation of the export that proves the claim. Payment is released by a contract when a proof of the check verifies.",
            "tags": ["lean", "proof", "x402"],
            "inputModes": [WORK_MEDIA_TYPE],
            "outputModes": [ARTIFACT_MEDIA_TYPE],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_live_under_one_prefix_with_a_version_and_differ() {
        let ids = [BINDING, POSSESSION_EXTENSION, SETTLEMENT_EXTENSION];
        for id in ids {
            assert!(id.starts_with("https://coproduct.one/a2a/ext/"), "{id}");
            assert!(id.ends_with("/v1"), "{id}");
        }
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
        // A renamed identifier is a new identifier: none of the old ones is reused.
        for (_, old) in SUPERSEDED {
            assert!(!ids.contains(&old));
        }
    }

    #[test]
    fn the_card_names_its_node_the_binding_and_requires_the_proof() {
        let node = "ab".repeat(32);
        let card = card(&node, "n", "d", "1");
        let interface = &card["supportedInterfaces"][0];
        assert_eq!(interface["url"], json!(format!("iroh://{node}")));
        assert_eq!(interface["protocolBinding"], json!(BINDING));
        let required: Vec<&str> = card["capabilities"]["extensions"]
            .as_array()
            .map(|e| {
                e.iter()
                    .filter(|e| e["required"] == true)
                    .filter_map(|e| e["uri"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(required, [POSSESSION_EXTENSION, X402_EXTENSION]);
    }
}
