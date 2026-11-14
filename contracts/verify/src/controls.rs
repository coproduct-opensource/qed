//! Upgrade and administrative controls, checked against the chain: proxy
//! storage slots, opcodes that run or remove other code, administrative
//! function names in the ABI, and calls to the usual administrative getters.

use crate::evm::{CALLCODE, DELEGATECALL, SELFDESTRUCT, metadata, opcode_hits, opcode_name};
use crate::rpc::{Probe, Rpc};
use crate::util::{Res, hex};
use serde_json::Value;

/// (name, slot). EIP-1967's three, the EIP-1822 slot, and the zeppelinos one.
pub const SLOTS: [(&str, &str); 5] = [
    (
        "EIP-1967 implementation",
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    ),
    (
        "EIP-1967 admin",
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    ),
    (
        "EIP-1967 beacon",
        "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    ),
    (
        "EIP-1822 proxiable",
        "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",
    ),
    (
        "zeppelinos implementation",
        "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
    ),
];

/// Getters an owned, pausable or upgradeable contract answers: (signature, selector).
pub const PROBES: [(&str, [u8; 4]); 5] = [
    ("owner()", [0x8d, 0xa5, 0xcb, 0x5b]),
    ("pendingOwner()", [0xe3, 0x0c, 0x39, 0x78]),
    ("paused()", [0x5c, 0x97, 0x5a, 0xbb]),
    ("implementation()", [0x5c, 0x60, 0xda, 0x1b]),
    ("admin()", [0xf8, 0x51, 0xa4, 0x40]),
];

const EXACT: [&str; 6] = [
    "owner",
    "pendingowner",
    "admin",
    "implementation",
    "proxiableuuid",
    "kill",
];
/// `set` counts only as `setX` or `set_x`: a bare prefix match flagged the
/// vault's `settle` (found by this module's test).
fn is_setter(name: &str) -> bool {
    name.strip_prefix("set")
        .and_then(|r| r.chars().next())
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
}

const PREFIXES: [&str; 13] = [
    "upgrade",
    "pause",
    "unpause",
    "transferownership",
    "renounce",
    "acceptownership",
    "grantrole",
    "revokerole",
    "changeadmin",
    "initialize",
    "reinitialize",
    "destroy",
    "selfdestruct",
];

/// ABI function names that look administrative. A name is a convention, not
/// a mechanism: this list says what the ABI does not offer under the usual
/// names, and the opcode and slot checks say what the code cannot do.
pub fn administrative_names(abi: &Value) -> Vec<String> {
    abi.as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["type"] == "function")
        .filter_map(|e| e["name"].as_str())
        .filter(|n| {
            let l = n.to_ascii_lowercase();
            is_setter(n) || EXACT.contains(&l.as_str()) || PREFIXES.iter().any(|p| l.starts_with(p))
        })
        .map(str::to_string)
        .collect()
}

pub fn function_names(abi: &Value) -> Vec<String> {
    abi.as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["type"] == "function")
        .filter_map(|e| e["name"].as_str().map(str::to_string))
        .collect()
}

pub fn has_fallback(abi: &Value) -> bool {
    abi.as_array()
        .into_iter()
        .flatten()
        .any(|e| e["type"] == "fallback" || e["type"] == "receive")
}

/// The code's opcode hits, excluding the trailing metadata.
pub fn dangerous_opcodes(code: &[u8]) -> Vec<(usize, &'static str)> {
    let end = metadata(code).map(|m| m.start).unwrap_or(code.len());
    opcode_hits(code, end, &[DELEGATECALL, CALLCODE, SELFDESTRUCT])
        .into_iter()
        .map(|(pc, op)| (pc, opcode_name(op)))
        .collect()
}

pub struct Control {
    pub what: String,
    pub ok: bool,
    pub detail: String,
}

pub fn check(rpc: &Rpc, address: &str, code: &[u8], abi: Option<&Value>) -> Res<Vec<Control>> {
    let mut out = Vec::new();
    for (name, slot) in SLOTS {
        let value = rpc.storage(address, slot)?;
        let empty = value.iter().all(|b| *b == 0);
        out.push(Control {
            what: format!("{name} slot"),
            ok: empty,
            detail: if empty { "empty".into() } else { hex(&value) },
        });
    }
    let hits = dangerous_opcodes(code);
    out.push(Control {
        what: "DELEGATECALL, CALLCODE, SELFDESTRUCT in runtime code".into(),
        ok: hits.is_empty(),
        detail: if hits.is_empty() {
            "none (opcode walk over the code before the metadata, PUSH data skipped)".into()
        } else {
            hits.iter()
                .map(|(pc, n)| format!("{n} at {pc}"))
                .collect::<Vec<_>>()
                .join(", ")
        },
    });
    if let Some(abi) = abi {
        let admin = administrative_names(abi);
        out.push(Control {
            what: "administrative function names in the ABI".into(),
            ok: admin.is_empty(),
            detail: if admin.is_empty() {
                format!("none among {}", function_names(abi).join(", "))
            } else {
                admin.join(", ")
            },
        });
        out.push(Control {
            what: "fallback or receive function".into(),
            ok: !has_fallback(abi),
            detail: if has_fallback(abi) {
                "present".into()
            } else {
                "none".into()
            },
        });
    }
    for (sig, sel) in PROBES {
        let (ok, detail) = match rpc.probe(address, &sel)? {
            Probe::Reverted => (true, "reverts".to_string()),
            Probe::Returned(b) if b.is_empty() => (true, "returns nothing".to_string()),
            Probe::Returned(b) => (false, format!("returns {}", hex(&b))),
        };
        out.push(Control {
            what: format!("call {sig}"),
            ok,
            detail,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_delegatecall_fixture_is_flagged_and_metadata_is_not_walked() {
        // PUSH1 0, DELEGATECALL, STOP, then a metadata tail whose bytes include 0xff.
        let mut code = vec![0x60, 0x00, 0xf4, 0x00];
        let cbor = [0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0xff, 0xff, 0xff];
        code.extend(cbor);
        code.extend((cbor.len() as u16).to_be_bytes());
        assert_eq!(dangerous_opcodes(&code), vec![(2, "DELEGATECALL")]);
        code[2] = 0x00;
        assert!(dangerous_opcodes(&code).is_empty());
    }

    #[test]
    fn administrative_names_are_found() {
        let abi = json!([
            {"type": "function", "name": "settle"},
            {"type": "function", "name": "owner"},
            {"type": "function", "name": "upgradeToAndCall"},
            {"type": "function", "name": "setVerifier"},
            {"type": "function", "name": "paused"},
            {"type": "constructor"}
        ]);
        assert_eq!(
            administrative_names(&abi),
            vec!["owner", "upgradeToAndCall", "setVerifier", "paused"]
        );
        let clean = json!([
            {"type": "function", "name": "settle"},
            {"type": "function", "name": "setup"},
            {"type": "function", "name": "withdraw"}
        ]);
        assert!(administrative_names(&clean).is_empty());
    }
}
