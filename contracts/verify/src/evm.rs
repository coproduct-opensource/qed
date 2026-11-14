//! Bytecode: the CBOR metadata solc appends, an opcode walk that steps over
//! PUSH data, and the runtime comparison with immutables filled in.

use crate::util::{base58, hex};
use std::collections::BTreeMap;

/// The CBOR map solc appends to runtime and creation code, and where it starts.
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    pub start: usize,
    pub entries: Vec<(String, CborValue)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
}

impl Metadata {
    pub fn get(&self, key: &str) -> Option<&CborValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    pub fn ipfs(&self) -> Option<String> {
        match self.get("ipfs") {
            Some(CborValue::Bytes(b)) => Some(base58(b)),
            _ => None,
        }
    }
    pub fn describe(&self) -> String {
        self.entries
            .iter()
            .map(|(k, v)| match v {
                CborValue::Bytes(b) if k == "ipfs" => format!("ipfs {}", base58(b)),
                CborValue::Bytes(b) if k == "solc" && b.len() == 3 => {
                    format!("solc {}.{}.{}", b[0], b[1], b[2])
                }
                CborValue::Bytes(b) => format!("{k} {}", hex(b)),
                CborValue::Text(t) => format!("{k} {t}"),
                CborValue::Bool(x) => format!("{k} {x}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The trailing CBOR map, if the last two bytes give a length that parses as
/// one. Code without it (or with a malformed one) yields `None`.
pub fn metadata(code: &[u8]) -> Option<Metadata> {
    if code.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([code[code.len() - 2], code[code.len() - 1]]) as usize;
    let start = code.len().checked_sub(2 + len)?;
    let cbor = &code[start..code.len() - 2];
    let (entries, used) = cbor_map(cbor)?;
    if used != cbor.len() {
        return None;
    }
    Some(Metadata { start, entries })
}

fn cbor_len(b: &[u8], i: &mut usize, low: u8) -> Option<usize> {
    match low {
        0..=23 => Some(low as usize),
        24 => {
            let v = *b.get(*i)? as usize;
            *i += 1;
            Some(v)
        }
        25 => {
            let v = u16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]) as usize;
            *i += 2;
            Some(v)
        }
        _ => None,
    }
}

fn cbor_map(b: &[u8]) -> Option<(Vec<(String, CborValue)>, usize)> {
    let mut i = 0;
    let head = *b.get(i)?;
    i += 1;
    if head >> 5 != 5 {
        return None;
    }
    let n = cbor_len(b, &mut i, head & 0x1f)?;
    let mut entries = Vec::new();
    for _ in 0..n {
        let kh = *b.get(i)?;
        i += 1;
        if kh >> 5 != 3 {
            return None;
        }
        let kl = cbor_len(b, &mut i, kh & 0x1f)?;
        let key = String::from_utf8(b.get(i..i + kl)?.to_vec()).ok()?;
        i += kl;
        let vh = *b.get(i)?;
        i += 1;
        let value = match vh >> 5 {
            2 => {
                let l = cbor_len(b, &mut i, vh & 0x1f)?;
                let v = b.get(i..i + l)?.to_vec();
                i += l;
                CborValue::Bytes(v)
            }
            3 => {
                let l = cbor_len(b, &mut i, vh & 0x1f)?;
                let v = String::from_utf8(b.get(i..i + l)?.to_vec()).ok()?;
                i += l;
                CborValue::Text(v)
            }
            7 if vh == 0xf4 => CborValue::Bool(false),
            7 if vh == 0xf5 => CborValue::Bool(true),
            _ => return None,
        };
        entries.push((key, value));
    }
    Some((entries, i))
}

pub const DELEGATECALL: u8 = 0xf4;
pub const CALLCODE: u8 = 0xf2;
pub const SELFDESTRUCT: u8 = 0xff;

pub fn opcode_name(op: u8) -> &'static str {
    match op {
        DELEGATECALL => "DELEGATECALL",
        CALLCODE => "CALLCODE",
        SELFDESTRUCT => "SELFDESTRUCT",
        0xf0 => "CREATE",
        0xf5 => "CREATE2",
        _ => "?",
    }
}

/// Every position in `code[..end]` where one of `wanted` is an instruction,
/// walking from 0 and stepping over the immediate data of PUSH1..PUSH32.
/// Solc places code before any data, so the walk is aligned through the
/// code; bytes after the code (data, and the metadata, which callers exclude
/// by `end`) are walked as if they were code, which can only add hits.
pub fn opcode_hits(code: &[u8], end: usize, wanted: &[u8]) -> Vec<(usize, u8)> {
    let end = end.min(code.len());
    let mut hits = Vec::new();
    let mut pc = 0;
    while pc < end {
        let op = code[pc];
        if (0x60..=0x7f).contains(&op) {
            pc += 1 + (op - 0x5f) as usize;
            continue;
        }
        if wanted.contains(&op) {
            hits.push((pc, op));
        }
        pc += 1;
    }
    hits
}

/// One immutable: its name (or `#<AST id>`) and every byte range it fills.
#[derive(Debug, Clone)]
pub struct Immutable {
    pub name: String,
    pub ranges: Vec<(usize, usize)>,
}

#[derive(Debug)]
pub enum RuntimeVerdict {
    /// Every byte equal, the metadata included, once immutables are filled.
    Exact,
    /// Equal outside the trailing metadata only: same code, different
    /// metadata (source text, comments, file names or settings that do not
    /// change code).
    MetadataOnly {
        chain: Option<String>,
        compiled: Option<String>,
    },
    Differs {
        reason: String,
    },
}

pub struct RuntimeComparison {
    pub verdict: RuntimeVerdict,
    /// Immutable name → the value read from the chain's code.
    pub immutables: BTreeMap<String, Vec<u8>>,
}

/// Compare the chain's runtime code with the compiler's, where the compiler
/// left zeros at each immutable's ranges. Each immutable's ranges must hold
/// the same bytes on chain, and every other byte must be equal.
pub fn compare_runtime(
    chain: &[u8],
    compiled: &[u8],
    immutables: &[Immutable],
) -> RuntimeComparison {
    let mut values = BTreeMap::new();
    let differs = |reason: String, values| RuntimeComparison {
        verdict: RuntimeVerdict::Differs { reason },
        immutables: values,
    };
    if chain.len() != compiled.len() {
        return differs(
            format!(
                "length {} on chain, {} compiled",
                chain.len(),
                compiled.len()
            ),
            values,
        );
    }
    let mut mask = vec![false; chain.len()];
    for imm in immutables {
        let mut value: Option<&[u8]> = None;
        for &(start, len) in &imm.ranges {
            let Some(slice) = chain.get(start..start + len) else {
                return differs(
                    format!("immutable {} range out of bounds", imm.name),
                    values,
                );
            };
            if compiled[start..start + len].iter().any(|b| *b != 0) {
                return differs(
                    format!(
                        "compiled code is not zero at immutable {} ({start})",
                        imm.name
                    ),
                    values,
                );
            }
            match value {
                None => value = Some(slice),
                Some(v) if v == slice => {}
                Some(_) => {
                    return differs(
                        format!(
                            "immutable {} holds different values at its references",
                            imm.name
                        ),
                        values,
                    );
                }
            }
            for m in &mut mask[start..start + len] {
                *m = true;
            }
        }
        if let Some(v) = value {
            values.insert(imm.name.clone(), v.to_vec());
        }
    }
    let first = (0..chain.len()).find(|&i| !mask[i] && chain[i] != compiled[i]);
    let Some(first) = first else {
        return RuntimeComparison {
            verdict: RuntimeVerdict::Exact,
            immutables: values,
        };
    };
    let (mc, mo) = (metadata(chain), metadata(compiled));
    if let (Some(a), Some(b)) = (&mc, &mo)
        && a.start == b.start
        && first >= a.start
    {
        return RuntimeComparison {
            verdict: RuntimeVerdict::MetadataOnly {
                chain: a.ipfs(),
                compiled: b.ipfs(),
            },
            immutables: values,
        };
    }
    differs(
        format!(
            "first differing byte at {first}: chain {:02x}, compiled {:02x}",
            chain[first], compiled[first]
        ),
        values,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_walk_flags_delegatecall_and_skips_push_data() {
        // PUSH2 0xf4ff (data, not instructions), then DELEGATECALL, STOP.
        let code = [0x61, 0xf4, 0xff, 0xf4, 0x00];
        let hits = opcode_hits(&code, code.len(), &[DELEGATECALL, SELFDESTRUCT]);
        assert_eq!(hits, vec![(3, DELEGATECALL)]);
        // The same bytes with the opcode removed: nothing.
        let clean = [0x61, 0xf4, 0xff, 0x00];
        assert!(opcode_hits(&clean, clean.len(), &[DELEGATECALL, SELFDESTRUCT]).is_empty());
        // PUSH32 swallows 32 bytes of 0xff.
        let mut p32 = vec![0x7f];
        p32.extend([0xff; 32]);
        p32.push(0xf2);
        assert_eq!(
            opcode_hits(&p32, p32.len(), &[CALLCODE, SELFDESTRUCT]),
            vec![(33, CALLCODE)]
        );
        // A grep would have found three; PUSH0 (0x5f) takes no data.
        let p0 = [0x5f, 0xff];
        assert_eq!(
            opcode_hits(&p0, 2, &[SELFDESTRUCT]),
            vec![(1, SELFDESTRUCT)]
        );
    }

    fn with_metadata(code: &[u8], ipfs_byte: u8) -> Vec<u8> {
        let mut c = code.to_vec();
        let mut cbor = vec![0xa2, 0x64];
        cbor.extend(b"ipfs");
        cbor.push(0x58);
        cbor.push(34);
        cbor.extend([0x12, 0x20]);
        cbor.extend([ipfs_byte; 32]);
        cbor.push(0x64);
        cbor.extend(b"solc");
        cbor.extend([0x43, 0, 8, 38]);
        let n = cbor.len() as u16;
        c.extend(cbor);
        c.extend(n.to_be_bytes());
        c
    }

    #[test]
    fn metadata_parses_and_classifies() {
        let a = with_metadata(&[0x60, 0x00, 0x00], 1);
        let m = metadata(&a).unwrap();
        assert_eq!(m.start, 3);
        assert!(m.describe().ends_with("solc 0.8.38"));
        let b = with_metadata(&[0x60, 0x00, 0x00], 2);
        assert!(matches!(
            compare_runtime(&a, &a, &[]).verdict,
            RuntimeVerdict::Exact
        ));
        assert!(matches!(
            compare_runtime(&a, &b, &[]).verdict,
            RuntimeVerdict::MetadataOnly { .. }
        ));
        let c = with_metadata(&[0x60, 0x01, 0x00], 1);
        assert!(matches!(
            compare_runtime(&a, &c, &[]).verdict,
            RuntimeVerdict::Differs { .. }
        ));
    }

    #[test]
    fn immutables_fill_and_must_agree() {
        let compiled = [0x60, 0, 0, 0x60, 0, 0];
        let imm = [Immutable {
            name: "x".into(),
            ranges: vec![(1, 2), (4, 2)],
        }];
        let chain = [0x60, 0xab, 0xcd, 0x60, 0xab, 0xcd];
        let r = compare_runtime(&chain, &compiled, &imm);
        assert!(matches!(r.verdict, RuntimeVerdict::Exact));
        assert_eq!(r.immutables["x"], vec![0xab, 0xcd]);
        let split = [0x60, 0xab, 0xcd, 0x60, 0xab, 0xce];
        assert!(matches!(
            compare_runtime(&split, &compiled, &imm).verdict,
            RuntimeVerdict::Differs { .. }
        ));
        // Without the immutable declared, the same chain code differs.
        assert!(matches!(
            compare_runtime(&chain, &compiled, &[]).verdict,
            RuntimeVerdict::Differs { .. }
        ));
    }
}
