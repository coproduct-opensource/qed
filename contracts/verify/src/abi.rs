//! Constructor arguments: decode the ABI encoding of static types, and refuse
//! any encoding that is not the canonical one for the decoded values.

use crate::util::{Res, decimal, hex};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Arg {
    pub name: String,
    pub ty: String,
    /// Canonical text: lowercase 0x-hex for address and bytesN, decimal for
    /// integers, true/false for bool.
    pub value: String,
}

/// The constructor's inputs from an ABI, as (name, type).
pub fn constructor_inputs(abi: &Value) -> Vec<(String, String)> {
    abi.as_array()
        .into_iter()
        .flatten()
        .find(|e| e["type"] == "constructor")
        .and_then(|c| c["inputs"].as_array())
        .map(|inputs| {
            inputs
                .iter()
                .map(|i| {
                    (
                        i["name"].as_str().unwrap_or("").to_string(),
                        i["type"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn decode(inputs: &[(String, String)], data: &[u8]) -> Res<Vec<Arg>> {
    if data.len() != 32 * inputs.len() {
        return Err(format!(
            "constructor arguments are {} bytes; {} static arguments take {}",
            data.len(),
            inputs.len(),
            32 * inputs.len()
        )
        .into());
    }
    inputs
        .iter()
        .zip(data.chunks(32))
        .map(|((name, ty), word)| {
            Ok(Arg {
                name: name.clone(),
                ty: ty.clone(),
                value: word_value(ty, word).map_err(|e| format!("{name} ({ty}): {e}"))?,
            })
        })
        .collect()
}

fn word_value(ty: &str, w: &[u8]) -> Res<String> {
    let zero = |r: std::ops::Range<usize>| w[r].iter().all(|b| *b == 0);
    if ty == "address" {
        if !zero(0..12) {
            return Err("high bytes not zero".into());
        }
        return Ok(hex(&w[12..]));
    }
    if ty == "bool" {
        return match (zero(0..31), w[31]) {
            (true, 0) => Ok("false".into()),
            (true, 1) => Ok("true".into()),
            _ => Err("not 0 or 1".into()),
        };
    }
    if let Some(bits) = ty.strip_prefix("uint") {
        let bits: usize = if bits.is_empty() { 256 } else { bits.parse()? };
        if !zero(0..32 - bits / 8) {
            return Err(format!("does not fit in {bits} bits").into());
        }
        return Ok(decimal(w));
    }
    if let Some(n) = ty.strip_prefix("bytes")
        && !n.is_empty()
    {
        let n: usize = n.parse()?;
        if n == 0 || n > 32 || !zero(n..32) {
            return Err("not a left-aligned bytesN".into());
        }
        return Ok(hex(&w[..n]));
    }
    Err(format!("type {ty} is not decoded by this tool").into())
}

/// Normalise an expected value for comparison with `Arg::value`.
pub fn normalise(ty: &str, value: &str) -> String {
    if ty == "address" || ty.starts_with("bytes") {
        value.trim().to_ascii_lowercase()
    } else {
        value.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_refuses_dirty_words() {
        let inputs = vec![
            ("a".to_string(), "address".to_string()),
            ("b".to_string(), "uint16".to_string()),
            ("c".to_string(), "bytes32".to_string()),
        ];
        let mut data = vec![0u8; 96];
        data[31] = 0x11;
        data[63] = 50;
        data[64] = 0xaa;
        let args = decode(&inputs, &data).unwrap();
        assert_eq!(args[0].value, format!("0x{}11", "00".repeat(19)));
        assert_eq!(args[1].value, "50");
        assert!(args[2].value.starts_with("0xaa00"));
        let mut dirty = data.clone();
        dirty[0] = 1;
        assert!(decode(&inputs, &dirty).is_err());
        let mut wide = data.clone();
        wide[61] = 1;
        assert!(decode(&inputs, &wide).is_err());
        assert!(decode(&inputs, &data[..64]).is_err());
    }
}
