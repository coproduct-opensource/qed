//! Minimal JSON-RPC client and legacy (EIP-155) transaction signer.
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{error::Error, thread::sleep, time::Duration};

pub type Res<T> = Result<T, Box<dyn Error>>;
pub type Address = [u8; 20];

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
pub fn unhex(text: &str) -> Res<Vec<u8>> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    let digits = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_owned()
    };
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(Into::into))
        .collect()
}
pub fn address_of(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_sec1_point(false);
    let mut out = [0; 20];
    out.copy_from_slice(&keccak(&point.as_bytes()[1..])[12..]);
    out
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    match bytes {
        [single] if *single < 0x80 => vec![*single],
        _ => [rlp_length(bytes.len(), 0x80), bytes.to_vec()].concat(),
    }
}
fn rlp_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let be = len.to_be_bytes();
        let be = &be[be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1)..];
        [vec![offset + 55 + be.len() as u8], be.to_vec()].concat()
    }
}
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body = items.concat();
    [rlp_length(body.len(), 0xc0), body].concat()
}
fn rlp_uint(value: u128) -> Vec<u8> {
    let be = value.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    rlp_bytes(&be[start..])
}

pub struct Receipt {
    pub success: bool,
    pub contract: Option<Address>,
    pub gas_used: u64,
    pub transaction: String,
}

#[derive(Clone)]
pub struct Chain {
    url: String,
    pub id: u64,
}

impl Chain {
    pub fn connect(url: &str) -> Res<Self> {
        let mut chain = Self {
            url: url.to_owned(),
            id: 0,
        };
        chain.id = chain.quantity("eth_chainId", json!([]))? as u64;
        Ok(chain)
    }
    pub fn rpc(&self, method: &str, params: Value) -> Res<Value> {
        let reply: Value = ureq::post(&self.url)
            .send_json(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))?
            .body_mut()
            .read_json()?;
        if let Some(error) = reply.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        Ok(reply["result"].clone())
    }
    fn quantity(&self, method: &str, params: Value) -> Res<u128> {
        let value = self.rpc(method, params)?;
        let text = value.as_str().ok_or("quantity expected")?;
        Ok(u128::from_str_radix(text.trim_start_matches("0x"), 16)?)
    }
    /// The latest block's timestamp: the time the vault's deadlines are
    /// measured against.
    pub fn timestamp(&self) -> Res<u64> {
        let block = self.rpc("eth_getBlockByNumber", json!(["latest", false]))?;
        let text = block["timestamp"]
            .as_str()
            .ok_or("block timestamp expected")?;
        Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
    }
    pub fn balance(&self, address: Address) -> Res<u128> {
        self.quantity("eth_getBalance", json!([hex(&address), "latest"]))
    }
    pub fn code(&self, address: Address) -> Res<Vec<u8>> {
        unhex(
            self.rpc("eth_getCode", json!([hex(&address), "latest"]))?
                .as_str()
                .ok_or("code expected")?,
        )
    }
    /// eth_call; an execution revert is returned as `Err` carrying the node's message.
    pub fn call(&self, from: Address, to: Address, data: &[u8]) -> Res<Vec<u8>> {
        let out = self.rpc(
            "eth_call",
            json!([{"from": hex(&from), "to": hex(&to), "data": hex(data)}, "latest"]),
        )?;
        unhex(out.as_str().ok_or("call result expected")?)
    }
    /// Sign and send a legacy transaction, then wait for its receipt.
    pub fn send(
        &self,
        key: &SigningKey,
        to: Option<Address>,
        value: u128,
        data: &[u8],
    ) -> Res<Receipt> {
        let from = address_of(key);
        let nonce = self.quantity("eth_getTransactionCount", json!([hex(&from), "pending"]))?;
        // A sender must hold gas limit x price up front. Keep both margins modest
        // so a faucet-funded wallet is not refused for headroom it will get back.
        let gas_price = self.quantity("eth_gasPrice", json!([]))?.saturating_mul(21) / 20;
        let mut request =
            json!({"from": hex(&from), "data": hex(data), "value": format!("{value:#x}")});
        if let Some(to) = to {
            request["to"] = json!(hex(&to));
        }
        let gas = self
            .quantity("eth_estimateGas", json!([request]))?
            .saturating_mul(11)
            / 10;
        let to_field = to.map_or_else(|| rlp_bytes(&[]), |to| rlp_bytes(&to));
        let unsigned = |tail: [Vec<u8>; 3]| {
            let mut items = vec![
                rlp_uint(nonce),
                rlp_uint(gas_price),
                rlp_uint(gas),
                to_field.clone(),
                rlp_uint(value),
                rlp_bytes(data),
            ];
            items.extend(tail);
            rlp_list(&items)
        };
        let digest = keccak(&unsigned([
            rlp_uint(u128::from(self.id)),
            rlp_uint(0),
            rlp_uint(0),
        ]));
        let (signature, recovery) = key.sign_prehash_recoverable(&digest);
        let bytes = signature.to_bytes();
        let strip = |word: &[u8]| {
            rlp_bytes(&word[word.iter().position(|b| *b != 0).unwrap_or(word.len())..])
        };
        let v = u128::from(self.id) * 2 + 35 + u128::from(recovery.to_byte());
        let raw = unsigned([rlp_uint(v), strip(&bytes[..32]), strip(&bytes[32..])]);
        let hash = self.rpc("eth_sendRawTransaction", json!([hex(&raw)]))?;
        let hash = hash.as_str().ok_or("transaction hash expected")?.to_owned();
        for _ in 0..200 {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([hash]))?;
            if !receipt.is_null() {
                let number = |field: &str| -> Res<u64> {
                    Ok(u64::from_str_radix(
                        receipt[field]
                            .as_str()
                            .ok_or("field expected")?
                            .trim_start_matches("0x"),
                        16,
                    )?)
                };
                let contract = match receipt["contractAddress"].as_str() {
                    Some(text) => Some(unhex(text)?.try_into().map_err(|_| "address expected")?),
                    None => None,
                };
                return Ok(Receipt {
                    success: number("status")? == 1,
                    contract,
                    gas_used: number("gasUsed")?,
                    transaction: hash,
                });
            }
            sleep(Duration::from_millis(100));
        }
        Err("no receipt".into())
    }
}
