//! Read-only Ethereum JSON-RPC. No keys, no signing, no sending.

use crate::util::{Res, hex, unhex};
use serde_json::{Value, json};
use std::time::Duration;

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: &str) -> Rpc {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build()
            .new_agent();
        Rpc {
            url: url.to_string(),
            agent,
        }
    }

    /// One call. A transport failure is retried twice; an answer carrying a
    /// JSON-RPC error is returned as that error, not retried.
    pub fn call(&self, method: &str, params: Value) -> Res<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut last = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(800 * attempt));
            }
            let response = match self.agent.post(&self.url).send_json(&body) {
                Ok(r) => r,
                Err(e) => {
                    last = format!("{method}: transport: {e}");
                    continue;
                }
            };
            let status = response.status().as_u16();
            let text = match response.into_body().read_to_string() {
                Ok(t) => t,
                Err(e) => {
                    last = format!("{method}: reading the answer: {e}");
                    continue;
                }
            };
            if status == 429 || status >= 500 {
                last = format!("{method}: HTTP {status}");
                continue;
            }
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("{method}: HTTP {status}, not JSON: {e}"))?;
            if let Some(err) = v.get("error") {
                return Err(RpcError(format!("{method}: {err}")).into());
            }
            return v
                .get("result")
                .cloned()
                .ok_or_else(|| format!("{method}: no result").into());
        }
        Err(last.into())
    }

    pub fn chain_id(&self) -> Res<u64> {
        let v = self.call("eth_chainId", json!([]))?;
        quantity(&v)
    }

    pub fn block_number(&self) -> Res<u64> {
        quantity(&self.call("eth_blockNumber", json!([]))?)
    }

    pub fn code(&self, address: &str, block: &str) -> Res<Vec<u8>> {
        bytes(&self.call("eth_getCode", json!([address, block]))?)
    }

    pub fn storage(&self, address: &str, slot: &str) -> Res<Vec<u8>> {
        bytes(&self.call("eth_getStorageAt", json!([address, slot, "latest"]))?)
    }

    pub fn transaction(&self, hash: &str) -> Res<Value> {
        let v = self.call("eth_getTransactionByHash", json!([hash]))?;
        if v.is_null() {
            return Err(format!("transaction {hash} not found").into());
        }
        Ok(v)
    }

    pub fn receipt(&self, hash: &str) -> Res<Value> {
        let v = self.call("eth_getTransactionReceipt", json!([hash]))?;
        if v.is_null() {
            return Err(format!("receipt for {hash} not found").into());
        }
        Ok(v)
    }

    pub fn block(&self, number: u64) -> Res<Value> {
        self.call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), true]),
        )
    }

    /// `eth_call` with `data`. A revert is `Ok(Reverted)`, not an error: the
    /// probes below expect reverts.
    pub fn probe(&self, address: &str, data: &[u8]) -> Res<Probe> {
        match self.call(
            "eth_call",
            json!([{"to": address, "data": hex(data)}, "latest"]),
        ) {
            Ok(v) => Ok(Probe::Returned(bytes(&v)?)),
            Err(e) if e.downcast_ref::<RpcError>().is_some() => Ok(Probe::Reverted),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub enum Probe {
    Returned(Vec<u8>),
    Reverted,
}

#[derive(Debug)]
pub struct RpcError(pub String);
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RpcError {}

pub fn quantity(v: &Value) -> Res<u64> {
    let s = v.as_str().ok_or("quantity is not a string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

pub fn bytes(v: &Value) -> Res<Vec<u8>> {
    unhex(v.as_str().ok_or("data is not a string")?)
}
