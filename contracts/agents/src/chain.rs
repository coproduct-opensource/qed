//! Minimal JSON-RPC client, a legacy (EIP-155) transaction signer (`send`)
//! and an EIP-1559 signer (`Eip1559`, used by the relayer).
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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

/// How long and how hard a call is retried before it is called unavailable.
/// Tests shorten it; nothing else should.
#[derive(Clone, Copy, Debug)]
pub struct Patience {
    pub first_backoff: Duration,
    pub most_backoff: Duration,
    /// The longest a `Retry-After` is honoured for.
    pub most_retry_after: Duration,
    /// A call with no answer in this long ends as unavailable.
    pub give_up_after: Duration,
    /// The least time between two `eth_getLogs` to one endpoint.
    pub log_spacing: Duration,
    pub receipt_poll: Duration,
    pub receipt_wait: Duration,
    pub request_timeout: Duration,
}
impl Patience {
    pub const DEFAULT: Self = Self {
        first_backoff: Duration::from_secs(1),
        most_backoff: Duration::from_secs(60),
        most_retry_after: Duration::from_secs(300),
        give_up_after: Duration::from_secs(120),
        log_spacing: Duration::from_secs(4),
        receipt_poll: Duration::from_secs(1),
        receipt_wait: Duration::from_secs(180),
        request_timeout: Duration::from_secs(20),
    };
}

/// One endpoint's answer to one request, classified (R-1 in
/// docs/rfcs/proof-commerce-standing-bounty-2026-11-13.md).
#[derive(Clone, Debug, PartialEq)]
pub enum Attempt {
    /// A `result`.
    Answer(Value),
    /// A JSON-RPC error that is the chain's answer. Never retried.
    Refused(Value),
    /// Rate limited: back off this endpoint for this method, for at least
    /// `wait` when the endpoint said how long.
    Busy { wait: Option<Duration>, why: String },
    /// Network error, timeout, 5xx, or not JSON-RPC: back off.
    Down(String),
    /// This endpoint will not serve this call; ask the next one now.
    Cannot(String),
}

fn says_busy(code: Option<i64>, message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    matches!(code, Some(-32005 | -32029 | -32011))
        || ["rate limit", "too many requests", "request limit"]
            .iter()
            .any(|needle| message.contains(needle))
}
fn says_cannot(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "personal token",
        "api key",
        "apikey",
        "archive request",
        "free plan",
        "block range",
        "range too large",
        "ranges over",
        "range is over",
        "maximum allowed is",
        "are not supported",
        "is not supported",
        "discontinued",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}
/// A revert carries the contract's own text, which may say anything; it is
/// always the chain's answer.
fn says_reverted(code: Option<i64>, message: &str) -> bool {
    code == Some(3) || message.to_ascii_lowercase().contains("reverted")
}

/// Classify one HTTP exchange. `status` is `None` when no response came.
pub fn classify(status: Option<u16>, retry_after: Option<&str>, body: &str) -> Attempt {
    let Some(status) = status else {
        return Attempt::Down(body.to_owned());
    };
    let wait = retry_after
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let reply: Option<Value> = serde_json::from_str(body).ok();
    let error = reply
        .as_ref()
        .and_then(|reply| reply.get("error"))
        // A JSON-RPC error is an object; a gateway's `"error": "text"` is not.
        .filter(|error| error.is_object())
        .cloned();
    let short = || body.chars().take(200).collect::<String>();
    let message = |error: &Value| {
        let mut text = error["message"].as_str().unwrap_or_default().to_owned();
        if let Some(data) = error.get("data").and_then(Value::as_str) {
            text.push(' ');
            text.push_str(data);
        }
        text
    };
    match (status, error) {
        (429, _) => Attempt::Busy {
            wait,
            why: format!("HTTP 429: {}", short()),
        },
        (500..=599, _) => Attempt::Down(format!("HTTP {status}: {}", short())),
        (200..=299, None) => match reply {
            Some(reply) if reply.get("result").is_some() => {
                Attempt::Answer(reply["result"].clone())
            }
            _ => Attempt::Down(format!("HTTP {status}, not JSON-RPC: {}", short())),
        },
        (_, Some(error)) => {
            let text = message(&error);
            let code = error["code"].as_i64();
            if says_reverted(code, &text) {
                Attempt::Refused(error)
            } else if says_busy(code, &text) {
                Attempt::Busy {
                    wait,
                    why: format!("HTTP {status}: {text}"),
                }
            } else if says_cannot(&text) || code == Some(-32601) || code == Some(35) {
                Attempt::Cannot(format!("HTTP {status}: {text}"))
            } else {
                Attempt::Refused(error)
            }
        }
        (_, None) => Attempt::Cannot(format!("HTTP {status}: {}", short())),
    }
}

/// Why a call has no answer.
#[derive(Debug)]
pub enum RpcError {
    /// No endpoint answered in time, or every one said it cannot serve the
    /// call. Nothing was decided; trying later may work.
    Unavailable {
        method: String,
        /// Each endpoint's last failure, in the order they happened.
        failures: Vec<String>,
        /// Every endpoint said it cannot serve this call.
        all_cannot: bool,
    },
    /// A transaction was broadcast and no receipt was seen in time.
    NoReceipt {
        transaction: String,
        waited: Duration,
    },
    /// The chain's own answer: reverted, nonce too low, and so on.
    Refused { method: String, error: Value },
    /// An endpoint reports another chain than the deployment's.
    WrongChain {
        url: String,
        expected: u64,
        found: u64,
    },
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable {
                method, failures, ..
            } => {
                // The last few say what is happening; the count says how long.
                let shown = &failures[failures.len().saturating_sub(3)..];
                write!(
                    f,
                    "{method}: no RPC endpoint answered after {} tries (last: {})",
                    failures.len(),
                    shown.join("; ")
                )
            }
            Self::NoReceipt {
                transaction,
                waited,
            } => write!(
                f,
                "no receipt for {transaction} after {} s",
                waited.as_secs()
            ),
            Self::Refused { method, error } => write!(f, "{method}: {error}"),
            Self::WrongChain {
                url,
                expected,
                found,
            } => write!(f, "{url} is chain {found}, not {expected}"),
        }
    }
}
impl Error for RpcError {}

/// Whether an error is one that waiting may cure.
pub fn is_transient(error: &(dyn Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<RpcError>(),
        Some(RpcError::Unavailable { .. } | RpcError::NoReceipt { .. })
    )
}

struct Endpoint {
    url: String,
    /// Reported the chain's ID.
    verified: bool,
    last_logs: Option<Instant>,
}
/// What the clones of one `Chain` learn about its endpoints.
struct Pool {
    endpoints: Vec<Endpoint>,
    /// (endpoint, method) to when it may be asked again and the backoff
    /// that got it there.
    cooling: HashMap<(usize, String), (Instant, Duration)>,
    /// Unix seconds of the last answer or refusal from any endpoint.
    last_answer: Option<u64>,
}

#[derive(Clone)]
pub struct Chain {
    pool: Arc<Mutex<Pool>>,
    agent: ureq::Agent,
    patience: Patience,
    pub id: u64,
    /// When set, `send` estimates and prints the transaction it would sign,
    /// then refuses, sending nothing.
    dry_run: bool,
}

/// A little jitter from the clock: the scheduling of retries, not secrets.
fn jitter(base: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // 50% to 150% of the base.
    base / 2 + base.mul_f64(f64::from(nanos % 1_000) / 1_000.0)
}

/// The address a contract created by `sender` at `nonce` gets (CREATE).
pub fn create_address(sender: Address, nonce: u128) -> Address {
    let encoded = rlp_list(&[rlp_bytes(&sender), rlp_uint(nonce)]);
    let mut out = [0; 20];
    out.copy_from_slice(&keccak(&encoded)[12..]);
    out
}

impl Chain {
    pub fn connect(url: &str) -> Res<Self> {
        Self::connect_any(&[url.to_owned()], Patience::DEFAULT)
    }
    /// A chain reached through any of `urls`, asked in that order. The
    /// first to answer sets the chain ID; every other must report the same
    /// before it is used.
    pub fn connect_any(urls: &[String], patience: Patience) -> Res<Self> {
        if urls.is_empty() {
            return Err("no RPC endpoint".into());
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(patience.request_timeout))
            .build()
            .into();
        let mut chain = Self {
            pool: Arc::new(Mutex::new(Pool {
                endpoints: urls
                    .iter()
                    .map(|url| Endpoint {
                        url: url.clone(),
                        verified: false,
                        last_logs: None,
                    })
                    .collect(),
                cooling: HashMap::new(),
                last_answer: None,
            })),
            agent,
            patience,
            id: 0,
            dry_run: false,
        };
        chain.id = chain.quantity("eth_chainId", json!([]))? as u64;
        Ok(chain)
    }
    /// Unix seconds of the last answer from any endpoint.
    pub fn last_answer(&self) -> Option<u64> {
        self.pool.lock().ok().and_then(|pool| pool.last_answer)
    }
    fn pool(&self) -> Result<std::sync::MutexGuard<'_, Pool>, RpcError> {
        self.pool.lock().map_err(|_| RpcError::Unavailable {
            method: "pool".into(),
            failures: vec!["endpoint state poisoned".into()],
            all_cannot: false,
        })
    }
    /// One request to one endpoint, classified.
    fn attempt(&self, url: &str, method: &str, params: &Value) -> Attempt {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        match self.agent.post(url).send_json(&body) {
            Err(error) => classify(None, None, &format!("{url}: {error}")),
            Ok(mut response) => {
                let status = response.status().as_u16();
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                match response.body_mut().read_to_string() {
                    Ok(text) => classify(Some(status), retry_after.as_deref(), &text),
                    Err(error) => Attempt::Down(format!("HTTP {status}, body unreadable: {error}")),
                }
            }
        }
    }
    /// Ask the endpoints in order until one answers or refuses (R-1).
    fn request(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let started = Instant::now();
        let mut failures: Vec<String> = vec![];
        let mut skipped: Vec<usize> = vec![];
        let unavailable = |failures: Vec<String>, all_cannot: bool| RpcError::Unavailable {
            method: method.to_owned(),
            failures,
            all_cannot,
        };
        loop {
            // Choose: the first endpoint not skipped for this call and not
            // backing off for this method; else wait for the earliest.
            let (index, url, verified) = {
                let pool = self.pool()?;
                let now = Instant::now();
                let open: Vec<usize> = (0..pool.endpoints.len())
                    .filter(|index| !skipped.contains(index))
                    .collect();
                if open.is_empty() {
                    return Err(unavailable(failures, true));
                }
                let ready = |index: &usize| {
                    pool.cooling
                        .get(&(*index, method.to_owned()))
                        .map_or(now, |(until, _)| *until)
                };
                let index = *open
                    .iter()
                    .min_by_key(|index| (ready(index).max(now), **index))
                    .ok_or("no endpoint")
                    .map_err(|why| unavailable(vec![why.into()], false))?;
                let until = ready(&index);
                drop(pool);
                if until > now {
                    if started.elapsed() + (until - now) > self.patience.give_up_after {
                        return Err(unavailable(failures, false));
                    }
                    sleep(until - now);
                }
                if method == "eth_getLogs" {
                    let last = self.pool()?.endpoints[index].last_logs;
                    if let Some(last) = last {
                        let next = last + self.patience.log_spacing;
                        let now = Instant::now();
                        if next > now {
                            sleep(next - now);
                        }
                    }
                }
                let mut pool = self.pool()?;
                let endpoint = &mut pool.endpoints[index];
                if method == "eth_getLogs" {
                    endpoint.last_logs = Some(Instant::now());
                }
                (index, endpoint.url.clone(), endpoint.verified)
            };
            // An endpoint reports the chain's ID before it is used.
            let attempt = if !verified && self.id != 0 {
                match self.attempt(&url, "eth_chainId", &json!([])) {
                    Attempt::Answer(found) => {
                        let found = found
                            .as_str()
                            .and_then(|text| {
                                u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
                            })
                            .unwrap_or(0);
                        if found != self.id {
                            return Err(RpcError::WrongChain {
                                url,
                                expected: self.id,
                                found,
                            });
                        }
                        self.pool()?.endpoints[index].verified = true;
                        self.attempt(&url, method, params)
                    }
                    other => other,
                }
            } else {
                let attempt = self.attempt(&url, method, params);
                if method == "eth_chainId" && matches!(attempt, Attempt::Answer(_)) {
                    self.pool()?.endpoints[index].verified = true;
                }
                attempt
            };
            let mut pool = self.pool()?;
            let key = (index, method.to_owned());
            match attempt {
                Attempt::Answer(value) => {
                    pool.cooling.remove(&key);
                    pool.last_answer = crate::world::wall_clock().ok();
                    return Ok(value);
                }
                Attempt::Refused(error) => {
                    pool.last_answer = crate::world::wall_clock().ok();
                    return Err(RpcError::Refused {
                        method: method.to_owned(),
                        error,
                    });
                }
                Attempt::Cannot(why) => {
                    failures.push(format!("{url} cannot: {why}"));
                    skipped.push(index);
                }
                Attempt::Busy { wait, why } => {
                    let backoff = pool
                        .cooling
                        .get(&key)
                        .map_or(self.patience.first_backoff, |(_, last)| {
                            (*last * 2).min(self.patience.most_backoff)
                        });
                    let pause = jitter(backoff)
                        .max(wait.unwrap_or_default().min(self.patience.most_retry_after));
                    pool.cooling.insert(key, (Instant::now() + pause, backoff));
                    failures.push(format!("{url} busy: {why}"));
                }
                Attempt::Down(why) => {
                    let backoff = pool
                        .cooling
                        .get(&key)
                        .map_or(self.patience.first_backoff, |(_, last)| {
                            (*last * 2).min(self.patience.most_backoff)
                        });
                    pool.cooling
                        .insert(key, (Instant::now() + jitter(backoff), backoff));
                    failures.push(format!("{url} down: {why}"));
                }
            }
            if started.elapsed() > self.patience.give_up_after {
                return Err(unavailable(failures, false));
            }
        }
    }
    /// Logs matching `filter` (address and topics) in blocks `from..=to`,
    /// asked for in ranges every endpoint can serve.
    pub fn logs(&self, filter: &Value, from: u64, to: u64) -> Res<Vec<Value>> {
        let mut out = vec![];
        let mut range: u64 = 5_000;
        let mut start = from;
        while start <= to {
            let end = to.min(start.saturating_add(range - 1));
            let mut query = filter.clone();
            query["fromBlock"] = json!(format!("{start:#x}"));
            query["toBlock"] = json!(format!("{end:#x}"));
            match self.request("eth_getLogs", &json!([query])) {
                Ok(logs) => {
                    out.extend(logs.as_array().ok_or("logs expected")?.iter().cloned());
                    start = end + 1;
                }
                Err(RpcError::Unavailable {
                    all_cannot: true, ..
                }) if range > 10 => range /= 5,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(out)
    }
    /// The same chain, but `send` only prints what it would sign.
    pub fn dry(self) -> Self {
        Self {
            dry_run: true,
            ..self
        }
    }
    pub fn storage(&self, address: Address, slot: [u8; 32]) -> Res<[u8; 32]> {
        let word = unhex(
            self.rpc(
                "eth_getStorageAt",
                json!([hex(&address), hex(&slot), "latest"]),
            )?
            .as_str()
            .ok_or("storage word expected")?,
        )?;
        let mut out = [0; 32];
        out[32 - word.len().min(32)..].copy_from_slice(&word[word.len().saturating_sub(32)..]);
        Ok(out)
    }
    pub fn nonce(&self, address: Address) -> Res<u128> {
        self.quantity("eth_getTransactionCount", json!([hex(&address), "pending"]))
    }
    /// One JSON-RPC call, failed over and retried as R-1 says. The error is
    /// an `RpcError`; `is_transient` tells whether waiting may cure it.
    pub fn rpc(&self, method: &str, params: Value) -> Res<Value> {
        Ok(self.request(method, &params)?)
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
        if self.dry_run {
            let target = to.map_or_else(
                || {
                    format!(
                        "CREATE -> predicted address {}",
                        hex(&create_address(from, nonce))
                    )
                },
                |to| format!("call {}", hex(&to)),
            );
            println!(
                "  dry  chain {} from {} nonce {nonce}: {target}; value {value} wei; data {} bytes, sha256 {}; gas limit {gas} (estimate +10%) at {gas_price} wei; at most {} wei",
                self.id,
                hex(&from),
                data.len(),
                hex(&<sha2::Sha256 as sha2::Digest>::digest(data)),
                gas.saturating_mul(gas_price)
            );
            return Err("dry run: nothing was sent".into());
        }
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
        // The hash is the transaction's own; an endpoint's echo is checked
        // against it. After a lost reply the same signed bytes may be sent
        // again, which cannot make a second transaction: the answer is then
        // "already known", or "nonce too low" once the first was mined.
        // Either way the receipt decides, and if none comes the caller
        // re-derives what happened from the chain.
        let hash = hex(&keccak(&raw));
        match self.request("eth_sendRawTransaction", &json!([hex(&raw)])) {
            Ok(echo) if echo.as_str() == Some(hash.as_str()) => {}
            Ok(echo) => {
                return Err(format!("the node named transaction {echo}, not {hash}").into());
            }
            Err(RpcError::Refused { error, .. })
                if error["message"].as_str().is_some_and(|m| {
                    let m = m.to_ascii_lowercase();
                    m.contains("already known") || m.contains("nonce too low")
                }) => {}
            Err(error) => return Err(error.into()),
        }
        let started = Instant::now();
        while started.elapsed() < self.patience.receipt_wait {
            let receipt = match self.request("eth_getTransactionReceipt", &json!([hash])) {
                Ok(receipt) => receipt,
                // Keep looking until the receipt wait is over.
                Err(RpcError::Unavailable { .. }) => Value::Null,
                Err(error) => return Err(error.into()),
            };
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
            sleep(self.patience.receipt_poll);
        }
        Err(RpcError::NoReceipt {
            transaction: hash,
            waited: started.elapsed(),
        }
        .into())
    }

    /// `eth_estimateGas` for a call, unpadded.
    pub fn estimate(&self, from: Address, to: Address, value: u128, data: &[u8]) -> Res<u128> {
        self.quantity(
            "eth_estimateGas",
            json!([{"from": hex(&from), "to": hex(&to), "value": format!("{value:#x}"), "data": hex(data)}]),
        )
    }
    /// The latest block's base fee and the endpoint's suggested priority fee,
    /// in wei per gas.
    pub fn fees(&self) -> Res<(u128, u128)> {
        let block = self.rpc("eth_getBlockByNumber", json!(["latest", false]))?;
        let base = u128::from_str_radix(
            block["baseFeePerGas"]
                .as_str()
                .ok_or("block has no base fee")?
                .trim_start_matches("0x"),
            16,
        )?;
        Ok((base, self.quantity("eth_maxPriorityFeePerGas", json!([]))?))
    }
    /// Broadcast signed bytes whose hash is `hash`. "Already known" and
    /// "nonce too low" are not failures here: the receipt decides (see `send`).
    pub fn broadcast(&self, raw: &[u8], hash: &str) -> Res<()> {
        match self.request("eth_sendRawTransaction", &json!([hex(raw)])) {
            Ok(echo) if echo.as_str() == Some(hash) => Ok(()),
            Ok(echo) => Err(format!("the node named transaction {echo}, not {hash}").into()),
            Err(RpcError::Refused { error, .. })
                if error["message"].as_str().is_some_and(|m| {
                    let m = m.to_ascii_lowercase();
                    m.contains("already known") || m.contains("nonce too low")
                }) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
    /// The receipt of `hash`, if the chain has one. An endpoint that cannot
    /// say is "not yet", as in `send`.
    pub fn receipt(&self, hash: &str) -> Res<Option<Receipt>> {
        let receipt = match self.request("eth_getTransactionReceipt", &json!([hash])) {
            Ok(receipt) => receipt,
            Err(RpcError::Unavailable { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if receipt.is_null() {
            return Ok(None);
        }
        let number = |field: &str| -> Res<u64> {
            Ok(u64::from_str_radix(
                receipt[field]
                    .as_str()
                    .ok_or("receipt field expected")?
                    .trim_start_matches("0x"),
                16,
            )?)
        };
        Ok(Some(Receipt {
            success: number("status")? == 1,
            contract: None,
            gas_used: number("gasUsed")?,
            transaction: hash.to_owned(),
        }))
    }
    /// What the chain says transaction `hash` is: its recipient, value and
    /// input. `None` if no endpoint knows it.
    pub fn transaction(&self, hash: &str) -> Res<Option<Sent>> {
        let found = match self.request("eth_getTransactionByHash", &json!([hash])) {
            Ok(found) => found,
            Err(RpcError::Unavailable { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if found.is_null() {
            return Ok(None);
        }
        let to = match found["to"].as_str() {
            Some(text) => Some(unhex(text)?.try_into().map_err(|_| "to length")?),
            None => None,
        };
        Ok(Some(Sent {
            to,
            value: u128::from_str_radix(
                found["value"]
                    .as_str()
                    .ok_or("value expected")?
                    .trim_start_matches("0x"),
                16,
            )?,
            input: unhex(found["input"].as_str().ok_or("input expected")?)?,
        }))
    }
}

/// A transaction as the chain reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub to: Option<Address>,
    pub value: u128,
    pub input: Vec<u8>,
}

/// An EIP-1559 (type 2) call, unsigned. No access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: u128,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas: u128,
    pub to: Address,
    pub value: u128,
    pub data: Vec<u8>,
}
impl Eip1559 {
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(u128::from(self.chain_id)),
            rlp_uint(self.nonce),
            rlp_uint(self.max_priority_fee),
            rlp_uint(self.max_fee),
            rlp_uint(self.gas),
            rlp_bytes(&self.to),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
            rlp_list(&[]),
        ]
    }
    /// keccak256(0x02 || rlp(fields)): what the sender signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak(&[&[2u8][..], &rlp_list(&self.fields())].concat())
    }
    /// The signed bytes to broadcast and the transaction's hash.
    pub fn sign(&self, key: &SigningKey) -> (Vec<u8>, String) {
        let (signature, recovery) = key.sign_prehash_recoverable(&self.signing_hash());
        let bytes = signature.to_bytes();
        let strip = |word: &[u8]| {
            rlp_bytes(&word[word.iter().position(|b| *b != 0).unwrap_or(word.len())..])
        };
        let mut items = self.fields();
        items.push(rlp_uint(u128::from(recovery.to_byte())));
        items.push(strip(&bytes[..32]));
        items.push(strip(&bytes[32..]));
        let raw = [vec![2u8], rlp_list(&items)].concat();
        let hash = hex(&keccak(&raw));
        (raw, hash)
    }
}

#[cfg(test)]
pub(crate) mod fault;
#[cfg(test)]
mod tests;
