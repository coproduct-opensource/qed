//! The gas relayer, a mode of the wrap service, and the seller's client for it
//! (docs/rfcs/qed-relayer-2026-11-13.md).
//!
//! It sends `fund`, `settle` and `claim` to an allow-listed vault and pays
//! the gas, so a seller needs no ETH. The rules are numbered in the RFC and
//! named next to the code that keeps them:
//! - S-1 to S-4: only those three calls, only to an allow-listed vault, value
//!   0, calldata parsed and re-encoded. It never moves tokens.
//! - A-1 to A-8: DPoP on every request; rate limits per key, per address and
//!   per named seller per day; simulation and a gas cap before any send; an
//!   ETH budget and a balance floor; EIP-1559 fees under a cap; one nonce lane
//!   per chain; bounded fee-bump replacement.
//! - R-1 to R-4 (seller side, `submit`): the seller checks the mined
//!   transaction against the calldata it built, and sends the call itself if
//!   the relayer does not deliver in time.
//! - T-1 to T-9 (`transfer.rs`, RFC §15): one more call, the token's
//!   `transferWithAuthorization`, signed by a seller an allow-listed vault
//!   paid, within what the vaults paid it.
pub mod transfer;
use crate::chain::{Eip1559, RpcError, Sent};
use crate::dpop::{DPOP_TYP, proof_check, proof_make};
use crate::message::{Reply, Request};
use crate::prelude::*;
use crate::world::third;
use crate::wrap::Window;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// The largest request body: a `settle` carries the artifact.
pub const MAXIMUM_REQUEST: usize = 2 << 20;
/// How many requests' transaction hashes are remembered for `GET /relay/…`.
const HISTORY: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Fund,
    Settle,
    Claim,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fund => "fund",
            Self::Settle => "settle",
            Self::Claim => "claim",
        }
    }
}

/// A call the relayer has parsed: which one, and the seller it serves (the
/// order's `seller`, or the `payee` of a claim), for the daily cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub kind: Kind,
    pub seller: Address,
}

/// S-3: the calldata must be one of the third form's three calls, in the
/// encoding the relayer itself would produce.
pub fn parse(data: &[u8]) -> Result<Parsed, &'static str> {
    let selector: [u8; 4] = data
        .get(..4)
        .ok_or("calldata has no selector")?
        .try_into()
        .map_err(|_| "calldata has no selector")?;
    let (parsed, again) = if selector == third::fundCall::SELECTOR {
        let call =
            third::fundCall::abi_decode(data).map_err(|_| "fund calldata does not decode")?;
        let seller = call.o.seller.into_array();
        (
            Parsed {
                kind: Kind::Fund,
                seller,
            },
            call.abi_encode(),
        )
    } else if selector == third::settleCall::SELECTOR {
        let call =
            third::settleCall::abi_decode(data).map_err(|_| "settle calldata does not decode")?;
        let seller = call.o.seller.into_array();
        (
            Parsed {
                kind: Kind::Settle,
                seller,
            },
            call.abi_encode(),
        )
    } else if selector == third::claimCall::SELECTOR {
        let call =
            third::claimCall::abi_decode(data).map_err(|_| "claim calldata does not decode")?;
        let seller = call.payee.into_array();
        (
            Parsed {
                kind: Kind::Claim,
                seller,
            },
            call.abi_encode(),
        )
    } else {
        return Err("only fund, settle and claim are relayed");
    };
    if again != data {
        return Err("calldata is not the canonical encoding of its call");
    }
    Ok(parsed)
}

/// Limits that apply across chains.
#[derive(Clone, Debug)]
pub struct Limits {
    pub per_key_per_hour: usize,
    pub per_address_per_hour: usize,
    /// Relayed calls per named seller in any 24 hours (A-2).
    pub per_seller_per_day: usize,
    /// A-4.
    pub maximum_gas_per_call: u128,
    /// A-8.
    pub replace_after: Duration,
    pub maximum_replacements: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            per_key_per_hour: 20,
            per_address_per_hour: 60,
            per_seller_per_day: 30,
            maximum_gas_per_call: 600_000,
            replace_after: Duration::from_secs(60),
            maximum_replacements: 3,
        }
    }
}

/// What one chain's lane may do.
#[derive(Clone, Debug)]
pub struct LaneConfig {
    /// S-1.
    pub vaults: Vec<Address>,
    /// A-6.
    pub maximum_fee_per_gas: u128,
    /// A-5: the most this process reserves for gas on this chain.
    pub budget: u128,
    /// A-5: the balance the relayer keeps on this chain.
    pub floor: u128,
    /// T-1: the token whose transfers are relayed here. `None`: none are.
    pub transfer: Option<transfer::TransferConfig>,
}

struct Pending {
    first: String,
    tx: Eip1559,
    sent: Instant,
    replacements: u32,
}
#[derive(Default)]
struct LaneState {
    next: Option<u128>,
    reserved: u128,
    pending: Vec<Pending>,
    /// First hash of a request, and every hash used for it, oldest first.
    history: VecDeque<(String, Vec<String>)>,
    /// T-7: the relayed transfer in flight for each `from`, by first hash,
    /// until one of its hashes is mined.
    transfers: HashMap<Address, String>,
}
impl LaneState {
    fn record(&mut self, first: &str, hash: &str) {
        if let Some((_, hashes)) = self.history.iter_mut().find(|(f, _)| f == first) {
            hashes.push(hash.to_owned());
            return;
        }
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history
            .push_back((first.to_owned(), vec![hash.to_owned()]));
    }
    fn pending_worst(&self) -> u128 {
        self.pending
            .iter()
            .map(|p| p.tx.gas.saturating_mul(p.tx.max_fee))
            .fold(0u128, u128::saturating_add)
    }
}

/// One chain: its client, its rules and its single nonce queue (A-7).
pub struct Lane {
    pub chain: Chain,
    pub config: LaneConfig,
    state: Mutex<LaneState>,
}

type Refusal = (u16, String);

/// A chain error as an answer: the chain's own refusal is the request's
/// fault (422); anything else may pass (503).
fn chain_refusal(error: &(dyn std::error::Error + 'static), what: &str) -> Refusal {
    match error.downcast_ref::<RpcError>() {
        Some(RpcError::Refused { error, .. }) => (
            422,
            format!(
                "{what}: {}",
                error["message"].as_str().unwrap_or("refused by the chain")
            ),
        ),
        _ => (503, format!("chain unavailable: {error}")),
    }
}

/// A-6: the max fee for a base fee and priority fee under `cap`.
pub fn max_fee(base: u128, priority: u128, cap: u128) -> Result<(u128, u128), Refusal> {
    let floor = base.saturating_add(priority);
    if floor > cap {
        return Err((
            503,
            format!("gas price {floor} wei is over the cap of {cap} wei"),
        ));
    }
    Ok((
        priority,
        base.saturating_mul(2).saturating_add(priority).min(cap),
    ))
}

impl Lane {
    pub fn new(chain: Chain, config: LaneConfig) -> Self {
        Self {
            chain,
            config,
            state: Mutex::new(LaneState::default()),
        }
    }
    fn state(&self) -> Result<std::sync::MutexGuard<'_, LaneState>, Refusal> {
        self.state
            .lock()
            .map_err(|_| (500, "lane state poisoned".to_owned()))
    }
    /// A-5: whether `worst` more wei may be committed.
    fn afford(&self, state: &LaneState, from: Address, worst: u128) -> Result<(), Refusal> {
        if state.reserved.saturating_add(worst) > self.config.budget {
            return Err((503, "the relayer's gas budget is spent".into()));
        }
        let balance = self
            .chain
            .balance(from)
            .map_err(|e| chain_refusal(e.as_ref(), "balance"))?;
        let needed = self
            .config
            .floor
            .saturating_add(state.pending_worst())
            .saturating_add(worst);
        if balance < needed {
            return Err((
                503,
                "the relayer's balance would fall below its floor".into(),
            ));
        }
        Ok(())
    }
    /// Simulate, estimate, price, reserve, sign with the next nonce and
    /// broadcast. Returns the transaction hash and nonce.
    fn send(
        &self,
        key: &SigningKey,
        to: Address,
        data: &[u8],
        limits: &Limits,
    ) -> Result<(String, u128), Refusal> {
        let from = address_of(key);
        // A-3: a call that would revert is refused before anything is signed.
        self.chain
            .call(from, to, data)
            .map_err(|e| chain_refusal(e.as_ref(), "simulation reverts"))?;
        let estimate = self
            .chain
            .estimate(from, to, 0, data)
            .map_err(|e| chain_refusal(e.as_ref(), "gas estimate reverts"))?;
        // A-4.
        let gas = estimate.saturating_mul(12) / 10;
        if gas > limits.maximum_gas_per_call {
            return Err((
                422,
                format!(
                    "gas limit {gas} is over the per-call cap of {}",
                    limits.maximum_gas_per_call
                ),
            ));
        }
        let (base, priority) = self
            .chain
            .fees()
            .map_err(|e| chain_refusal(e.as_ref(), "fees"))?;
        let (priority, max_fee) = max_fee(base, priority, self.config.maximum_fee_per_gas)?;
        let worst = gas.saturating_mul(max_fee);
        // A-7: one lock from nonce choice to broadcast.
        let mut state = self.state()?;
        self.afford(&state, from, worst)?;
        let on_chain = self
            .chain
            .nonce(from)
            .map_err(|e| chain_refusal(e.as_ref(), "nonce"))?;
        let nonce = state.next.unwrap_or(0).max(on_chain);
        let tx = Eip1559 {
            chain_id: self.chain.id,
            nonce,
            max_priority_fee: priority,
            max_fee,
            gas,
            to,
            value: 0,
            data: data.to_vec(),
        };
        let (raw, hash) = tx.sign(key);
        self.chain
            .broadcast(&raw, &hash)
            .map_err(|e| chain_refusal(e.as_ref(), "broadcast refused"))?;
        state.next = Some(nonce + 1);
        state.reserved = state.reserved.saturating_add(worst);
        state.record(&hash, &hash);
        state.pending.push(Pending {
            first: hash.clone(),
            tx,
            sent: Instant::now(),
            replacements: 0,
        });
        Ok((hash, nonce))
    }
    /// A-8: forget what was mined; re-sign what is stuck with higher fees.
    pub fn tend(&self, key: &SigningKey, limits: &Limits) {
        let Ok(mut state) = self.state() else { return };
        let mut keep = Vec::new();
        for mut pending in std::mem::take(&mut state.pending) {
            let hashes: Vec<String> = state
                .history
                .iter()
                .find(|(first, _)| *first == pending.first)
                .map(|(_, hashes)| hashes.clone())
                .unwrap_or_default();
            let mined = hashes
                .iter()
                .any(|hash| matches!(self.chain.receipt(hash), Ok(Some(_))));
            if mined {
                state.transfers.retain(|_, first| *first != pending.first);
                continue;
            }
            if pending.sent.elapsed() < limits.replace_after
                || pending.replacements >= limits.maximum_replacements
            {
                keep.push(pending);
                continue;
            }
            let cap = self.config.maximum_fee_per_gas;
            let bump = |fee: u128| (fee.saturating_mul(5) / 4).max(fee.saturating_add(1));
            let max_fee = bump(pending.tx.max_fee).min(cap);
            let priority = bump(pending.tx.max_priority_fee).min(max_fee);
            if max_fee <= pending.tx.max_fee {
                println!(
                    "relay: {} is stuck at the fee cap; not replaced",
                    pending.first
                );
                pending.replacements = limits.maximum_replacements;
                keep.push(pending);
                continue;
            }
            let extra = pending.tx.gas.saturating_mul(max_fee - pending.tx.max_fee);
            if state.reserved.saturating_add(extra) > self.config.budget {
                println!("relay: {} not replaced: budget spent", pending.first);
                keep.push(pending);
                continue;
            }
            let tx = Eip1559 {
                max_fee,
                max_priority_fee: priority,
                ..pending.tx.clone()
            };
            let (raw, hash) = tx.sign(key);
            match self.chain.broadcast(&raw, &hash) {
                Ok(()) => {
                    state.reserved = state.reserved.saturating_add(extra);
                    let first = pending.first.clone();
                    state.record(&first, &hash);
                    println!(
                        "relay: replaced {first} (nonce {}) with {hash} at max fee {max_fee}",
                        tx.nonce
                    );
                    pending.tx = tx;
                    pending.sent = Instant::now();
                    pending.replacements += 1;
                }
                Err(error) => {
                    println!("relay: replacing {} refused: {error}", pending.first);
                    pending.replacements += 1;
                }
            }
            keep.push(pending);
        }
        state.pending = keep;
    }
    /// T-7: the first hash of the relayed transfer for `from` not yet mined.
    fn transfer_in_flight(&self, from: Address) -> Result<Option<String>, Refusal> {
        Ok(self.state()?.transfers.get(&from).cloned())
    }
    /// Send an admitted transfer (T-9: A-3 to A-8 as for every call) and
    /// hold it in flight for its `from` until it is mined (T-7).
    fn send_transfer(
        &self,
        key: &SigningKey,
        admitted: transfer::Admitted,
        limits: &Limits,
    ) -> Result<(String, u128), Refusal> {
        let (token, data, from) = admitted.into_call();
        let (hash, nonce) = self.send(key, token, &data, limits)?;
        self.state()?.transfers.insert(from, hash.clone());
        Ok((hash, nonce))
    }
    fn hashes(&self, first: &str) -> Option<Vec<String>> {
        let state = self.state.lock().ok()?;
        state
            .history
            .iter()
            .find(|(f, _)| f == first)
            .map(|(_, hashes)| hashes.clone())
    }
}

pub struct Relay {
    /// Scheme and authority as a proof's `htu` names it.
    pub base: String,
    pub limits: Limits,
    key: SigningKey,
    lanes: HashMap<u64, Lane>,
    replay: Mutex<HashSet<String>>,
    keys: Mutex<Window>,
    addresses: Mutex<Window>,
    sellers: Mutex<Window>,
    /// T-8: relayed transfers per `from`, and in all, per day.
    transfers: Mutex<Window>,
    /// T-7: the (chain, `from`) pairs whose transfer is being admitted now.
    admitting: Mutex<HashSet<(u64, Address)>>,
}

/// Holds one (chain, `from`) in `Relay::admitting` and releases it on drop.
struct Admitting<'a> {
    set: &'a Mutex<HashSet<(u64, Address)>>,
    key: (u64, Address),
}
impl Drop for Admitting<'_> {
    fn drop(&mut self) {
        if let Ok(mut set) = self.set.lock() {
            set.remove(&self.key);
        }
    }
}

impl Relay {
    pub fn new(base: &str, key: SigningKey, limits: Limits, lanes: Vec<Lane>) -> Res<Self> {
        let mut by_chain = HashMap::new();
        for lane in lanes {
            if by_chain.insert(lane.chain.id, lane).is_some() {
                return Err("two lanes for one chain".into());
            }
        }
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            limits,
            key,
            lanes: by_chain,
            replay: Mutex::new(HashSet::new()),
            keys: Mutex::new(Window::default()),
            addresses: Mutex::new(Window::default()),
            sellers: Mutex::new(Window::default()),
            transfers: Mutex::new(Window::default()),
            admitting: Mutex::new(HashSet::new()),
        })
    }
    /// The address that pays the gas.
    pub fn address(&self) -> Address {
        address_of(&self.key)
    }
    /// Run A-8 on every lane.
    pub fn tend(&self) {
        for lane in self.lanes.values() {
            lane.tend(&self.key, &self.limits);
        }
    }

    /// `POST /relay` or `GET /relay/<hash>`.
    pub fn handle(&self, peer: IpAddr, request: &Request, now: u64) -> Reply {
        let answer = match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/relay") => self.submit(peer, request, now),
            ("GET", path) if path.starts_with("/relay/0x") => self.status(request, now),
            _ => Err((404, "not found".into())),
        };
        match answer {
            Ok(body) => {
                let status = if request.method == "POST" { 202 } else { 200 };
                let mut reply = Reply::new(status).with("content-type", "application/json".into());
                reply.body = body.to_string().into_bytes();
                reply
            }
            Err((status, why)) => Reply::text(status, &why),
        }
    }

    /// A-1.
    fn possession(&self, request: &Request, now: u64) -> Result<String, Refusal> {
        let proof = request
            .headers
            .get("dpop")
            .ok_or((401, "DPoP proof missing".to_owned()))?;
        let uri = format!("{}{}", self.base, request.path);
        let body = (request.method == "POST").then_some(request.body.as_slice());
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| (500, "state poisoned".to_owned()))?;
        proof_check(
            proof,
            DPOP_TYP,
            &request.method,
            &uri,
            body,
            now,
            &mut replay,
        )
        .map(|proved| proved.thumbprint)
        .map_err(|error| (401, error.to_string()))
    }

    fn submit(&self, peer: IpAddr, request: &Request, now: u64) -> Result<Value, Refusal> {
        if request.body.is_empty() || request.body.len() > MAXIMUM_REQUEST {
            return Err((413, "request size refused".into()));
        }
        let thumbprint = self.possession(request, now)?;
        let admitted = |window: &Mutex<Window>, who: &str, limit, span| {
            window
                .lock()
                .map(|mut w| w.admit_within(who, now, limit, span))
                .unwrap_or(false)
        };
        // A-2, before any work is done for the request.
        if !admitted(&self.keys, &thumbprint, self.limits.per_key_per_hour, 3600)
            || !admitted(
                &self.addresses,
                &peer.to_string(),
                self.limits.per_address_per_hour,
                3600,
            )
        {
            return Err((429, "hourly limit reached".into()));
        }
        let malformed = |what: &str| (400, format!("{what} malformed"));
        let body: Value =
            serde_json::from_slice(&request.body).map_err(|_| malformed("request"))?;
        let chain_id = body["chainId"]
            .as_u64()
            .ok_or_else(|| malformed("chainId"))?;
        let to: Address = unhex(body["to"].as_str().ok_or_else(|| malformed("to"))?)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| malformed("to"))?;
        let value: u128 = body["value"]
            .as_str()
            .ok_or_else(|| malformed("value"))?
            .parse()
            .map_err(|_| malformed("value"))?;
        let data = unhex(body["data"].as_str().ok_or_else(|| malformed("data"))?)
            .map_err(|_| malformed("data"))?;
        let lane = self
            .lanes
            .get(&chain_id)
            .ok_or((403, "chain not served here".to_owned()))?;
        if let Some(config) = &lane.config.transfer
            && to == config.token
        {
            if value != 0 {
                return Err((403, "value must be 0".into()));
            }
            let claims: Vec<String> = match &body["claims"] {
                Value::Array(list) => list
                    .iter()
                    .map(|c| {
                        c.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| malformed("claims"))
                    })
                    .collect::<Result<_, _>>()?,
                _ => return Err(malformed("claims")),
            };
            return self.submit_transfer(chain_id, lane, config, &data, &claims, now);
        }
        // S-1, S-2.
        if !lane.config.vaults.contains(&to) {
            return Err((403, "not an allow-listed vault".into()));
        }
        if value != 0 {
            return Err((403, "value must be 0".into()));
        }
        // S-3.
        let parsed = parse(&data).map_err(|why| (422, why.to_owned()))?;
        if !admitted(
            &self.sellers,
            &format!("{chain_id}:{}", hex(&parsed.seller)),
            self.limits.per_seller_per_day,
            86_400,
        ) {
            return Err((429, "daily limit for this seller reached".into()));
        }
        let (hash, nonce) = lane.send(&self.key, to, &data, &self.limits)?;
        println!(
            "relay: {} for seller {} on chain {chain_id}: tx {hash} nonce {nonce}",
            parsed.kind.name(),
            hex(&parsed.seller)
        );
        Ok(json!({"transaction": hash, "relayer": hex(&self.address()), "nonce": nonce}))
    }

    /// T-1 to T-9 for one transfer to `config.token` with value 0.
    fn submit_transfer(
        &self,
        chain_id: u64,
        lane: &Lane,
        config: &transfer::TransferConfig,
        data: &[u8],
        claims: &[String],
        now: u64,
    ) -> Result<Value, Refusal> {
        // T-2, T-3: no chain needed.
        let signed = transfer::check_offline(config, data)?;
        let from = signed.authorization.from;
        let admitted = |window: &Mutex<Window>, who: &str, limit| {
            window
                .lock()
                .map(|mut w| w.admit_within(who, now, limit, 86_400))
                .unwrap_or(false)
        };
        // T-8.
        if !admitted(
            &self.sellers,
            &format!("{chain_id}:{}", hex(&from)),
            self.limits.per_seller_per_day,
        ) || !admitted(
            &self.transfers,
            &format!("{chain_id}:{}", hex(&from)),
            config.per_address_per_day,
        ) {
            return Err((429, "daily limit for this address reached".into()));
        }
        if !admitted(&self.transfers, &format!("{chain_id}:all"), config.per_day) {
            return Err((429, "daily limit for relayed transfers reached".into()));
        }
        // T-7: one admission at a time per `from`, and none while an earlier
        // transfer for it is not yet mined.
        let key = (chain_id, from);
        if !self
            .admitting
            .lock()
            .map_err(|_| (500, "state poisoned".to_owned()))?
            .insert(key)
        {
            return Err((409, "a transfer for this address is being admitted".into()));
        }
        let _held = Admitting {
            set: &self.admitting,
            key,
        };
        if let Some(first) = lane.transfer_in_flight(from)? {
            return Err((
                409,
                format!("transfer {first} for this address is not mined yet"),
            ));
        }
        // T-4 to T-6.
        let admitted = transfer::admit(lane, config, signed, claims)?;
        let (value, paid) = (admitted.value(), admitted.paid());
        // T-9.
        let (hash, nonce) = lane.send_transfer(&self.key, admitted, &self.limits)?;
        println!(
            "relay: transfer of {value} for {} on chain {chain_id} (claimed {}, out {} since block {}): tx {hash} nonce {nonce}",
            hex(&from),
            paid.claimed,
            paid.out,
            paid.since
        );
        Ok(json!({"transaction": hash, "relayer": hex(&self.address()), "nonce": nonce}))
    }

    fn status(&self, request: &Request, now: u64) -> Result<Value, Refusal> {
        self.possession(request, now)?;
        let first = request.path.trim_start_matches("/relay/");
        self.lanes
            .values()
            .find_map(|lane| lane.hashes(first))
            .map(|hashes| json!({ "transactions": hashes }))
            .ok_or((404, "unknown transaction".into()))
    }
}

/// Serve over plain HTTP/1.1 behind TLS, and tend the lanes every few
/// seconds. `forwarded` trusts `X-Forwarded-For` from a local proxy.
pub fn serve(listener: std::net::TcpListener, relay: Arc<Relay>, forwarded: bool) {
    let tender = relay.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            tender.tend();
        }
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let relay = relay.clone();
        std::thread::spawn(move || {
            let _ = crate::http::answer(stream, |peer, request| {
                let peer = if forwarded {
                    request
                        .headers
                        .get("x-forwarded-for")
                        .and_then(|v| v.split(',').next()?.trim().parse().ok())
                        .unwrap_or(peer)
                } else {
                    peer
                };
                relay.handle(peer, request, crate::world::wall_clock().unwrap_or(0))
            });
        });
    }
}

// ---------------------------------------------------------------- seller side

/// What the relayer answered for a request, before anything is believed.
pub trait RelayApi: Send + Sync {
    /// Ask for `data` to be sent to `to` on `chain_id`; the first hash.
    /// `claims` names the claim transactions a transfer is bounded by (T-6);
    /// empty for a vault call.
    fn submit(&self, chain_id: u64, to: Address, data: &[u8], claims: &[String]) -> Res<String>;
    /// Every hash the relayer says it used for the request `first`.
    fn hashes(&self, first: &str) -> Res<Vec<String>>;
}

/// The seller's HTTP client: a fresh DPoP proof on every request.
pub struct RelayClient {
    pub url: String,
    key: p256::ecdsa::SigningKey,
    agent: ureq::Agent,
}
impl RelayClient {
    pub fn new(url: &str, key: p256::ecdsa::SigningKey) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            key,
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(60)))
                .build()
                .into(),
        }
    }
    fn ask(&self, method: &str, path: &str, body: Option<&[u8]>) -> Res<Value> {
        let target = format!("{}{path}", self.url);
        let now = crate::world::wall_clock()?;
        let proof = proof_make(&self.key, DPOP_TYP, method, &target, now, None, body)?;
        let mut response = match body {
            Some(body) => self
                .agent
                .post(&target)
                .header("dpop", &proof)
                .header("content-type", "application/json")
                .send(body)?,
            None => self.agent.get(&target).header("dpop", &proof).call()?,
        };
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_string()?;
        if !(200..300).contains(&status) {
            return Err(format!("relayer answered {status}: {}", text.trim()).into());
        }
        Ok(serde_json::from_str(&text)?)
    }
}
impl RelayApi for RelayClient {
    fn submit(&self, chain_id: u64, to: Address, data: &[u8], claims: &[String]) -> Res<String> {
        let mut body =
            json!({"chainId": chain_id, "to": hex(&to), "value": "0", "data": hex(data)});
        if !claims.is_empty() {
            body["claims"] = json!(claims);
        }
        let body = body.to_string();
        let answer = self.ask("POST", "/relay", Some(body.as_bytes()))?;
        Ok(answer["transaction"]
            .as_str()
            .ok_or("relayer named no transaction")?
            .to_owned())
    }
    fn hashes(&self, first: &str) -> Res<Vec<String>> {
        let answer = self.ask("GET", &format!("/relay/{first}"), None)?;
        Ok(answer["transactions"]
            .as_array()
            .ok_or("relayer listed no transactions")?
            .iter()
            .filter_map(|hash| hash.as_str().map(str::to_owned))
            .collect())
    }
}

/// How the seller judged one relayed transaction (R-3).
#[derive(Debug, PartialEq, Eq)]
pub enum Seen {
    /// Not on chain yet, or not mined.
    NotYet,
    /// Mined, successful, and exactly the call asked for.
    Landed { gas: u64 },
    /// Mined and reverted.
    Reverted,
    /// The chain has a transaction under this hash, and it is not the call
    /// the seller asked for.
    OtherCall,
}

/// R-3: judge `hash` against the call the seller built.
pub fn judge(chain: &Chain, hash: &str, to: Address, data: &[u8]) -> Res<Seen> {
    let Some(Sent {
        to: sent_to,
        value,
        input,
    }) = chain.transaction(hash)?
    else {
        return Ok(Seen::NotYet);
    };
    if sent_to != Some(to) || value != 0 || input != data {
        return Ok(Seen::OtherCall);
    }
    Ok(match chain.receipt(hash)? {
        None => Seen::NotYet,
        Some(receipt) if receipt.success => Seen::Landed {
            gas: receipt.gas_used,
        },
        Some(_) => Seen::Reverted,
    })
}

/// How a call reached the chain.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivered {
    /// Through the relayer, in this transaction.
    Relayed { transaction: String, gas: u64 },
    /// Sent by the seller itself (R-4).
    OwnGas { transaction: String, gas: u64 },
    /// The effect was already on chain when the seller looked (R-4).
    AlreadyDone,
}
impl Delivered {
    pub fn transaction(&self) -> Option<&str> {
        match self {
            Self::Relayed { transaction, .. } | Self::OwnGas { transaction, .. } => {
                Some(transaction)
            }
            Self::AlreadyDone => None,
        }
    }
}

/// The seller's side of one call, R-1 to R-4. `until` is the wall-clock time
/// after which the seller stops waiting for the relayer; `done` reads the
/// call's effect from the chain; `own` sends the call with the seller's gas.
pub struct Submission<'a> {
    pub chain: &'a Chain,
    pub relayer: Option<&'a dyn RelayApi>,
    /// The call's target: the vault, or the token for a transfer.
    pub target: Address,
    pub data: &'a [u8],
    /// T-6: the claims a transfer names; empty for a vault call.
    pub claims: &'a [String],
    pub wait: Duration,
    pub until: Option<u64>,
    pub poll: Duration,
    pub label: &'a str,
}
impl Submission<'_> {
    pub fn run(
        &self,
        done: &dyn Fn() -> Res<bool>,
        own: &dyn Fn() -> Res<crate::chain::Receipt>,
    ) -> Res<Delivered> {
        if let Some(relayer) = self.relayer {
            match self.through(relayer) {
                Ok(Some(delivered)) => return Ok(delivered),
                Ok(None) => println!(
                    "seller: {}: the relayer did not deliver in time; checking the chain",
                    self.label
                ),
                Err(error) => println!(
                    "seller: {}: relayer refused or misbehaved ({error}); checking the chain",
                    self.label
                ),
            }
            if done()? {
                return Ok(Delivered::AlreadyDone);
            }
            println!("seller: {}: sending it with its own gas", self.label);
        }
        let receipt = own()?;
        if !receipt.success {
            return Err(format!("{} reverted", self.label).into());
        }
        Ok(Delivered::OwnGas {
            transaction: receipt.transaction,
            gas: receipt.gas_used,
        })
    }
    /// `Ok(None)`: nothing counted in time.
    fn through(&self, relayer: &dyn RelayApi) -> Res<Option<Delivered>> {
        let first = relayer.submit(self.chain.id, self.target, self.data, self.claims)?;
        println!("seller: {}: relayer sent {first}", self.label);
        let started = Instant::now();
        loop {
            // The relayer's list is a hint; the chain decides each hash.
            let mut hashes = relayer.hashes(&first).unwrap_or_default();
            if !hashes.contains(&first) {
                hashes.insert(0, first.clone());
            }
            for hash in &hashes {
                match judge(self.chain, hash, self.target, self.data)? {
                    Seen::Landed { gas } => {
                        return Ok(Some(Delivered::Relayed {
                            transaction: hash.clone(),
                            gas,
                        }));
                    }
                    Seen::OtherCall => {
                        return Err(format!(
                            "transaction {hash} is not the call this seller asked for"
                        )
                        .into());
                    }
                    Seen::Reverted => {
                        return Err(format!("relayed transaction {hash} reverted").into());
                    }
                    Seen::NotYet => {}
                }
            }
            let late = self
                .until
                .is_some_and(|until| crate::world::wall_clock().unwrap_or(u64::MAX) >= until);
            if started.elapsed() >= self.wait || late {
                return Ok(None);
            }
            std::thread::sleep(self.poll);
        }
    }
}

#[cfg(test)]
mod tests;
