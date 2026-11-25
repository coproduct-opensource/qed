//! The market: every post on the board, ours and anyone's, joined to the
//! vault orders that answer it, derived from chain events alone.
//! Model: proofs/commerce/Market.lean; findings:
//! docs/rfcs/qed-market-index-2026-11-25.md.
//!
//! Three parts:
//! * the model (`Market`, `apply`, `state`, rounds, `taken`), a mirror of
//!   the Lean file, whose golden tests replay its examples;
//! * the index (`Index`): the board's and vaults' events in chain order,
//!   with each order's `context` and `policyHash` decoded from the `fund`
//!   calldata (or from `settle`/`refund` when the fund call was not direct)
//!   and checked against the `Funded` digest. `scan` extends it from its
//!   cursor and rescans from the deploy blocks when it cannot resume;
//! * `filtered`: what may be published of it. Posters are shown by address
//!   (owner decision, 2026-11-25), except the authors' wallets other than
//!   the bounty buyer, the relayer and the ladder buyer, which need the
//!   authors' list to tell apart: without it every other poster is elided.
//!   Buyers, sellers, payees and senders other than those three are elided.
use crate::status::ELIDED;
use crate::{Res, hex, unhex};
use alloy_primitives::keccak256;
use alloy_sol_types::SolCall;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const SCHEMA: &str = "qed-market-index/1";
pub type Word = [u8; 32];

mod v3 {
    alloy_sol_types::sol! {
        struct Order { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; bytes32 base; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
        function fund(Order o, bytes authorization);
        function settle(Order o, bytes artifact, bytes seal);
        function refund(Order o);
    }
}
mod v2 {
    alloy_sol_types::sol! {
        struct Order { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
        function fund(Order o, bytes authorization);
        function settle(Order o, bytes artifact, bytes seal);
        function refund(Order o);
    }
}

/// `0x`-prefixed lower-case hex.
pub fn hx(bytes: &[u8]) -> String {
    format!("0x{}", hex(bytes))
}
/// A 32-byte word from hex; anything else is zero (joins nothing).
pub fn word(text: &str) -> Word {
    unhex(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; 32])
}

/// The `context` an order answering a post carries:
/// keccak256(keccak256("NucleusContextV1") ‖ id ‖ buyerKeyBinding), as
/// `vault_wire::context` and the agents' `board::context` compute it.
pub fn context(id: &Word, key_binding: &Word) -> Word {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(keccak256(b"NucleusContextV1").as_slice());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(key_binding);
    keccak256(&bytes).0
}

/// What a `Claimed` names for an order: its seller and asset as one key.
pub fn payee_key(payee: &[u8], asset: &[u8]) -> Word {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(payee);
    bytes.extend_from_slice(asset);
    keccak256(&bytes).0
}

// ---- The model (proofs/commerce/Market.lean) ---------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Funded,
    Refunded,
    Settled,
    Claimed,
}
impl Phase {
    pub fn rank(self) -> u8 {
        match self {
            Phase::Funded => 3,
            Phase::Refunded => 4,
            Phase::Settled => 5,
            Phase::Claimed => 6,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Phase::Funded => "funded",
            Phase::Refunded => "refunded",
            Phase::Settled => "settled",
            Phase::Claimed => "claimed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Listed,
    Expired,
    Withdrawn,
    Funded,
    Refunded,
    Settled,
    Claimed,
}
impl State {
    pub fn rank(self) -> u8 {
        self as u8
    }
    pub fn of_rank(n: u8) -> State {
        match n {
            0 => State::Listed,
            1 => State::Expired,
            2 => State::Withdrawn,
            3 => State::Funded,
            4 => State::Refunded,
            5 => State::Settled,
            _ => State::Claimed,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            State::Listed => "listed",
            State::Expired => "expired",
            State::Withdrawn => "withdrawn",
            State::Funded => "funded",
            State::Refunded => "refunded",
            State::Settled => "settled",
            State::Claimed => "claimed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelPost {
    pub id: Word,
    pub key_binding: Word,
    pub policy: Word,
    pub statement: Word,
    pub fund_by: u64,
    pub poster: String,
    pub block: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelOrder {
    pub digest: Word,
    pub context: Word,
    pub policy: Word,
    pub payee: Word,
    pub amount: u128,
    pub phase: Phase,
}

#[derive(Clone, Debug)]
pub enum ModelEvent {
    Posted(ModelPost),
    Withdrawn(Word),
    Funded {
        digest: Word,
        context: Word,
        policy: Word,
        payee: Word,
        amount: u128,
    },
    Settled(Word),
    Refunded(Word),
    Claimed(Word),
    Tick(u64),
}

#[derive(Clone, Debug, Default)]
pub struct Market {
    pub posts: Vec<ModelPost>,
    pub withdrawn: Vec<Word>,
    pub orders: Vec<ModelOrder>,
    pub now: u64,
}

/// A round: its budget and task count, and which posts are its.
pub struct Round<'a> {
    pub budget: u128,
    pub tasks: u64,
    pub member: &'a dyn Fn(&ModelPost) -> bool,
}

impl Market {
    pub fn joins(p: &ModelPost, o: &ModelOrder) -> bool {
        o.context == context(&p.id, &p.key_binding) && o.policy == p.policy
    }

    /// `Market.apply`.
    pub fn apply(&mut self, e: &ModelEvent) {
        match e {
            ModelEvent::Posted(p) => {
                if !self.posts.iter().any(|q| q.id == p.id) {
                    self.posts.push(p.clone());
                }
            }
            ModelEvent::Withdrawn(id) => self.withdrawn.push(*id),
            ModelEvent::Funded {
                digest,
                context,
                policy,
                payee,
                amount,
            } => {
                if !self.orders.iter().any(|o| o.digest == *digest) {
                    self.orders.push(ModelOrder {
                        digest: *digest,
                        context: *context,
                        policy: *policy,
                        payee: *payee,
                        amount: *amount,
                        phase: Phase::Funded,
                    });
                }
            }
            ModelEvent::Settled(d) | ModelEvent::Refunded(d) => {
                let to = if matches!(e, ModelEvent::Settled(_)) {
                    Phase::Settled
                } else {
                    Phase::Refunded
                };
                for o in &mut self.orders {
                    if o.digest == *d && o.phase == Phase::Funded {
                        o.phase = to;
                    }
                }
            }
            ModelEvent::Claimed(payee) => {
                for o in &mut self.orders {
                    if o.payee == *payee && o.phase == Phase::Settled {
                        o.phase = Phase::Claimed;
                    }
                }
            }
            ModelEvent::Tick(n) => self.now = self.now.max(*n),
        }
    }

    pub fn replay<'a>(events: impl IntoIterator<Item = &'a ModelEvent>) -> Market {
        let mut m = Market::default();
        for e in events {
            m.apply(e);
        }
        m
    }

    fn base(&self, p: &ModelPost) -> u8 {
        if self.withdrawn.contains(&p.id) {
            2
        } else if p.fund_by < self.now {
            1
        } else {
            0
        }
    }

    /// The furthest phase any joined order reached; 0 when none joined.
    pub fn top(&self, p: &ModelPost) -> u8 {
        self.orders
            .iter()
            .filter(|o| Self::joins(p, o))
            .map(|o| o.phase.rank())
            .max()
            .unwrap_or(0)
    }

    pub fn rank_of(&self, p: &ModelPost) -> u8 {
        self.base(p).max(self.top(p))
    }

    pub fn state(&self, p: &ModelPost) -> State {
        State::of_rank(self.rank_of(p))
    }

    /// The orders joined to a post, in funding order.
    pub fn joined<'a>(&'a self, p: &'a ModelPost) -> impl Iterator<Item = &'a ModelOrder> + 'a {
        self.orders.iter().filter(move |o| Self::joins(p, o))
    }

    pub fn taken(&self, statement: &Word) -> bool {
        self.posts
            .iter()
            .any(|p| p.statement == *statement && self.rank_of(p) >= 5)
    }

    fn in_round(&self, r: &Round, o: &ModelOrder) -> bool {
        self.posts
            .iter()
            .any(|p| (r.member)(p) && Self::joins(p, o))
    }
    pub fn funded_amount(&self, r: &Round) -> u128 {
        self.orders
            .iter()
            .filter(|o| self.in_round(r, o))
            .map(|o| o.amount)
            .sum()
    }
    pub fn refund_amount(&self, r: &Round) -> u128 {
        self.orders
            .iter()
            .filter(|o| self.in_round(r, o) && o.phase == Phase::Refunded)
            .map(|o| o.amount)
            .sum()
    }
    pub fn funded_tasks(&self, r: &Round) -> u64 {
        self.orders.iter().filter(|o| self.in_round(r, o)).count() as u64
    }
    pub fn refund_tasks(&self, r: &Round) -> u64 {
        self.orders
            .iter()
            .filter(|o| self.in_round(r, o) && o.phase == Phase::Refunded)
            .count() as u64
    }
    /// budget − (funded − refunded); `None` when the round broke its
    /// commitment (funded more than its budget net of refunds), which the
    /// page then says instead of a truncated zero.
    pub fn remaining(&self, r: &Round) -> Option<u128> {
        let spent = self.funded_amount(r) - self.refund_amount(r);
        r.budget.checked_sub(spent)
    }
    pub fn remaining_tasks(&self, r: &Round) -> Option<u64> {
        let used = self.funded_tasks(r) - self.refund_tasks(r);
        r.tasks.checked_sub(used)
    }
}

// ---- The index ----------------------------------------------------------------

/// An order's terms, decoded from a direct `fund`, `settle` or `refund` call
/// whose recomputed EIP-712 digest equals the logged one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Terms {
    /// `fund`, `settle` or `refund`: which call carried them.
    pub from: String,
    pub context: String,
    pub policy_hash: String,
    pub program: String,
    pub verifier: String,
    pub fund_by: u64,
    pub deliver_by: u64,
    pub salt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all_fields = "camelCase")]
pub enum Event {
    Posted {
        id: String,
        poster: String,
        vault: String,
        statement_sha256: String,
        statement_blake3: String,
        policy_hash: String,
        asset: String,
        maximum_amount: String,
        verifier: String,
        program: String,
        fund_by: u64,
        deliver_by: u64,
        buyer_node: String,
        buyer_key_binding: String,
        salt: String,
        buyer_address: String,
    },
    Withdrawn {
        id: String,
    },
    Funded {
        digest: String,
        buyer: String,
        seller: String,
        asset: String,
        amount: String,
        payee_key: String,
        terms: Option<Terms>,
    },
    Settled {
        digest: String,
        artifact_hash: String,
        seller_owed: String,
        fee_owed: String,
        royalty_payee: String,
        royalty_owed: String,
    },
    Refunded {
        digest: String,
        buyer: String,
        amount: String,
    },
    Claimed {
        payee: String,
        asset: String,
        amount: String,
        payee_key: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Logged {
    pub block: u64,
    pub log_index: u64,
    pub transaction: String,
    /// The contract that emitted it.
    pub contract: String,
    /// Who sent the transaction (vault events only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_by: Option<String>,
    #[serde(flatten)]
    pub event: Event,
}

/// What the last scan did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanNote {
    /// `full` or `incremental`.
    pub kind: String,
    /// Why a full scan, when it was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    pub from: u64,
    pub to: u64,
    /// JSON-RPC calls made.
    pub calls: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Index {
    pub schema: String,
    pub chain_id: u64,
    pub board: String,
    pub vaults: Vec<String>,
    /// Every block up to and including this one is in `events`.
    pub cursor: u64,
    pub cursor_hash: String,
    /// The cursor block's timestamp.
    pub cursor_time: u64,
    /// True when addresses were filtered for publication: such an index
    /// cannot be resumed (claims match on full payees) and is rescanned.
    pub filtered: bool,
    pub scan: ScanNote,
    pub events: Vec<Logged>,
}

/// What the scan reads: the board, the vaults (address, deploy block) and
/// the most blocks one `eth_getLogs` may span.
pub struct Chain {
    pub chain_id: u64,
    pub board: String,
    pub board_from: u64,
    pub vaults: Vec<(String, u64)>,
    pub range: u64,
}

/// One JSON-RPC call: (method, params) → result.
pub type Rpc<'a> = dyn FnMut(&str, Value) -> Res<Value> + 'a;

fn quantity(v: &Value) -> Res<u64> {
    let s = v.as_str().ok_or("quantity is not a string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}
fn word_u128(w: &[u8]) -> Res<u128> {
    if w.len() != 32 || w[..16].iter().any(|b| *b != 0) {
        return Err("amount does not fit in 128 bits".into());
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&w[16..]);
    Ok(u128::from_be_bytes(a))
}
fn addr_of_word(w: &[u8]) -> String {
    hx(&w[12..32])
}
fn topic(signature: &str) -> Word {
    keccak256(signature.as_bytes()).0
}

/// The EIP-712 digest of a third-version order (domain version "3").
fn digest3(chain: u64, vault: &[u8; 20], o: &v3::Order) -> Word {
    let mut w = Words::default();
    w.hash(
        keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .0,
    );
    w.hash(keccak256(b"NucleusVault").0);
    w.hash(keccak256(b"3").0);
    w.uint(u128::from(chain));
    w.addr(vault);
    let domain = keccak256(&w.0).0;
    let mut m = Words::default();
    m.hash(keccak256(b"Order(address buyer,address seller,address asset,uint256 amount,address verifier,bytes32 program,bytes32 policyHash,bytes32 base,uint64 fundBy,uint64 deliverBy,bytes32 salt,bytes32 context)").0);
    m.addr(&o.buyer.0.0);
    m.addr(&o.seller.0.0);
    m.addr(&o.asset.0.0);
    m.hash(o.amount.to_be_bytes());
    m.addr(&o.verifier.0.0);
    m.hash(o.program.0);
    m.hash(o.policyHash.0);
    m.hash(o.base.0);
    m.uint(u128::from(o.fundBy));
    m.uint(u128::from(o.deliverBy));
    m.hash(o.salt.0);
    m.hash(o.context.0);
    let message = keccak256(&m.0).0;
    let mut bytes = vec![0x19, 0x01];
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&message);
    keccak256(&bytes).0
}
/// The EIP-712 digest of a second-version order (domain version "1").
fn digest2(chain: u64, vault: &[u8; 20], o: &v2::Order) -> Word {
    let mut w = Words::default();
    w.hash(
        keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .0,
    );
    w.hash(keccak256(b"NucleusVault").0);
    w.hash(keccak256(b"1").0);
    w.uint(u128::from(chain));
    w.addr(vault);
    let domain = keccak256(&w.0).0;
    let mut m = Words::default();
    m.hash(keccak256(b"Order(address buyer,address seller,address asset,uint256 amount,address verifier,bytes32 program,bytes32 policyHash,uint64 fundBy,uint64 deliverBy,bytes32 salt,bytes32 context)").0);
    m.addr(&o.buyer.0.0);
    m.addr(&o.seller.0.0);
    m.addr(&o.asset.0.0);
    m.hash(o.amount.to_be_bytes());
    m.addr(&o.verifier.0.0);
    m.hash(o.program.0);
    m.hash(o.policyHash.0);
    m.uint(u128::from(o.fundBy));
    m.uint(u128::from(o.deliverBy));
    m.hash(o.salt.0);
    m.hash(o.context.0);
    let message = keccak256(&m.0).0;
    let mut bytes = vec![0x19, 0x01];
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&message);
    keccak256(&bytes).0
}
#[derive(Default)]
struct Words(Vec<u8>);
impl Words {
    fn hash(&mut self, w: Word) {
        self.0.extend_from_slice(&w);
    }
    fn uint(&mut self, v: u128) {
        self.0.extend_from_slice(&[0u8; 16]);
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn addr(&mut self, a: &[u8; 20]) {
        self.0.extend_from_slice(&[0u8; 12]);
        self.0.extend_from_slice(a);
    }
}

/// The order a direct vault call carries, when its digest is `digest`.
pub fn terms_from_call(
    chain: u64,
    vault: &[u8; 20],
    calldata: &[u8],
    digest: &Word,
) -> Option<Terms> {
    let three = |o: v3::Order, from: &str| {
        (digest3(chain, vault, &o) == *digest).then(|| Terms {
            from: from.into(),
            context: hx(&o.context.0),
            policy_hash: hx(&o.policyHash.0),
            program: hx(&o.program.0),
            verifier: hx(o.verifier.as_slice()),
            fund_by: o.fundBy,
            deliver_by: o.deliverBy,
            salt: hx(&o.salt.0),
        })
    };
    let two = |o: v2::Order, from: &str| {
        (digest2(chain, vault, &o) == *digest).then(|| Terms {
            from: from.into(),
            context: hx(&o.context.0),
            policy_hash: hx(&o.policyHash.0),
            program: hx(&o.program.0),
            verifier: hx(o.verifier.as_slice()),
            fund_by: o.fundBy,
            deliver_by: o.deliverBy,
            salt: hx(&o.salt.0),
        })
    };
    if let Ok(c) = v3::fundCall::abi_decode(calldata) {
        return three(c.o, "fund");
    }
    if let Ok(c) = v3::settleCall::abi_decode(calldata) {
        return three(c.o, "settle");
    }
    if let Ok(c) = v3::refundCall::abi_decode(calldata) {
        return three(c.o, "refund");
    }
    if let Ok(c) = v2::fundCall::abi_decode(calldata) {
        return two(c.o, "fund");
    }
    if let Ok(c) = v2::settleCall::abi_decode(calldata) {
        return two(c.o, "settle");
    }
    if let Ok(c) = v2::refundCall::abi_decode(calldata) {
        return two(c.o, "refund");
    }
    None
}

/// Decode one log of the board or a vault. `tx` is the transaction that
/// emitted it (`eth_getTransactionByHash`), needed for vault logs.
pub fn decode(chain: u64, log: &Value, tx: Option<&Value>) -> Res<Logged> {
    let contract = log["address"]
        .as_str()
        .ok_or("log address")?
        .to_ascii_lowercase();
    let topics: Vec<Word> = log["topics"]
        .as_array()
        .ok_or("log topics")?
        .iter()
        .map(|t| -> Res<Word> {
            unhex(t.as_str().unwrap_or(""))?
                .try_into()
                .map_err(|_| "topic length".into())
        })
        .collect::<Res<_>>()?;
    let data = unhex(log["data"].as_str().unwrap_or("0x"))?;
    let transaction = log["transactionHash"]
        .as_str()
        .ok_or("log transaction")?
        .to_ascii_lowercase();
    let block = quantity(&log["blockNumber"])?;
    let log_index = quantity(&log["logIndex"])?;
    let first = topics.first().copied().unwrap_or([0; 32]);
    let words: Vec<&[u8]> = data.chunks(32).collect();
    let sent_by = tx
        .and_then(|t| t["from"].as_str())
        .map(str::to_ascii_lowercase);
    let event = if first == nucleus_board_reference::posted_topic()
        || first == nucleus_board_reference::withdrawn_topic()
    {
        match nucleus_board_reference::decode_log(&topics, &data)
            .map_err(|e| format!("board log in {transaction}: {e:?}"))?
        {
            nucleus_board_reference::Notice::Posted(p) => {
                let t = &p.task;
                Event::Posted {
                    id: hx(&p.id),
                    poster: hx(&p.poster),
                    vault: hx(&p.vault),
                    statement_sha256: hx(&t.statement_sha256),
                    statement_blake3: hx(&t.statement_blake3),
                    policy_hash: hx(&t.policy_hash),
                    asset: hx(&t.asset),
                    maximum_amount: alloy_primitives::U256::from_be_bytes(t.maximum_amount)
                        .to_string(),
                    verifier: hx(&t.verifier),
                    program: hx(&t.program),
                    fund_by: t.fund_by,
                    deliver_by: t.deliver_by,
                    buyer_node: hx(&t.buyer_node),
                    buyer_key_binding: hx(&t.buyer_key_binding),
                    salt: hx(&t.salt),
                    buyer_address: t.buyer_address.clone(),
                }
            }
            nucleus_board_reference::Notice::Withdrawn(id) => Event::Withdrawn { id: hx(&id) },
        }
    } else if first == topic("Funded(bytes32,address,address,address,uint256)")
        && topics.len() == 4
        && words.len() == 2
    {
        let digest = topics[1];
        let seller = &topics[3][12..];
        let asset = &words[0][12..];
        let vault: [u8; 20] = unhex(&contract)?.try_into().map_err(|_| "vault address")?;
        let terms = tx.and_then(|t| {
            let to = t["to"].as_str()?.to_ascii_lowercase();
            (to == contract).then_some(())?;
            let input = unhex(t["input"].as_str()?).ok()?;
            terms_from_call(chain, &vault, &input, &digest)
        });
        Event::Funded {
            digest: hx(&digest),
            buyer: addr_of_word(&topics[2]),
            seller: hx(seller),
            asset: hx(asset),
            amount: word_u128(words[1])?.to_string(),
            payee_key: hx(&payee_key(seller, asset)),
            terms,
        }
    } else if first == topic("Settled(bytes32,bytes32,uint256,uint256,address,uint256)")
        && topics.len() == 2
        && words.len() == 5
    {
        Event::Settled {
            digest: hx(&topics[1]),
            artifact_hash: hx(words[0]),
            seller_owed: word_u128(words[1])?.to_string(),
            fee_owed: word_u128(words[2])?.to_string(),
            royalty_payee: addr_of_word(words[3]),
            royalty_owed: word_u128(words[4])?.to_string(),
        }
    } else if first == topic("Refunded(bytes32,address,uint256)")
        && topics.len() == 3
        && words.len() == 1
    {
        Event::Refunded {
            digest: hx(&topics[1]),
            buyer: addr_of_word(&topics[2]),
            amount: word_u128(words[0])?.to_string(),
        }
    } else if first == topic("Claimed(address,address,uint256)")
        && topics.len() == 3
        && words.len() == 1
    {
        let payee = &topics[1][12..];
        let asset = &topics[2][12..];
        Event::Claimed {
            payee: hx(payee),
            asset: hx(asset),
            amount: word_u128(words[0])?.to_string(),
            payee_key: hx(&payee_key(payee, asset)),
        }
    } else {
        return Err(format!("unknown log from {contract} in {transaction}").into());
    };
    let is_vault = !matches!(event, Event::Posted { .. } | Event::Withdrawn { .. });
    Ok(Logged {
        block,
        log_index,
        transaction,
        contract,
        sent_by: if is_vault { sent_by } else { None },
        event,
    })
}

/// Extend `prev` to `head`, or scan from the deploy blocks when it cannot
/// be resumed: absent, another schema or deployment, filtered, ahead of
/// `head`, or its cursor block's hash no longer on the chain (a reorg).
/// Returns the index and the reads made, as the status page records them.
pub fn scan(
    rpc: &mut Rpc,
    chain: &Chain,
    prev: Option<&Index>,
    head: u64,
    head_hash: &str,
    head_time: u64,
) -> Res<(Index, Vec<Value>)> {
    let mut reads = Vec::new();
    let mut calls = 0u64;
    let mut call = |method: &str, params: Value, reads: &mut Vec<Value>, id: String| {
        calls += 1;
        let result = rpc(method, params.clone())?;
        if method == "eth_getLogs" {
            reads.push(json!({
                "id": id, "what": "the board's and vaults' events", "method": method,
                "params": params,
                "result": format!("{} logs", result.as_array().map_or(0, Vec::len)),
            }));
        }
        Ok::<Value, Box<dyn std::error::Error>>(result)
    };
    let vaults: Vec<String> = chain
        .vaults
        .iter()
        .map(|(a, _)| a.to_ascii_lowercase())
        .collect();
    let board = chain.board.to_ascii_lowercase();
    let deploy = chain
        .vaults
        .iter()
        .map(|(_, b)| *b)
        .chain([chain.board_from])
        .min()
        .unwrap_or(chain.board_from);
    let resume: Result<&Index, String> = match prev {
        None => Err("no earlier index".into()),
        Some(p) if p.schema != SCHEMA => Err(format!("schema {}", p.schema)),
        Some(p) if p.chain_id != chain.chain_id || p.board != board || p.vaults != vaults => {
            Err("another deployment".into())
        }
        Some(p) if p.filtered => Err("the earlier index was filtered for publication".into()),
        Some(p) if p.cursor > head => Err(format!("cursor {} is ahead of head {head}", p.cursor)),
        Some(p) => {
            let at = call(
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", p.cursor), false]),
                &mut reads,
                String::new(),
            )?;
            if at["hash"].as_str().map(str::to_ascii_lowercase).as_deref()
                == Some(p.cursor_hash.as_str())
            {
                Ok(p)
            } else {
                Err(format!("block {} has another hash now", p.cursor))
            }
        }
    };
    let (mut events, from, kind, why) = match resume {
        Ok(p) => (p.events.clone(), p.cursor + 1, "incremental", None),
        Err(why) => (Vec::new(), deploy, "full", Some(why)),
    };
    let mut addresses = vec![board.clone()];
    addresses.extend(vaults.iter().cloned());
    let mut start = from;
    let mut part = 0;
    let mut logs = Vec::new();
    while start <= head {
        let end = head.min(start + chain.range - 1);
        let filter = json!([{"address": addresses, "fromBlock": format!("0x{start:x}"), "toBlock": format!("0x{end:x}")}]);
        let got = call(
            "eth_getLogs",
            filter,
            &mut reads,
            format!("market-logs-{part}"),
        )?;
        for log in got.as_array().cloned().unwrap_or_default() {
            let a = log["address"].as_str().unwrap_or("").to_ascii_lowercase();
            if addresses.contains(&a) && log["removed"] != json!(true) {
                logs.push(log);
            }
        }
        start = end + 1;
        part += 1;
    }
    let mut new = Vec::new();
    for log in &logs {
        let a = log["address"].as_str().unwrap_or("").to_ascii_lowercase();
        let tx = if a == board {
            None
        } else {
            let hash = log["transactionHash"].as_str().ok_or("log transaction")?;
            Some(call(
                "eth_getTransactionByHash",
                json!([hash]),
                &mut reads,
                String::new(),
            )?)
        };
        new.push((decode(chain.chain_id, log, tx.as_ref())?, tx));
    }
    new.sort_by_key(|(l, _)| (l.block, l.log_index));
    for (logged, tx) in new {
        // A Funded whose fund call was not direct: take the order from
        // this settle or refund call when it is one.
        if let (Event::Settled { digest, .. } | Event::Refunded { digest, .. }, Some(tx)) =
            (&logged.event, &tx)
        {
            let calldata = tx["input"].as_str().and_then(|i| unhex(i).ok());
            let to = tx["to"].as_str().map(str::to_ascii_lowercase);
            if let (Some(input), Some(to)) = (calldata, to) {
                for earlier in events.iter_mut() {
                    if let Event::Funded {
                        digest: d,
                        terms: terms @ None,
                        ..
                    } = &mut earlier.event
                        && d == digest
                        && to == logged.contract
                    {
                        let vault: [u8; 20] =
                            unhex(&to)?.try_into().map_err(|_| "vault address")?;
                        *terms = terms_from_call(chain.chain_id, &vault, &input, &word(digest));
                    }
                }
            }
        }
        events.push(logged);
    }
    Ok((
        Index {
            schema: SCHEMA.into(),
            chain_id: chain.chain_id,
            board,
            vaults,
            cursor: head,
            cursor_hash: head_hash.to_ascii_lowercase(),
            cursor_time: head_time,
            filtered: false,
            scan: ScanNote {
                kind: kind.into(),
                why,
                from,
                to: head,
                calls,
            },
            events,
        },
        reads,
    ))
}

/// The deployment the index reads, from the input's main network.
pub fn chain_of(input: &crate::Input) -> Res<Chain> {
    let m = input
        .mainnet
        .as_ref()
        .ok_or("the input has no main network")?;
    let st = m
        .status
        .as_ref()
        .ok_or("the input's main network has no status block")?;
    Ok(Chain {
        chain_id: m.network.chain_id,
        board: m.board.address.clone(),
        board_from: m.board.deploy_block.ok_or("board deploy block")?,
        vaults: st
            .vaults
            .iter()
            .map(|v| (v.address.clone(), v.deploy_block))
            .collect(),
        range: m.network.log_range.unwrap_or(10_000),
    })
}

/// Read the head, then `scan` to it: `nucleus-site market-capture`.
pub fn read(rpc: &mut Rpc, chain: &Chain, prev: Option<&Index>) -> Res<(Index, Vec<Value>)> {
    let id = quantity(&rpc("eth_chainId", json!([]))?)?;
    if id != chain.chain_id {
        return Err(format!("the endpoint serves chain {id}, not {}", chain.chain_id).into());
    }
    let head = quantity(&rpc("eth_blockNumber", json!([]))?)?;
    let header = rpc(
        "eth_getBlockByNumber",
        json!([format!("0x{head:x}"), false]),
    )?;
    let hash = header["hash"].as_str().ok_or("block hash")?.to_owned();
    scan(
        rpc,
        chain,
        prev,
        head,
        &hash,
        quantity(&header["timestamp"])?,
    )
}

// ---- Replay ---------------------------------------------------------------

/// The model's events for an index, with a tick at `now`.
pub fn model_events(index: &Index, now: u64) -> Vec<ModelEvent> {
    let mut out: Vec<ModelEvent> = index
        .events
        .iter()
        .map(|l| match &l.event {
            Event::Posted {
                id,
                poster,
                statement_sha256,
                policy_hash,
                fund_by,
                buyer_key_binding,
                ..
            } => ModelEvent::Posted(ModelPost {
                id: word(id),
                key_binding: word(buyer_key_binding),
                policy: word(policy_hash),
                statement: word(statement_sha256),
                fund_by: *fund_by,
                poster: poster.clone(),
                block: l.block,
            }),
            Event::Withdrawn { id } => ModelEvent::Withdrawn(word(id)),
            Event::Funded {
                digest,
                amount,
                payee_key,
                terms,
                ..
            } => ModelEvent::Funded {
                digest: word(digest),
                // Undecodable terms join nothing.
                context: terms.as_ref().map_or([0; 32], |t| word(&t.context)),
                policy: terms.as_ref().map_or([0; 32], |t| word(&t.policy_hash)),
                payee: word(payee_key),
                amount: amount.parse().unwrap_or(0),
            },
            Event::Settled { digest, .. } => ModelEvent::Settled(word(digest)),
            Event::Refunded { digest, .. } => ModelEvent::Refunded(word(digest)),
            Event::Claimed { payee_key, .. } => ModelEvent::Claimed(word(payee_key)),
        })
        .collect();
    out.push(ModelEvent::Tick(now));
    out
}

// ---- Publication ----------------------------------------------------------

/// Which addresses may be shown.
#[derive(Clone, Debug, Default)]
pub struct Names {
    /// The bounty buyer, the relayer and the ladder buyer, lower case.
    pub published: Vec<String>,
    /// The authors' wallets, when the reader holds the list
    /// (`AUTHORS_FILE`); `None`: every other poster is elided too.
    pub authors: Option<BTreeSet<String>>,
}

/// The authors' wallet list, one address per line, `#` for comments. Kept
/// beside the input (for `snapshot-status`) or in the reader's state
/// directory (`refresh-status`); never committed.
pub const AUTHORS_FILE: &str = "authors-wallets.txt";

impl Names {
    pub fn read_authors(path: &std::path::Path) -> Res<Option<BTreeSet<String>>> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut set = BTreeSet::new();
                for line in text.lines() {
                    let line = line.split('#').next().unwrap_or("").trim();
                    if line.is_empty() {
                        continue;
                    }
                    let a = line.to_ascii_lowercase();
                    if a.len() != 42 || !a.starts_with("0x") || unhex(&a).is_err() {
                        return Err(format!("{}: not an address: {line}", path.display()).into());
                    }
                    set.insert(a);
                }
                Ok(Some(set))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display()).into()),
        }
    }
    /// A party other than a poster: one of the three, or elided.
    pub fn party(&self, a: &str) -> String {
        let a = a.to_ascii_lowercase();
        if self.published.contains(&a) {
            a
        } else {
            ELIDED.into()
        }
    }
    /// A poster: one of the three, anyone outside the authors' list, or
    /// elided when the list is not held.
    pub fn poster(&self, a: &str) -> String {
        let a = a.to_ascii_lowercase();
        if self.published.contains(&a) {
            return a;
        }
        match &self.authors {
            Some(authors) if !authors.contains(&a) && a != ELIDED => a,
            _ => ELIDED.into(),
        }
    }
}

/// The three published wallets from the input, and the authors' list
/// from `dir/authors-wallets.txt` when it is there.
pub fn names(input: &crate::Input, dir: &std::path::Path) -> Res<Names> {
    let mut published = Vec::new();
    if let Some(st) = input.mainnet.as_ref().and_then(|m| m.status.as_ref())
        && st.publish_wallets
    {
        published.push(st.buyer.to_ascii_lowercase());
        published.push(st.relayer.to_ascii_lowercase());
        if let Some(l) = &st.ladder_buyer {
            published.push(l.to_ascii_lowercase());
        }
    }
    Ok(Names {
        published,
        authors: Names::read_authors(&dir.join(AUTHORS_FILE))?,
    })
}

/// The index as it may be published: addresses filtered by `names`.
pub fn filtered(index: &Index, names: &Names) -> Index {
    if index.filtered {
        return index.clone();
    }
    let mut out = index.clone();
    out.filtered = true;
    for l in &mut out.events {
        l.sent_by = l.sent_by.as_deref().map(|a| names.party(a));
        match &mut l.event {
            Event::Posted {
                poster,
                buyer_address,
                ..
            } => {
                let shown = names.poster(poster);
                *buyer_address = if buyer_address.is_empty() {
                    String::new()
                } else if buyer_address.eq_ignore_ascii_case(poster) && shown != ELIDED {
                    shown.clone()
                } else {
                    ELIDED.into()
                };
                *poster = shown;
            }
            Event::Funded { buyer, seller, .. } => {
                *buyer = names.party(buyer);
                *seller = names.party(seller);
            }
            Event::Settled { royalty_payee, .. } => {
                if royalty_payee
                    .trim_start_matches("0x")
                    .bytes()
                    .any(|b| b != b'0')
                {
                    *royalty_payee = names.party(royalty_payee);
                }
            }
            Event::Refunded { buyer, .. } => *buyer = names.party(buyer),
            Event::Claimed { payee, .. } => *payee = names.party(payee),
            Event::Withdrawn { .. } => {}
        }
    }
    out
}

/// Posters a filtered index shows by address (lower case, without `0x`).
pub fn shown_posters(index: &Index) -> BTreeSet<String> {
    index
        .events
        .iter()
        .filter_map(|l| match &l.event {
            Event::Posted { poster, .. } if poster != ELIDED => {
                Some(poster.trim_start_matches("0x").to_owned())
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[path = "market/tests.rs"]
mod tests;
