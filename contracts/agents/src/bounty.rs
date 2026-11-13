//! A standing bounty: a buyer that keeps one small task posted, within fixed
//! limits, and remembers what it did in an append-only journal.
//!
//!   nucleus-buyer bounty DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX JOURNAL \
//!       PRICE BUDGET TASKS PAUSE_SECONDS POST_WINDOW_SECONDS BIND
//!
//! Semantics: docs/rfcs/proof-commerce-standing-bounty-2026-11-13.md.
//!
//! ```text
//! Idle ─intent journaled, then posted─▶ Posted ─desk signs first passing offer─▶ Signed
//!   ▲                                     │                                        │
//!   ├── funding deadline, nothing signed ─┘ (withdraw)        vault: settled ──▶ Settled
//!   │                                          funded, past delivery deadline ─▶ refund, claim ─▶ Refunded
//!   │                                          not funded, past funding deadline ─▶ Lapsed
//!   └──────────────── Settled | Refunded | Lapsed | Withdrawn ◀────────────────────┘
//! ```
//!
//! The rules live in two places. `Ledger::apply` admits only the moves in the
//! diagram, so a journal that records anything else does not replay. `run`
//! decides what to do next from the ledger and the chain, and nothing else.
//! Everything that touches a chain, a desk or a clock is behind `Market`, so
//! the rules are tested without any of them.
use crate::board::{self, Board, Task};
use crate::desk::{Desk, Posted};
use crate::iroh_net;
use crate::post::{phase_of, settled_artifact};
use crate::prelude::*;
use crate::world::*;
use nucleus_proof_acceptance::accept;
use nucleus_proof_commerce::{Hash, vault::wire::WireOrder};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// Fixed when the bounty starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Cap each post carries; no order above it is signed for.
    pub price: u64,
    /// The most the bounty may ever have paid.
    pub budget: u64,
    /// The most posts it may ever make.
    pub tasks: u32,
    /// Seconds between one task ending and the next post.
    pub pause: u64,
}

/// What the journal is about. A journal is never continued against another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub chain: u64,
    pub vault: Address,
    pub board: Address,
    pub token: Address,
    pub buyer: Address,
    /// The chain's height when the journal was opened.
    pub block: u64,
}

/// A task of this journal: its board ID and the terms it was posted with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRef {
    pub id: Hash,
    pub price: u64,
    pub fund_by: u64,
    pub deliver_by: u64,
    /// The task's salt, so a restarted process can rebuild the task and
    /// reopen its desk (R-3). `None` in intents journaled before R-3.
    pub salt: Option<Hash>,
}

/// Why a post was withdrawn, which decides whether it used up a task (R-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Withdrawal {
    /// Its whole funding window passed and nothing was signed. A task.
    WindowEnded,
    /// This buyer could not reopen its desk after a restart. Not a task.
    Unresumable(String),
    /// The operator closed the bounty. Not a task.
    Closed,
    /// Journaled before reasons were. Not a task: every such withdrawal on
    /// Base mainnet was one of the crash loop's four (RFC, "Mainnet crash
    /// loop, 2026-11-13").
    Unrecorded,
}
impl Withdrawal {
    fn to_json(&self) -> (Value, Value) {
        match self {
            Self::WindowEnded => (json!("window"), Value::Null),
            Self::Unresumable(why) => (json!("unresumable"), json!(why)),
            Self::Closed => (json!("closed"), Value::Null),
            Self::Unrecorded => (Value::Null, Value::Null),
        }
    }
    fn from_json(reason: &Value, why: &Value) -> Result<Self, String> {
        Ok(match reason.as_str() {
            None if reason.is_null() => Self::Unrecorded,
            Some("window") => Self::WindowEnded,
            Some("unresumable") => Self::Unresumable(text(why)?),
            Some("closed") => Self::Closed,
            _ => return Err(format!("unknown withdrawal reason {reason}")),
        })
    }
}

/// Whether a restarted process could reopen a post's desk (R-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resumption {
    Resumed,
    Unresumable(String),
}

/// What the bounty last knew about itself, for the status file (R-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// A transient failure; the same step runs again after `retry_in`.
    Degraded {
        error: String,
        failures: u32,
        retry_in: u64,
    },
    /// The process is about to exit with this error.
    Failed {
        error: String,
    },
}

/// An order this buyer signed one authorization for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderRef {
    pub digest: Hash,
    pub amount: u64,
    pub order: vault::Order,
}

/// One line of the journal.
#[derive(Clone, Debug, PartialEq, Eq)]
// One value per journal line, short-lived: boxing the order would only add noise.
#[allow(clippy::large_enum_variant)]
pub enum Entry {
    Opened(Header),
    /// Written before the post is sent, so a crash between the two is found.
    Intent(TaskRef),
    Posted {
        task: Hash,
        transaction: String,
    },
    /// Written by the desk before the authorization leaves it.
    Signed {
        task: Hash,
        order: OrderRef,
    },
    Settled {
        digest: Hash,
        paid: u64,
        checked: bool,
        block: u64,
    },
    Refunded {
        digest: Hash,
        block: u64,
    },
    Lapsed {
        digest: Hash,
        block: u64,
    },
    Withdrawn {
        task: Hash,
        transaction: String,
        block: u64,
        reason: Withdrawal,
    },
    /// An intent whose post never reached the board.
    Abandoned {
        task: Hash,
    },
    Stopped {
        reason: String,
    },
}

/// The task this journal has open, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
// One value at a time, short-lived: boxing the order would only add noise.
#[allow(clippy::large_enum_variant)]
pub enum Open {
    Intent(TaskRef),
    Posted(TaskRef),
    Signed(TaskRef, OrderRef),
}

/// Why a journal cannot be continued.
#[derive(Debug, PartialEq, Eq)]
pub enum Irreconcilable {
    /// A line that is not a journal event.
    Unreadable { line: usize, why: String },
    /// A move the state diagram does not allow.
    NotAMove { line: usize, why: &'static str },
    /// The journal is for another chain, vault, board, token or buyer.
    AnotherJournal,
    /// The journal says a task was posted and the board does not know it.
    PostMissing(Hash),
    /// The vault took a deposit from this buyer for an order the journal
    /// does not contain.
    UnknownDeposit(Hash),
}
impl std::fmt::Display for Irreconcilable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { line, why } => write!(f, "journal line {line} is unreadable: {why}"),
            Self::NotAMove { line, why } => write!(f, "journal line {line}: {why}"),
            Self::AnotherJournal => write!(
                f,
                "the journal is for another chain, vault, board, token or buyer"
            ),
            Self::PostMissing(id) => write!(
                f,
                "the journal says task {} was posted; the board does not know it",
                hex(id)
            ),
            Self::UnknownDeposit(digest) => write!(
                f,
                "the vault holds a deposit from this buyer for order {}, which this journal did not sign",
                hex(digest)
            ),
        }
    }
}
impl std::error::Error for Irreconcilable {}

/// Everything the journal says, as replaying it gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    pub header: Header,
    /// What the vault has paid out of this buyer's deposits for this journal.
    pub spent: u64,
    /// Posts made.
    pub posted: u32,
    /// Posts that used up a task: settled, refunded or lapsed orders, and
    /// posts withdrawn after their whole funding window (R-4).
    pub consumed: u32,
    /// Posts withdrawn because this buyer could not resume them.
    pub failures: u32,
    pub open: Option<Open>,
    /// Digests of every order this journal signed for.
    pub signed: Vec<Hash>,
    /// The height up to which the vault's deposits were compared with `signed`.
    pub checkpoint: u64,
    lines: usize,
}

impl Ledger {
    fn new(header: Header) -> Self {
        let checkpoint = header.block;
        Self {
            header,
            spent: 0,
            posted: 0,
            consumed: 0,
            failures: 0,
            open: None,
            signed: vec![],
            checkpoint,
            lines: 1,
        }
    }
    /// Admit one event, or say why the diagram does not allow it here.
    fn apply(&mut self, entry: &Entry) -> Result<(), &'static str> {
        let open = self.open.take();
        let next = match (entry, open) {
            (Entry::Opened(_), _) => return Err("a journal is opened once, on its first line"),
            (Entry::Stopped { .. }, open) => open,
            (Entry::Intent(task), None) => Some(Open::Intent(task.clone())),
            (Entry::Intent(_), Some(_)) => return Err("a task is posted while another is open"),
            (Entry::Posted { task, .. }, Some(Open::Intent(intent))) if *task == intent.id => {
                self.posted += 1;
                Some(Open::Posted(intent))
            }
            (Entry::Posted { .. }, _) => return Err("a post without its intent"),
            (Entry::Abandoned { task }, Some(Open::Intent(intent))) if *task == intent.id => None,
            (Entry::Abandoned { .. }, _) => return Err("only an intent is abandoned"),
            (Entry::Signed { task, order }, Some(Open::Posted(posted))) if *task == posted.id => {
                if order.amount > posted.price {
                    return Err("an order above the posted cap was signed for");
                }
                self.signed.push(order.digest);
                Some(Open::Signed(posted, order.clone()))
            }
            (Entry::Signed { .. }, _) => return Err("a signature for a task that is not posted"),
            (
                Entry::Withdrawn {
                    task,
                    block,
                    reason,
                    ..
                },
                Some(Open::Posted(posted)),
            ) if *task == posted.id => {
                match reason {
                    Withdrawal::WindowEnded => self.consumed += 1,
                    Withdrawal::Unresumable(_) => self.failures += 1,
                    Withdrawal::Closed | Withdrawal::Unrecorded => {}
                }
                self.checkpoint = self.checkpoint.max(*block);
                None
            }
            (Entry::Withdrawn { .. }, _) => return Err("only an unsigned post is withdrawn"),
            (
                Entry::Settled {
                    digest,
                    paid,
                    block,
                    ..
                },
                Some(Open::Signed(_, order)),
            ) if *digest == order.digest => {
                if *paid != order.amount {
                    return Err("a settlement pays the order's amount");
                }
                self.spent += paid;
                self.consumed += 1;
                self.checkpoint = self.checkpoint.max(*block);
                None
            }
            (Entry::Refunded { digest, block }, Some(Open::Signed(_, order)))
            | (Entry::Lapsed { digest, block }, Some(Open::Signed(_, order)))
                if *digest == order.digest =>
            {
                self.consumed += 1;
                self.checkpoint = self.checkpoint.max(*block);
                None
            }
            (Entry::Settled { .. } | Entry::Refunded { .. } | Entry::Lapsed { .. }, _) => {
                return Err("an outcome for an order that is not the open one");
            }
        };
        self.open = next;
        self.lines += 1;
        Ok(())
    }
}

fn hash_of(value: &Value) -> Result<Hash, String> {
    unhex(value.as_str().ok_or("hash expected")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "32 bytes expected".to_owned())
}
fn address_in(value: &Value) -> Result<Address, String> {
    unhex(value.as_str().ok_or("address expected")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "20 bytes expected".to_owned())
}
fn number(value: &Value) -> Result<u64, String> {
    value.as_u64().ok_or_else(|| "number expected".to_owned())
}
fn text(value: &Value) -> Result<String, String> {
    Ok(value.as_str().ok_or("text expected")?.to_owned())
}

impl Entry {
    pub fn to_json(&self) -> Value {
        match self {
            Self::Opened(h) => json!({
                "event": "opened", "chain": h.chain, "vault": hex(&h.vault), "board": hex(&h.board),
                "token": hex(&h.token), "buyer": hex(&h.buyer), "block": h.block,
            }),
            Self::Intent(t) => {
                let mut line = json!({
                    "event": "intent", "task": hex(&t.id), "price": t.price,
                    "fundBy": t.fund_by, "deliverBy": t.deliver_by,
                });
                if let Some(salt) = &t.salt {
                    line["salt"] = json!(hex(salt));
                }
                line
            }
            Self::Posted { task, transaction } => {
                json!({"event": "posted", "task": hex(task), "transaction": transaction})
            }
            Self::Signed { task, order } => json!({
                "event": "signed", "task": hex(task), "digest": hex(&order.digest),
                "amount": order.amount, "order": WireOrder::from_order(&order.order),
            }),
            Self::Settled {
                digest,
                paid,
                checked,
                block,
            } => json!({
                "event": "settled", "digest": hex(digest), "paid": paid,
                "checked": checked, "block": block,
            }),
            Self::Refunded { digest, block } => {
                json!({"event": "refunded", "digest": hex(digest), "block": block})
            }
            Self::Lapsed { digest, block } => {
                json!({"event": "lapsed", "digest": hex(digest), "block": block})
            }
            Self::Withdrawn {
                task,
                transaction,
                block,
                reason,
            } => {
                let mut line = json!({
                    "event": "withdrawn", "task": hex(task), "transaction": transaction, "block": block,
                });
                let (reason, why) = reason.to_json();
                if !reason.is_null() {
                    line["reason"] = reason;
                }
                if !why.is_null() {
                    line["why"] = why;
                }
                line
            }
            Self::Abandoned { task } => json!({"event": "abandoned", "task": hex(task)}),
            Self::Stopped { reason } => json!({"event": "stopped", "reason": reason}),
        }
    }
    pub fn from_json(v: &Value) -> Result<Self, String> {
        Ok(match v["event"].as_str().ok_or("event expected")? {
            "opened" => Self::Opened(Header {
                chain: number(&v["chain"])?,
                vault: address_in(&v["vault"])?,
                board: address_in(&v["board"])?,
                token: address_in(&v["token"])?,
                buyer: address_in(&v["buyer"])?,
                block: number(&v["block"])?,
            }),
            "intent" => Self::Intent(TaskRef {
                id: hash_of(&v["task"])?,
                price: number(&v["price"])?,
                fund_by: number(&v["fundBy"])?,
                deliver_by: number(&v["deliverBy"])?,
                salt: match v.get("salt") {
                    None | Some(Value::Null) => None,
                    Some(salt) => Some(hash_of(salt)?),
                },
            }),
            "posted" => Self::Posted {
                task: hash_of(&v["task"])?,
                transaction: text(&v["transaction"])?,
            },
            "signed" => {
                let wire: WireOrder =
                    serde_json::from_value(v["order"].clone()).map_err(|e| e.to_string())?;
                Self::Signed {
                    task: hash_of(&v["task"])?,
                    order: OrderRef {
                        digest: hash_of(&v["digest"])?,
                        amount: number(&v["amount"])?,
                        order: wire.to_order().map_err(|e| e.to_string())?,
                    },
                }
            }
            "settled" => Self::Settled {
                digest: hash_of(&v["digest"])?,
                paid: number(&v["paid"])?,
                checked: v["checked"].as_bool().ok_or("checked expected")?,
                block: number(&v["block"])?,
            },
            "refunded" => Self::Refunded {
                digest: hash_of(&v["digest"])?,
                block: number(&v["block"])?,
            },
            "lapsed" => Self::Lapsed {
                digest: hash_of(&v["digest"])?,
                block: number(&v["block"])?,
            },
            "withdrawn" => Self::Withdrawn {
                task: hash_of(&v["task"])?,
                transaction: text(&v["transaction"])?,
                block: number(&v["block"])?,
                reason: Withdrawal::from_json(&v["reason"], &v["why"])?,
            },
            "abandoned" => Self::Abandoned {
                task: hash_of(&v["task"])?,
            },
            "stopped" => Self::Stopped {
                reason: text(&v["reason"])?,
            },
            other => return Err(format!("unknown event {other:?}")),
        })
    }
}

/// Replay journal text. The first line must be `opened`.
pub fn replay(text: &str) -> Result<Ledger, Irreconcilable> {
    let mut ledger: Option<Ledger> = None;
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let unreadable = |why: String| Irreconcilable::Unreadable {
            line: line_number,
            why,
        };
        let value: Value = serde_json::from_str(line).map_err(|e| unreadable(e.to_string()))?;
        let entry = Entry::from_json(&value).map_err(unreadable)?;
        match (&mut ledger, entry) {
            (None, Entry::Opened(header)) => ledger = Some(Ledger::new(header)),
            (None, _) => {
                return Err(Irreconcilable::NotAMove {
                    line: line_number,
                    why: "the first line must open the journal",
                });
            }
            (Some(ledger), entry) => {
                ledger
                    .apply(&entry)
                    .map_err(|why| Irreconcilable::NotAMove {
                        line: line_number,
                        why,
                    })?
            }
        }
    }
    ledger.ok_or(Irreconcilable::NotAMove {
        line: 0,
        why: "the journal is empty",
    })
}

/// The journal file and what replaying it gives. Every event is one atomic
/// append followed by a sync (`nucleus_jsonl::append_line_synced`), and counts
/// only once that returned.
pub struct Journal {
    path: PathBuf,
    ledger: Ledger,
}
pub type Shared = Arc<Mutex<Journal>>;

/// One line, appended in one write and synced; an error unless the log's own
/// proof says this line at this path was kept.
fn append(path: &Path, line: &str) -> Res<()> {
    let kept = nucleus_jsonl::append_line_synced(path, line)?;
    if !kept.proves(path, line) {
        return Err("the journal did not keep the line it was given".into());
    }
    Ok(())
}

impl Journal {
    /// Open the journal at `path` for `header`, creating it if absent. An
    /// existing journal must have been opened for the same chain, vault,
    /// board, token and buyer.
    pub fn open(path: &Path, header: Header) -> Res<Self> {
        let existing = match fs::read_to_string(path) {
            Ok(text) if !text.is_empty() => Some(text),
            Ok(_) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let ledger = match existing {
            Some(text) => {
                let ledger = replay(&text)?;
                let (was, now) = (&ledger.header, &header);
                if (was.chain, was.vault, was.board, was.token, was.buyer)
                    != (now.chain, now.vault, now.board, now.token, now.buyer)
                {
                    return Err(Irreconcilable::AnotherJournal.into());
                }
                ledger
            }
            None => {
                append(path, &Entry::Opened(header.clone()).to_json().to_string())?;
                Ledger::new(header)
            }
        };
        Ok(Self {
            path: path.to_owned(),
            ledger,
        })
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    /// Admit an event and make it durable. An event the diagram does not
    /// allow is refused and nothing is written.
    pub fn record(&mut self, entry: Entry) -> Res<()> {
        let mut next = self.ledger.clone();
        next.apply(&entry)?;
        append(&self.path, &entry.to_json().to_string())?;
        self.ledger = next;
        Ok(())
    }
}

/// What the vault says about an order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Empty,
    Funded,
    Settled,
    Refunded,
}

/// Everything outside the rules: the chain, the board, the desk, the clock.
pub trait Market {
    fn now(&mut self) -> Res<u64>;
    fn block(&mut self) -> Res<u64>;
    /// The buyer's balance of the token.
    fn wallet(&mut self) -> Res<u64>;
    /// Choose the next task's terms. No effect on anything outside.
    fn prepare(&mut self, price: u64) -> Res<TaskRef>;
    /// Open the desk for the prepared task and post it. Returns the transaction.
    fn post(&mut self, task: &TaskRef) -> Res<String>;
    /// Whether the board holds this task as posted by this buyer.
    fn on_board(&mut self, task: Hash) -> Res<bool>;
    /// Whether this process holds the task's desk, open for offers.
    fn desk_open(&mut self, task: Hash) -> Res<bool>;
    /// Rebuild a posted, unsigned task from this process's configuration
    /// and the journaled salt, and reopen its desk (R-3).
    fn resume(&mut self, task: &TaskRef) -> Res<Resumption>;
    /// No transaction from this buyer is waiting to be mined.
    fn quiet(&mut self) -> Res<bool>;
    /// Keep the status file (R-5). Never fails the bounty.
    fn report(&mut self, health: &Health);
    /// Close the desk for the task. False if it had already been signed for.
    fn close_desk(&mut self, task: Hash) -> Res<bool>;
    /// Withdraw the post on the board if it is not withdrawn. Returns the
    /// transaction, or a note that it already was.
    fn withdraw(&mut self, task: Hash) -> Res<String>;
    fn phase(&mut self, order: &OrderRef) -> Res<Phase>;
    /// Take the settled artifact from the chain and run the Lean checker on
    /// it. `Ok(Err(why))` is the checker or the chain refusing it.
    fn check_settled(&mut self, order: &OrderRef) -> Res<Result<(), String>>;
    /// Call `refund` for a funded order past its delivery deadline.
    fn refund(&mut self, order: &OrderRef) -> Res<String>;
    /// Bring a refunded deposit back to the wallet, where the vault books
    /// refunds and pays them on claim. Returns a note of what was done.
    fn recover(&mut self) -> Res<String>;
    /// Digests of orders the vault took a deposit for from this buyer, in
    /// blocks `from..=to`.
    fn deposits(&mut self, from: u64, to: u64) -> Res<Vec<Hash>>;
    fn wait(&mut self, seconds: u64) -> Res<()>;
}

/// Why the bounty ended without an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    TaskLimit,
    Budget,
    /// The wallet cannot cover one more task.
    Wallet,
    /// As many posts were withdrawn for this buyer's own failures as the
    /// task limit: something needs the operator.
    Failures,
}
impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TaskLimit => write!(f, "the task limit is reached"),
            Self::Failures => write!(
                f,
                "as many posts were withdrawn because this buyer could not resume them as the task limit; stopping for the operator"
            ),
            Self::Budget => write!(f, "the budget does not cover another task"),
            Self::Wallet => write!(f, "the wallet does not cover another task"),
        }
    }
}

/// Seconds between looks at the chain while a task is open.
const POLL: u64 = 15;
/// Seconds before a step that failed transiently runs again: doubled after
/// each failure in a row, up to the most (R-2).
const RETRY_FIRST: u64 = 15;
const RETRY_MOST: u64 = 300;

fn locked(journal: &Shared) -> Res<std::sync::MutexGuard<'_, Journal>> {
    journal.lock().map_err(|_| "journal poisoned".into())
}

/// Every deposit the vault took from this buyer since the checkpoint must be
/// for an order this journal signed.
fn attribute(journal: &Shared, market: &mut dyn Market) -> Res<()> {
    let (from, known) = {
        let journal = locked(journal)?;
        (journal.ledger().checkpoint, journal.ledger().signed.clone())
    };
    let to = market.block()?;
    for digest in market.deposits(from, to)? {
        if !known.contains(&digest) {
            return Err(Irreconcilable::UnknownDeposit(digest).into());
        }
    }
    Ok(())
}

/// Run the bounty until a limit stops it. A transient failure (R-2) is
/// waited out and the same step run again; any other error leaves the
/// journal as it was after the last event, and running again continues
/// from there.
pub fn run(limits: Limits, journal: &Shared, market: &mut dyn Market) -> Res<Stop> {
    let mut attributed = false;
    let mut first = true;
    let mut failures: u32 = 0;
    loop {
        let outcome = if attributed {
            Ok(())
        } else {
            attribute(journal, market)
        }
        .and_then(|()| {
            attributed = true;
            step(limits, journal, market, first)
        });
        match outcome {
            Ok(stop) => {
                if failures > 0 {
                    println!("bounty: recovered: after {failures} transient failures in a row");
                    failures = 0;
                }
                market.report(&Health::Ok);
                if let Some(stop) = stop {
                    return Ok(stop);
                }
                first = false;
            }
            Err(error) if crate::chain::is_transient(&*error) => {
                failures += 1;
                let retry_in = RETRY_FIRST
                    .saturating_mul(1 << (failures - 1).min(5))
                    .min(RETRY_MOST);
                println!(
                    "bounty: degraded: {error}; the same step runs again in {retry_in} s (failure {failures} in a row)"
                );
                market.report(&Health::Degraded {
                    error: error.to_string(),
                    failures,
                    retry_in,
                });
                market.wait(retry_in)?;
            }
            Err(error) => {
                market.report(&Health::Failed {
                    error: error.to_string(),
                });
                return Err(error);
            }
        }
    }
}

/// One step of the bounty: look at the journal and the chain, do at most
/// one thing, and say whether the bounty stops.
fn step(
    limits: Limits,
    journal: &Shared,
    market: &mut dyn Market,
    first: bool,
) -> Res<Option<Stop>> {
    let (open, spent, consumed, failed) = {
        let journal = locked(journal)?;
        let ledger = journal.ledger();
        (
            ledger.open.clone(),
            ledger.spent,
            ledger.consumed,
            ledger.failures,
        )
    };
    let record = |entry: Entry| -> Res<()> { locked(journal)?.record(entry) };
    match open {
        None => {
            let stop = if consumed >= limits.tasks {
                Some(Stop::TaskLimit)
            } else if failed >= limits.tasks {
                Some(Stop::Failures)
            } else if spent.saturating_add(limits.price) > limits.budget {
                Some(Stop::Budget)
            } else if market.wallet()? < limits.price {
                Some(Stop::Wallet)
            } else {
                None
            };
            if let Some(stop) = stop {
                record(Entry::Stopped {
                    reason: stop.to_string(),
                })?;
                return Ok(Some(stop));
            }
            if !first {
                market.wait(limits.pause)?;
            }
            let task = market.prepare(limits.price)?;
            record(Entry::Intent(task.clone()))?;
            let transaction = market.post(&task)?;
            record(Entry::Posted {
                task: task.id,
                transaction,
            })?;
        }
        // A crash or a lost receipt fell between the intent and the post.
        Some(Open::Intent(task)) => {
            if market.on_board(task.id)? {
                record(Entry::Posted {
                    task: task.id,
                    transaction: "(found on the board; its receipt was not seen)".into(),
                })?;
            } else if !market.quiet()? {
                // The post may still be waiting to be mined.
                market.wait(POLL)?;
            } else {
                market.close_desk(task.id)?;
                record(Entry::Abandoned { task: task.id })?;
            }
        }
        Some(Open::Posted(task)) => {
            if !market.on_board(task.id)? {
                return Err(Irreconcilable::PostMissing(task.id).into());
            }
            let withdrawal = if market.now()? > task.fund_by {
                if market.desk_open(task.id)? && !market.close_desk(task.id)? {
                    // Signed for while we looked; the journal has it now.
                    return Ok(None);
                }
                Some(Withdrawal::WindowEnded)
            } else if market.desk_open(task.id)? {
                market.wait(POLL)?;
                None
            } else {
                // Nothing was signed for it (a signature is journaled
                // before it is released), so its desk may be reopened.
                match market.resume(&task)? {
                    Resumption::Resumed => {
                        println!(
                            "bounty: resumed task {}; open for offers until {}",
                            hex(&task.id),
                            task.fund_by
                        );
                        None
                    }
                    Resumption::Unresumable(why) => {
                        println!(
                            "bounty: cannot resume task {}: {why}; withdrawing it",
                            hex(&task.id)
                        );
                        Some(Withdrawal::Unresumable(why))
                    }
                }
            };
            if let Some(reason) = withdrawal {
                let transaction = market.withdraw(task.id)?;
                let block = market.block()?;
                record(Entry::Withdrawn {
                    task: task.id,
                    transaction,
                    block,
                    reason,
                })?;
            }
        }
        Some(Open::Signed(_, order)) => match market.phase(&order)? {
            Phase::Settled => {
                let verdict = market.check_settled(&order)?;
                let block = market.block()?;
                record(Entry::Settled {
                    digest: order.digest,
                    paid: order.amount,
                    checked: verdict.is_ok(),
                    block,
                })?;
                if let Err(why) = verdict {
                    let reason = format!("a settled artifact was refused: {why}");
                    record(Entry::Stopped {
                        reason: reason.clone(),
                    })?;
                    return Err(reason.into());
                }
            }
            Phase::Funded if market.now()? > order.order.deliver_by => {
                market.refund(&order)?;
            }
            Phase::Refunded => {
                market.recover()?;
                let block = market.block()?;
                record(Entry::Refunded {
                    digest: order.digest,
                    block,
                })?;
            }
            Phase::Empty if market.now()? > order.order.fund_by => {
                let block = market.block()?;
                record(Entry::Lapsed {
                    digest: order.digest,
                    block,
                })?;
            }
            Phase::Funded | Phase::Empty => market.wait(POLL)?,
        },
    }
    Ok(None)
}

/// Close a bounty: leave nothing open on the board and say so in the
/// journal. An intent is resolved as on a restart; a post nobody has been
/// signed for is withdrawn. A signed order cannot be closed over: its
/// authorization has left this buyer, so the journal has to follow it to a
/// settlement, a refund or a lapse first (`run` does that).
pub fn close(journal: &Shared, market: &mut dyn Market) -> Res<()> {
    attribute(journal, market)?;
    loop {
        let open = locked(journal)?.ledger().open.clone();
        let record = |entry: Entry| -> Res<()> { locked(journal)?.record(entry) };
        match open {
            None => {
                return record(Entry::Stopped {
                    reason: "closed by the operator".into(),
                });
            }
            Some(Open::Intent(task)) => {
                if market.on_board(task.id)? {
                    record(Entry::Posted {
                        task: task.id,
                        transaction: "(found on the board when closing)".into(),
                    })?;
                } else if !market.quiet()? {
                    market.wait(POLL)?;
                } else {
                    record(Entry::Abandoned { task: task.id })?;
                }
            }
            Some(Open::Posted(task)) => {
                if !market.on_board(task.id)? {
                    return Err(Irreconcilable::PostMissing(task.id).into());
                }
                if market.desk_open(task.id)? && !market.close_desk(task.id)? {
                    // Signed for while closing; the journal has it now.
                    continue;
                }
                let transaction = market.withdraw(task.id)?;
                let block = market.block()?;
                record(Entry::Withdrawn {
                    task: task.id,
                    transaction,
                    block,
                    reason: Withdrawal::Closed,
                })?;
            }
            Some(Open::Signed(_, order)) => {
                return Err(format!(
                    "order {} is signed for and not finished; run the bounty until it settles, is refunded or lapses, then close",
                    hex(&order.digest)
                )
                .into());
            }
        }
    }
}

/// The real market: a deployment, a board, this buyer's keys and its desk.
struct Live {
    world: World,
    board: Board,
    keys: Keys,
    /// The statement, or why it could not be read. A missing statement
    /// ends nothing by itself: a signed order is still followed, and an
    /// open post is withdrawn with this as the reason (R-3).
    statement: Result<Statement, String>,
    program: Hash,
    post_window: u64,
    bind: String,
    relay: iroh_net::Relay,
    node: String,
    desk: Arc<Mutex<Desk>>,
    journal: Shared,
    /// The status file (R-5) and the last error it reported.
    status: PathBuf,
    last_error: Option<(u64, String)>,
    /// Tasks prepared and not yet posted.
    prepared: Vec<(Hash, Task)>,
    /// The desk's endpoint and the runtime it runs on, kept for as long as
    /// the market is.
    _router: iroh::protocol::Router,
    _runtime: tokio::runtime::Runtime,
}

/// How long after a post's funding deadline delivery may still take.
const DELIVERY_AFTER_FUNDING: u64 = 4 * 3_600;

fn units(value: U256) -> Res<u64> {
    u64::try_from(value).map_err(|_| "amount above u64".into())
}

/// The buyer's statement and what it pins.
struct Statement {
    bytes: Vec<u8>,
    policy: Policy,
    blake3: Hash,
}

impl Live {
    fn desk(&self) -> Res<std::sync::MutexGuard<'_, Desk>> {
        self.desk.lock().map_err(|_| "desk poisoned".into())
    }
    fn statement(&self) -> Res<&Statement> {
        self.statement.as_ref().map_err(|why| why.clone().into())
    }
    /// The task this configuration posts with these terms and salt.
    fn task_with(&self, price: u64, fund_by: u64, deliver_by: u64, salt: Hash) -> Res<Task> {
        let statement = self.statement()?;
        Ok(Task {
            statement_sha256: statement.policy.statement_sha256,
            statement_blake3: statement.blake3,
            policy_hash: statement.policy.hash(),
            asset: self.world.token,
            maximum_amount: U256::from(price).to_be_bytes(),
            verifier: self.world.verifier,
            program: self.program,
            fund_by,
            deliver_by,
            buyer_node: board::node_bytes(&self.node)?,
            buyer_key_binding: self.keys.binding(),
            salt,
            buyer_address: match self.relay {
                iroh_net::Relay::None => self.bind.clone(),
                iroh_net::Relay::Default | iroh_net::Relay::Url(_) => String::new(),
            },
        })
    }
    fn id_of(&self, task: &Task) -> Hash {
        nucleus_board_reference::id(
            self.world.chain.id,
            self.board.address,
            self.keys.address(),
            task,
        )
    }
}

/// Write `value` to `path` whole: a reader sees the old file or the new one.
fn write_atomically(path: &Path, value: &Value) -> Res<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, format!("{value:#}\n"))?;
    fs::rename(&temporary, path)?;
    Ok(())
}

impl Market for Live {
    fn now(&mut self) -> Res<u64> {
        wall_clock()
    }
    fn block(&mut self) -> Res<u64> {
        self.board.latest_block()
    }
    fn wallet(&mut self) -> Res<u64> {
        units(self.world.balance(self.keys.address())?)
    }
    fn prepare(&mut self, price: u64) -> Res<TaskRef> {
        let now = wall_clock()?;
        let salt = random32()?;
        let task = self.task_with(
            price,
            now + self.post_window,
            now + self.post_window + DELIVERY_AFTER_FUNDING,
            salt,
        )?;
        if let Some(refusal) = task.refusal(now) {
            return Err(format!("the board would refuse this task: {refusal}").into());
        }
        let id = self.id_of(&task);
        let reference = TaskRef {
            id,
            price,
            fund_by: task.fund_by,
            deliver_by: task.deliver_by,
            salt: Some(salt),
        };
        self.prepared.push((id, task));
        Ok(reference)
    }
    fn post(&mut self, task: &TaskRef) -> Res<String> {
        let at = self
            .prepared
            .iter()
            .position(|(id, _)| *id == task.id)
            .ok_or("this task was not prepared here")?;
        let (id, posted) = self.prepared.swap_remove(at);
        // Serve before posting, so the first seller to see the post finds the desk.
        let policy = self.statement()?.policy.clone();
        self.desk()?.open(Posted::new(id, posted.clone(), policy)?);
        let (posted_id, receipt) = self.board.post(&self.keys.wallet, &posted)?;
        if posted_id != id {
            return Err("the board gave the task another ID than the reference".into());
        }
        println!(
            "bounty: posted task {} at cap {} in tx {} (gas {}); open for offers until {}",
            hex(&id),
            task.price,
            receipt.transaction,
            receipt.gas_used,
            task.fund_by
        );
        Ok(receipt.transaction)
    }
    fn on_board(&mut self, task: Hash) -> Res<bool> {
        let poster = self.world.chain.call(
            [0; 20],
            self.board.address,
            &nucleus_board_reference::poster_of_call(task),
        )?;
        Ok(poster.get(12..32) == Some(&self.keys.address()[..]))
    }
    fn desk_open(&mut self, task: Hash) -> Res<bool> {
        Ok(self.desk()?.open_for_offers(&task))
    }
    fn close_desk(&mut self, task: Hash) -> Res<bool> {
        Ok(self.desk()?.withdraw(&task))
    }
    fn resume(&mut self, task: &TaskRef) -> Res<Resumption> {
        let unresumable = |why: &str| Ok(Resumption::Unresumable(why.to_owned()));
        let Some(salt) = task.salt else {
            return unresumable(
                "the journal kept no salt for it (its intent was written before posts could be resumed)",
            );
        };
        if self.board.withdrawn(task.id)? {
            return unresumable("the board shows it withdrawn already");
        }
        let policy = match &self.statement {
            Ok(statement) => statement.policy.clone(),
            Err(why) => return unresumable(why),
        };
        let rebuilt = self.task_with(task.price, task.fund_by, task.deliver_by, salt)?;
        if self.id_of(&rebuilt) != task.id {
            return unresumable(
                "the task rebuilt from this configuration has another ID: the statement, deployment, program, node or bind address changed since it was posted",
            );
        }
        match Posted::new(task.id, rebuilt, policy) {
            Ok(posted) => self.desk()?.open(posted),
            Err(why) => return unresumable(why),
        }
        Ok(Resumption::Resumed)
    }
    fn quiet(&mut self) -> Res<bool> {
        let buyer = hex(&self.keys.address());
        let count = |block: &str| -> Res<Value> {
            self.world
                .chain
                .rpc("eth_getTransactionCount", json!([buyer, block]))
        };
        Ok(count("pending")? == count("latest")?)
    }
    fn report(&mut self, health: &Health) {
        let now = wall_clock().unwrap_or(0);
        let (state, error) = match health {
            Health::Ok => ("ok", None),
            Health::Degraded { error, .. } => ("degraded", Some(error)),
            Health::Failed { error } => ("failed", Some(error)),
        };
        if let Some(error) = error {
            self.last_error = Some((now, error.clone()));
        }
        let (open, posted, consumed, failures, spent) = match locked(&self.journal) {
            Ok(journal) => {
                let ledger = journal.ledger();
                (
                    ledger.open.clone(),
                    ledger.posted,
                    ledger.consumed,
                    ledger.failures,
                    ledger.spent,
                )
            }
            Err(_) => (None, 0, 0, 0, 0),
        };
        let open = match &open {
            None => Value::Null,
            Some(Open::Intent(task)) => {
                json!({"stage": "intent", "task": hex(&task.id), "fundBy": task.fund_by})
            }
            Some(Open::Posted(task)) => json!({
                "stage": "posted", "task": hex(&task.id), "fundBy": task.fund_by,
                "deskOpen": self.desk().map(|desk| desk.open_for_offers(&task.id)).unwrap_or(false),
            }),
            Some(Open::Signed(task, order)) => json!({
                "stage": "signed", "task": hex(&task.id), "order": hex(&order.digest),
                "deliverBy": order.order.deliver_by,
            }),
        };
        let status = json!({
            "updated": now,
            "state": state,
            "retryIn": match health { Health::Degraded { retry_in, .. } => json!(retry_in), _ => Value::Null },
            "failuresInARow": match health { Health::Degraded { failures, .. } => *failures, _ => 0 },
            "lastRpcAnswer": self.world.chain.last_answer(),
            "open": open,
            "lastError": self.last_error.as_ref().map(|(at, error)| json!({"at": at, "error": error})),
            "posted": posted,
            "consumed": consumed,
            "withdrawnForFailures": failures,
            "spent": spent,
        });
        if let Err(error) = write_atomically(&self.status, &status) {
            println!(
                "bounty: degraded: the status file {} could not be written: {error}",
                self.status.display()
            );
        }
    }
    fn withdraw(&mut self, task: Hash) -> Res<String> {
        if self.board.withdrawn(task)? {
            return Ok("(already withdrawn)".into());
        }
        let receipt = self.board.withdraw(&self.keys.wallet, task)?;
        println!(
            "bounty: withdrew task {} in tx {}",
            hex(&task),
            receipt.transaction
        );
        Ok(receipt.transaction)
    }
    fn phase(&mut self, order: &OrderRef) -> Res<Phase> {
        Ok(match phase_of(&self.world, order.digest)? {
            0 => Phase::Empty,
            1 => Phase::Funded,
            2 => Phase::Settled,
            3 => Phase::Refunded,
            other => return Err(format!("the vault reports phase {other}").into()),
        })
    }
    fn check_settled(&mut self, order: &OrderRef) -> Res<Result<(), String>> {
        // The order was signed after the journal's last checkpoint, so its
        // settlement is no earlier.
        let from = locked(&self.journal)?.ledger().checkpoint;
        let artifact = match settled_artifact(
            self.world.deployment.rules.form(),
            &self.world.chain,
            self.world.deployment.vault,
            order.digest,
            from,
        ) {
            Ok(artifact) => artifact,
            // An RPC failure is not a refusal of the artifact.
            Err(error) if error.downcast_ref::<crate::chain::RpcError>().is_some() => {
                return Err(error);
            }
            Err(error) => return Ok(Err(error.to_string())),
        };
        let recorded = self.world.chain.call(
            [0; 20],
            self.world.deployment.vault,
            &artifactOfCall {
                d: order.digest.into(),
            }
            .abi_encode(),
        )?;
        if recorded != keccak(&artifact) {
            return Ok(Err(
                "the vault recorded another artifact for this order".into()
            ));
        }
        let statement = self.statement()?;
        Ok(
            match accept(&statement.policy, &statement.bytes, &artifact) {
                Ok(accepted) => {
                    println!(
                        "bounty: order {} settled for seller {}; {} byte artifact from calldata passes the Lean checker ({})",
                        hex(&order.digest),
                        hex(&order.order.seller),
                        artifact.len(),
                        accepted.proof
                    );
                    Ok(())
                }
                Err(refusal) => Err(format!("{refusal:?}")),
            },
        )
    }
    fn refund(&mut self, order: &OrderRef) -> Res<String> {
        let receipt = self.world.chain.send(
            &self.keys.wallet,
            Some(self.world.deployment.vault),
            0,
            &refund_data(self.world.deployment.rules.form(), &order.order),
        )?;
        if !receipt.success {
            return Err("refund reverted".into());
        }
        println!(
            "bounty: refunded order {} in tx {}",
            hex(&order.digest),
            receipt.transaction
        );
        Ok(receipt.transaction)
    }
    fn recover(&mut self) -> Res<String> {
        // The second form pays a refund inside `refund`; nothing to claim.
        if self.world.deployment.rules.form() == vault::Form::Second {
            return Ok("(paid by the refund itself)".into());
        }
        let buyer = self.keys.address();
        if self.world.owed(buyer)?.is_zero() {
            return Ok("(nothing owed)".into());
        }
        let receipt = self.world.chain.send(
            &self.keys.wallet,
            Some(self.world.deployment.vault),
            0,
            &third::claimCall {
                payee: A::from(buyer),
                asset: A::from(self.world.token),
            }
            .abi_encode(),
        )?;
        if !receipt.success {
            return Err("claim reverted".into());
        }
        println!("bounty: claimed the refund in tx {}", receipt.transaction);
        Ok(receipt.transaction)
    }
    fn deposits(&mut self, from: u64, to: u64) -> Res<Vec<Hash>> {
        let mut buyer = [0u8; 32];
        buyer[12..].copy_from_slice(&self.keys.address());
        let logs = self.world.chain.logs(
            &json!({
                "address": hex(&self.world.deployment.vault),
                "topics": [hex(&funded_topic()), Value::Null, hex(&buyer)],
            }),
            from,
            to,
        )?;
        logs.iter()
            .map(|log| hash_of(&log["topics"][1]).map_err(|e| format!("Funded log: {e}").into()))
            .collect()
    }
    fn wait(&mut self, seconds: u64) -> Res<()> {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
        Ok(())
    }
}

/// `nucleus-buyer bounty-close DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX JOURNAL BIND`:
/// withdraw this journal's open post, if it has one, and end the journal.
/// The bounty process for the journal must not be running.
pub fn bounty_close(args: &[String]) -> Res<()> {
    let [
        deployment,
        board_address,
        keyfile,
        statement,
        program,
        journal,
        bind,
    ] = args
    else {
        return Err(
            "usage: nucleus-buyer bounty-close DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX JOURNAL BIND"
                .into(),
        );
    };
    let (mut market, journal) = live(
        deployment,
        board_address,
        keyfile,
        statement,
        program,
        journal,
        "0",
        bind,
    )?;
    close(&journal, &mut market)?;
    let journal = locked(&journal)?;
    println!(
        "bounty: closed; nothing open; spent {} over {} posts",
        journal.ledger().spent,
        journal.ledger().posted
    );
    Ok(())
}

/// `nucleus-buyer bounty-ledger JOURNAL`: replay a journal and print what it
/// says, touching nothing else. What a restart would start from.
pub fn bounty_ledger(args: &[String]) -> Res<()> {
    let [journal] = args else {
        return Err("usage: nucleus-buyer bounty-ledger JOURNAL".into());
    };
    let ledger = replay(&fs::read_to_string(journal)?)?;
    let open = match &ledger.open {
        None => "nothing".to_owned(),
        Some(Open::Intent(task)) => format!("intent {}", hex(&task.id)),
        Some(Open::Posted(task)) => format!("posted {}", hex(&task.id)),
        Some(Open::Signed(task, order)) => {
            format!("signed {} order {}", hex(&task.id), hex(&order.digest))
        }
    };
    println!(
        "bounty-ledger: {} lines; posted {}; used up {} tasks; withdrawn for this buyer's failures {}; spent {}; open: {open}; checkpoint block {}",
        ledger.lines,
        ledger.posted,
        ledger.consumed,
        ledger.failures,
        ledger.spent,
        ledger.checkpoint
    );
    Ok(())
}

pub fn bounty(args: &[String]) -> Res<()> {
    let [
        deployment,
        board_address,
        keyfile,
        statement,
        program,
        journal,
        price,
        budget,
        tasks,
        pause,
        post_window,
        bind,
    ] = args
    else {
        return Err(
            "usage: nucleus-buyer bounty DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX JOURNAL PRICE BUDGET TASKS PAUSE_SECONDS POST_WINDOW_SECONDS BIND"
                .into(),
        );
    };
    let limits = Limits {
        price: price.parse()?,
        budget: budget.parse()?,
        tasks: tasks.parse()?,
        pause: pause.parse()?,
    };
    if limits.price == 0 || limits.price > limits.budget {
        return Err("the price must be positive and within the budget".into());
    }
    // Starting needs the chain too; an RPC outage at start is waited out
    // like one later (R-2).
    let mut failures: u32 = 0;
    let (mut market, journal) = loop {
        match live(
            deployment,
            board_address,
            keyfile,
            statement,
            program,
            journal,
            post_window,
            bind,
        ) {
            Ok(started) => break started,
            Err(error) if crate::chain::is_transient(&*error) => {
                failures += 1;
                let retry_in = RETRY_FIRST
                    .saturating_mul(1 << (failures - 1).min(5))
                    .min(RETRY_MOST);
                println!(
                    "bounty: degraded: starting: {error}; trying again in {retry_in} s (failure {failures} in a row)"
                );
                std::thread::sleep(std::time::Duration::from_secs(retry_in));
            }
            Err(error) => return Err(error),
        }
    };
    {
        let journal = locked(&journal)?;
        let ledger = journal.ledger();
        println!(
            "bounty: price {} budget {} tasks {} pause {}s; journal has spent {} over {} posts, {} of which used up a task and {} were withdrawn for this buyer's failures",
            limits.price,
            limits.budget,
            limits.tasks,
            limits.pause,
            ledger.spent,
            ledger.posted,
            ledger.consumed,
            ledger.failures
        );
    }
    let stop = run(limits, &journal, &mut market)?;
    let journal = locked(&journal)?;
    println!(
        "bounty: stopped: {stop}; spent {} over {} posts ({} used up a task)",
        journal.ledger().spent,
        journal.ledger().posted,
        journal.ledger().consumed
    );
    Ok(())
}

/// The live market and the journal for one buyer on one deployment and board.
#[allow(clippy::too_many_arguments)]
fn live(
    deployment: &str,
    board_address: &str,
    keyfile: &str,
    statement: &str,
    program: &str,
    journal: &str,
    post_window: &str,
    bind: &str,
) -> Res<(Live, Shared)> {
    let world = World::read(deployment)?;
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let keys = Keys::load_or_create(keyfile)?;
    let statement_path = statement;
    let statement = fs::read(statement_path)
        .map_err(|error| format!("the statement file {statement_path} cannot be read: {error}"));
    let program: Hash = unhex(program)?
        .try_into()
        .map_err(|_| "program id length")?;
    let board = Board {
        chain: world.chain.clone(),
        address: address_arg(board_address)?,
    };
    if board.vault()? != world.deployment.vault {
        return Err("the board is for another vault than this deployment's".into());
    }
    let journal_path = Path::new(journal);
    let journal: Shared = Arc::new(Mutex::new(Journal::open(
        journal_path,
        Header {
            chain: world.chain.id,
            vault: world.deployment.vault,
            board: board.address,
            token: world.token,
            buyer: keys.address(),
            block: board.latest_block()?,
        },
    )?));

    let relay = iroh_net::Relay::from_environment()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let endpoint = runtime
        .block_on(async { iroh_net::endpoint_in(keys.node, bind.parse()?, &relay).await })
        .map_err(|e| e.to_string())?;
    let node = endpoint.id().to_string();
    let store = {
        let _guard = runtime.enter();
        crate::blobs::store()
    };
    let statement = match statement {
        Ok(bytes) => Ok(Statement {
            policy: Policy {
                statement_sha256: Sha256::digest(&bytes).into(),
                claim: "Nucleus.Claim".into(),
                permitted_axioms: vec![],
                maximum_artifact_bytes: 65_536,
            },
            blake3: runtime.block_on(crate::blobs::add(&store, bytes.clone()))?,
            bytes,
        }),
        Err(why) => {
            println!("bounty: degraded: {why}");
            Err(why)
        }
    };

    let mut desk = Desk::new(
        world.deployment.clone(),
        world.domain.clone(),
        keys.wallet.clone(),
    );
    desk.accept_bases(world.bases.clone());
    // Rule 3: a signed order is in the journal before its authorization leaves.
    let for_desk = journal.clone();
    desk.record_signatures(Box::new(move |signed| {
        let amount = u64::try_from(U256::from_be_bytes(signed.order.amount))
            .map_err(|_| "amount above u64".to_owned())?;
        let mut journal = for_desk.lock().map_err(|_| "journal poisoned".to_owned())?;
        journal
            .record(Entry::Signed {
                task: signed.id,
                order: OrderRef {
                    digest: signed.digest,
                    amount,
                    order: signed.order.clone(),
                },
            })
            .map_err(|e| e.to_string())?;
        println!(
            "bounty: signed order {} for seller {} at {amount}",
            hex(&signed.digest),
            hex(&signed.order.seller)
        );
        Ok(())
    }));
    let desk = Arc::new(Mutex::new(desk));
    let _router = {
        let _guard = runtime.enter();
        iroh_net::serve_with(endpoint, desk.clone(), Some(&store))
    };
    println!(
        "bounty: buyer {} node {node} (relay {relay:?})",
        hex(&keys.address())
    );
    let market = Live {
        world,
        board,
        keys,
        statement,
        program,
        post_window: post_window.parse()?,
        bind: bind.to_owned(),
        relay,
        node,
        desk,
        journal: journal.clone(),
        status: journal_path.with_extension("status.json"),
        last_error: None,
        prepared: vec![],
        _router,
        _runtime: runtime,
    };
    Ok((market, journal))
}

#[cfg(test)]
mod tests;
