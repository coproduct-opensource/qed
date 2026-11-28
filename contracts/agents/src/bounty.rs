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
    /// The most posts this journal may ever make, counted by `posted`
    /// lines. `None` for the standing bounty, which posts again after a
    /// window ends; `Some(1)` for a ladder post (`tasks.rs`), which posts
    /// once and never again (proofs/commerce/LadderPost.lean, `intent`'s
    /// `first`).
    pub posts: Option<u32>,
    /// Gas units the wallet's ether must cover, at the price read before
    /// posting, before a task is posted: the buyer's own transactions for
    /// one task. `None` for the standing bounty (not checked); the ladder's
    /// is `tasks::LADDER_GAS` (gap 3).
    pub gas: Option<u128>,
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

/// Why a post was withdrawn. Since 2026-11-14 no withdrawal uses up a task
/// (R-4: only a settlement does); `Unresumable` still counts toward
/// `Stop::Failures`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Withdrawal {
    /// Its whole funding window passed and nothing was signed. A task until
    /// 2026-11-14; not one since (the journal line is unchanged).
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
    /// Written by the desk just before `Signed` when the order's salt binds
    /// a referrer: the referrer and the nonce that open it
    /// (docs/rfcs/qed-proof-carrying-savings-2026-11-28.md). Journals written
    /// before referrals have no such line and replay as before.
    Referred {
        task: Hash,
        digest: Hash,
        referrer: Address,
        nonce: Hash,
    },
    /// A share of a settled order's saving, sent or found already paid on
    /// the token (`payout::Paid`). The token's used nonce is what makes it
    /// once; this line is the record.
    Paid {
        share: crate::payout::Share,
        transaction: Option<String>,
    },
    /// A share the wallet could not yet cover; tried again on later steps.
    Owed {
        share: crate::payout::Share,
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
    /// Settled orders: the only thing that uses up a task (R-4, owner
    /// decision of 2026-11-14). A window that ends unanswered, a lapsed or
    /// a refunded order does not.
    pub settled: u32,
    /// Funded orders refunded undelivered. Not tasks; bounded on their own
    /// (`Stop::Refunds`), since each costs the buyer a refund and a claim.
    pub refunded: u32,
    /// Posts withdrawn because this buyer could not resume them.
    pub failures: u32,
    pub open: Option<Open>,
    /// Digests of every order this journal signed for.
    pub signed: Vec<Hash>,
    /// The height up to which the vault's deposits were compared with `signed`.
    pub checkpoint: u64,
    /// Order digest → the referrer and nonce journaled for it.
    pub referrals: Vec<(Hash, Address, Hash)>,
    /// Shares owed and not yet journaled paid, in the order they were owed.
    pub owed: Vec<crate::payout::Share>,
    lines: usize,
}

impl Ledger {
    fn new(header: Header) -> Self {
        let checkpoint = header.block;
        Self {
            header,
            spent: 0,
            posted: 0,
            settled: 0,
            refunded: 0,
            failures: 0,
            open: None,
            signed: vec![],
            checkpoint,
            referrals: vec![],
            owed: vec![],
            lines: 1,
        }
    }
    /// Admit one event, or say why the diagram does not allow it here.
    fn apply(&mut self, entry: &Entry) -> Result<(), &'static str> {
        let open = self.open.take();
        let next = match (entry, open) {
            (Entry::Opened(_), _) => return Err("a journal is opened once, on its first line"),
            (Entry::Stopped { .. }, open) => open,
            (
                Entry::Referred {
                    task,
                    digest,
                    referrer,
                    nonce,
                },
                Some(Open::Posted(posted)),
            ) if *task == posted.id => {
                self.referrals.push((*digest, *referrer, *nonce));
                Some(Open::Posted(posted))
            }
            (Entry::Referred { .. }, _) => return Err("a referral for a task that is not posted"),
            (Entry::Owed { share }, open) => {
                if !self.owed.contains(share) {
                    self.owed.push(share.clone());
                }
                open
            }
            (Entry::Paid { share, .. }, open) => {
                self.owed.retain(|s| s != share);
                open
            }
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
                    Withdrawal::Unresumable(_) => self.failures += 1,
                    // A window that ended unanswered cost one post's gas and
                    // no budget: not a task since 2026-11-14 (R-4).
                    Withdrawal::WindowEnded | Withdrawal::Closed | Withdrawal::Unrecorded => {}
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
                self.settled += 1;
                self.checkpoint = self.checkpoint.max(*block);
                None
            }
            (Entry::Refunded { digest, block }, Some(Open::Signed(_, order)))
                if *digest == order.digest =>
            {
                self.refunded += 1;
                self.checkpoint = self.checkpoint.max(*block);
                None
            }
            (Entry::Lapsed { digest, block }, Some(Open::Signed(_, order)))
                if *digest == order.digest =>
            {
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
fn address_of_json(value: &Value) -> Result<Address, String> {
    unhex(value.as_str().ok_or("address expected")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "20 bytes expected".to_owned())
}
fn share_json(s: &crate::payout::Share) -> Value {
    json!({
        "order": hex(&s.order),
        "role": match s.role { crate::payout::Role::Referrer => "referrer", crate::payout::Role::Author => "author" },
        "party": hex(&s.party),
        "amount": s.amount.to_string(),
        "nonce": hex(&crate::payout::nonce(s)),
    })
}
fn share_of(v: &Value) -> Result<crate::payout::Share, String> {
    let share = crate::payout::Share {
        order: hash_of(&v["order"])?,
        role: match v["role"].as_str() {
            Some("referrer") => crate::payout::Role::Referrer,
            Some("author") => crate::payout::Role::Author,
            _ => return Err("role expected".into()),
        },
        party: address_of_json(&v["party"])?,
        amount: v["amount"]
            .as_str()
            .and_then(|a| a.parse().ok())
            .ok_or("amount expected")?,
    };
    // The nonce is the share's; a line whose nonce is another's is not read.
    if hash_of(&v["nonce"])? != crate::payout::nonce(&share) {
        return Err("the nonce is not this share's".into());
    }
    Ok(share)
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
            Self::Referred {
                task,
                digest,
                referrer,
                nonce,
            } => json!({
                "event": "referred", "task": hex(task), "digest": hex(digest),
                "referrer": hex(referrer), "nonce": hex(nonce),
            }),
            Self::Paid { share, transaction } => {
                let mut line = share_json(share);
                line["event"] = json!("paid");
                line["transaction"] = json!(transaction);
                line
            }
            Self::Owed { share } => {
                let mut line = share_json(share);
                line["event"] = json!("owed");
                line
            }
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
            "referred" => Self::Referred {
                task: hash_of(&v["task"])?,
                digest: hash_of(&v["digest"])?,
                referrer: address_of_json(&v["referrer"])?,
                nonce: hash_of(&v["nonce"])?,
            },
            "paid" => Self::Paid {
                share: share_of(v)?,
                transaction: v["transaction"].as_str().map(str::to_owned),
            },
            "owed" => Self::Owed {
                share: share_of(v)?,
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
    /// The buyer's ether in wei, and the wei per gas its transactions
    /// would offer now. Asked only when `Limits::gas` is set.
    fn ether(&mut self) -> Res<(u128, u128)>;
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
    /// After a checked settlement of `order` on a post priced `cap`, with
    /// the referral its journal holds: publish who authored the reused
    /// lemmas and pay the shares of the saving (`payout::pay`,
    /// proofs/commerce/Payout.lean). Returns the `Paid` and `Owed` lines to
    /// journal. A market that pays nothing returns none.
    fn savings(
        &mut self,
        _order: &OrderRef,
        _cap: u64,
        _referral: Option<(Address, Hash)>,
    ) -> Res<Vec<Entry>> {
        Ok(vec![])
    }
    /// What the other rows could still be funded for; payouts leave it.
    fn reserve(&mut self, _reserved: u64) {}
    /// Pay shares still owed (`Owed` lines). Returns the lines to journal.
    fn pay_owed(&mut self, _owed: &[crate::payout::Share]) -> Res<Vec<Entry>> {
        Ok(vec![])
    }
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
    /// As many funded orders were refunded undelivered as the task limit:
    /// sellers keep taking the post and not proving (R-4, 2026-11-14).
    Refunds,
    /// As many posts were made as `Limits::posts` allows.
    PostLimit,
    /// The wallet's ether does not cover `Limits::gas` at the price read
    /// now: `have` and `need` in wei.
    Gas {
        have: u128,
        need: u128,
    },
}
impl std::error::Error for Stop {}
impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TaskLimit => write!(f, "the task limit is reached"),
            Self::PostLimit => write!(f, "the post limit is reached; nothing more is posted"),
            Self::Gas { have, need } => write!(
                f,
                "the wallet holds {have} wei; its own post, withdrawal, refund and claim need {need} wei at today's price, with headroom"
            ),
            Self::Failures => write!(
                f,
                "as many posts were withdrawn because this buyer could not resume them as the task limit; stopping for the operator"
            ),
            Self::Refunds => write!(
                f,
                "as many funded orders were refunded undelivered as the task limit; stopping for the operator"
            ),
            Self::Budget => write!(f, "the budget does not cover another task"),
            Self::Wallet => write!(f, "the wallet does not cover another task"),
        }
    }
}

/// Seconds between looks at the chain while a task is open.
const POLL: u64 = 15;
/// `Limits::gas` is checked at this many times the price read before
/// posting: the withdrawal or refund it pays for may be sent up to 16 days
/// later, and a sender holds gas limit × price up front.
pub const GAS_HEADROOM: u128 = 2;
/// Seconds before a step that failed transiently runs again: doubled after
/// each failure in a row, up to the most (R-2).
const RETRY_FIRST: u64 = 15;
const RETRY_MOST: u64 = 300;

fn locked(journal: &Shared) -> Res<std::sync::MutexGuard<'_, Journal>> {
    journal.lock().map_err(|_| "journal poisoned".into())
}

/// Every deposit the vault took from this buyer since the checkpoint must be
/// for an order this journal signed (rule 8).
fn attribute(journal: &Shared, market: &mut dyn Market) -> Res<()> {
    attribute_all(std::slice::from_ref(journal), market)
}

/// Rule 8 for a desk with several rows on one wallet: every deposit the
/// vault took from this buyer since the earliest of the journals'
/// checkpoints must be for an order one of them signed (`ladder::explains`;
/// `restart_admitted` in proofs/commerce/LadderMulti.lean). Checked against
/// each journal alone, one row's funded order stops every other row's
/// restart (`mutant_perRow_breaks_restart_admitted`).
pub(crate) fn attribute_all(journals: &[Shared], market: &mut dyn Market) -> Res<()> {
    let mut ledgers = vec![];
    for journal in journals {
        ledgers.push(locked(journal)?.ledger().clone());
    }
    let Some(from) = ledgers.iter().map(|ledger| ledger.checkpoint).min() else {
        return Ok(());
    };
    let to = market.block()?;
    let deposits = market.deposits(from, to)?;
    match crate::ladder::unexplained(&ledgers, &deposits) {
        Some(digest) => Err(Irreconcilable::UnknownDeposit(digest).into()),
        None => Ok(()),
    }
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
            step(limits, journal, market, first, 0).and_then(|next| match next {
                Next::Stop(stop) => Ok(Some(stop)),
                Next::Wait(seconds) => market.wait(seconds).map(|()| None),
                Next::Moved => Ok(None),
            })
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

/// What a step leaves for its caller to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// The bounty, or this row, stops.
    Stop(Stop),
    /// Nothing is due before this many seconds.
    Wait(u64),
    /// It moved; the next step may follow at once.
    Moved,
}

/// One step of the bounty: look at the journal and the chain, do at most
/// one thing, and say whether the bounty stops or what to wait for.
/// `reserved` is what the desk's other rows have committed the wallet to
/// (`ladder::committed`): a post is made only when the wallet covers its
/// cap on top of that (`no_overcommit` in proofs/commerce/LadderMulti.lean).
/// A one-row desk passes 0, and the check is the one-row check.
pub(crate) fn step(
    limits: Limits,
    journal: &Shared,
    market: &mut dyn Market,
    first: bool,
    reserved: u64,
) -> Res<Next> {
    let (open, spent, settled, refunded, failed, posted) = {
        let journal = locked(journal)?;
        let ledger = journal.ledger();
        (
            ledger.open.clone(),
            ledger.spent,
            ledger.settled,
            ledger.refunded,
            ledger.failures,
            ledger.posted,
        )
    };
    let record = |entry: Entry| -> Res<()> { locked(journal)?.record(entry) };
    market.reserve(reserved);
    // Shares a settlement left owed are tried first, every step.
    let owed = locked(journal)?.ledger().owed.clone();
    if !owed.is_empty() {
        for line in market.pay_owed(&owed)? {
            record(line)?;
        }
    }
    match open {
        None => {
            // R-4 (2026-11-14): only settled orders are tasks. Settlement is
            // the only spend, so `tasks` settled is the spend cap; refunds and
            // the buyer's own failures are bounded by the same number.
            let stop = if settled >= limits.tasks {
                Some(Stop::TaskLimit)
            } else if failed >= limits.tasks {
                Some(Stop::Failures)
            } else if refunded >= limits.tasks {
                Some(Stop::Refunds)
            } else if limits.posts.is_some_and(|most| posted >= most) {
                Some(Stop::PostLimit)
            } else if spent.saturating_add(limits.price) > limits.budget {
                Some(Stop::Budget)
            } else if !crate::ladder::covered(limits.price, reserved, market.wallet()?) {
                Some(Stop::Wallet)
            } else if let Some(units) = limits.gas {
                let (have, price) = market.ether()?;
                let need = units.saturating_mul(price).saturating_mul(GAS_HEADROOM);
                (have < need).then_some(Stop::Gas { have, need })
            } else {
                None
            };
            if let Some(stop) = stop {
                record(Entry::Stopped {
                    reason: stop.to_string(),
                })?;
                return Ok(Next::Stop(stop));
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
                return Ok(Next::Wait(POLL));
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
                    return Ok(Next::Moved);
                }
                Some(Withdrawal::WindowEnded)
            } else if market.desk_open(task.id)? {
                return Ok(Next::Wait(POLL));
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
        Some(Open::Signed(_, order)) => match follow(journal, market, &order)? {
            Followed::Moved => {}
            Followed::Waiting(_) => return Ok(Next::Wait(POLL)),
        },
    }
    Ok(Next::Moved)
}

/// What one look at a signed order did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Followed {
    /// It sent a transaction or journaled an outcome.
    Moved,
    /// Nothing is due yet: the order is funded before its delivery
    /// deadline, or unfunded before its funding deadline (which, in seconds
    /// since the epoch).
    Waiting(Waiting),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waiting {
    Delivery { deliver_by: u64 },
    Funding { fund_by: u64 },
}

/// The one decider for a signed order (rule 5, and gap 2 of the merge
/// ladder): settled is checked and journaled; funded past its delivery
/// deadline is refunded; refunded is claimed back and journaled; unfunded
/// past its funding deadline is journaled lapsed. `step` and `finish` both
/// come here.
fn follow(journal: &Shared, market: &mut dyn Market, order: &OrderRef) -> Res<Followed> {
    let record = |entry: Entry| -> Res<()> { locked(journal)?.record(entry) };
    match market.phase(order)? {
        Phase::Settled => {
            let verdict = market.check_settled(order)?;
            let block = market.block()?;
            if verdict.is_ok() {
                // Paid before `Settled` is journaled: a crash between the
                // two pays nothing twice (the token holds each nonce), and
                // a crash before either retries the payouts.
                let (cap, referral) = {
                    let journal = locked(journal)?;
                    let ledger = journal.ledger();
                    let cap = match &ledger.open {
                        Some(Open::Signed(task, _)) => task.price,
                        _ => order.amount,
                    };
                    let referral = ledger
                        .referrals
                        .iter()
                        .find(|(d, ..)| *d == order.digest)
                        .map(|(_, r, n)| (*r, *n));
                    (cap, referral)
                };
                for line in market.savings(order, cap, referral)? {
                    record(line)?;
                }
            }
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
            market.refund(order)?;
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
        Phase::Funded => {
            return Ok(Followed::Waiting(Waiting::Delivery {
                deliver_by: order.order.deliver_by,
            }));
        }
        Phase::Empty => {
            return Ok(Followed::Waiting(Waiting::Funding {
                fund_by: order.order.fund_by,
            }));
        }
    }
    Ok(Followed::Moved)
}

/// Why `finish` did not end a journal's signed order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfinished {
    /// The journal has no signed order open (what it has, in words).
    NoSignedOrder(String),
    /// The order is funded and its delivery deadline has not passed: the
    /// vault refuses `refund` until then, and the seller may still settle.
    NotYetRefundable { deliver_by: u64, now: u64 },
    /// The order is not funded and its funding deadline has not passed: it
    /// may still be funded.
    NotYetLapsed { fund_by: u64, now: u64 },
}
impl std::fmt::Display for Unfinished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignedOrder(open) => {
                write!(f, "the journal has no signed order open (open: {open})")
            }
            Self::NotYetRefundable { deliver_by, now } => write!(
                f,
                "the order is funded and its delivery deadline {deliver_by} has not passed (now {now}); the vault refuses a refund until then"
            ),
            Self::NotYetLapsed { fund_by, now } => write!(
                f,
                "the order is not funded and its funding deadline {fund_by} has not passed (now {now})"
            ),
        }
    }
}
impl std::error::Error for Unfinished {}

/// `task-refund`: follow the journal's signed order to its end now, without
/// posting or waiting: refund and claim a funded order past its delivery
/// deadline, journal a settlement or a lapse. Refuses, changing nothing,
/// when nothing is due yet.
pub fn finish(journal: &Shared, market: &mut dyn Market) -> Res<()> {
    finish_beside(journal, &[], market)
}

/// `finish` for one row of a desk with several: the deposits are checked
/// against this journal and the other rows' (`attribute_all`).
pub fn finish_beside(journal: &Shared, others: &[Shared], market: &mut dyn Market) -> Res<()> {
    attribute_all(&[std::slice::from_ref(journal), others].concat(), market)?;
    let mut moved = false;
    loop {
        let open = locked(journal)?.ledger().open.clone();
        let order = match open {
            Some(Open::Signed(_, order)) => order,
            // The order reached its end in this call.
            None if moved => return Ok(()),
            None => return Err(Unfinished::NoSignedOrder("nothing".into()).into()),
            Some(Open::Intent(task)) => {
                let open = format!("intent {}", hex(&task.id));
                return Err(Unfinished::NoSignedOrder(open).into());
            }
            Some(Open::Posted(task)) => {
                let open = format!("posted {}", hex(&task.id));
                return Err(Unfinished::NoSignedOrder(open).into());
            }
        };
        match follow(journal, market, &order)? {
            Followed::Moved => moved = true,
            Followed::Waiting(Waiting::Delivery { deliver_by }) => {
                let now = market.now()?;
                return Err(Unfinished::NotYetRefundable { deliver_by, now }.into());
            }
            Followed::Waiting(Waiting::Funding { fund_by }) => {
                let now = market.now()?;
                return Err(Unfinished::NotYetLapsed { fund_by, now }.into());
            }
        }
    }
}

/// Close a bounty: leave nothing open on the board and say so in the
/// journal. An intent is resolved as on a restart; a post nobody has been
/// signed for is withdrawn. A signed order cannot be closed over: its
/// authorization has left this buyer, so the journal has to follow it to a
/// settlement, a refund or a lapse first (`run` does that).
pub fn close(journal: &Shared, market: &mut dyn Market) -> Res<()> {
    close_beside(journal, &[], market)
}

/// `close` for one row of a desk with several: the deposits are checked
/// against this journal and the other rows' (`attribute_all`).
pub fn close_beside(journal: &Shared, others: &[Shared], market: &mut dyn Market) -> Res<()> {
    attribute_all(&[std::slice::from_ref(journal), others].concat(), market)?;
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

/// What every row of one desk shares: the deployment, the board, the
/// buyer's keys, and the one iroh node, listener and desk it serves on. A
/// post names the node, and the node key is the buyer's, so one key has one
/// node; one `Desk` holds every task it opened, by ID, and answers for every
/// row (proofs/commerce/LadderMulti.lean).
pub(crate) struct Hub {
    world: World,
    board: Board,
    keys: Keys,
    bind: String,
    relay: iroh_net::Relay,
    node: String,
    desk: Arc<Mutex<Desk>>,
    store: crate::blobs::Store,
    /// The endpoint, until `listen` serves on it.
    endpoint: Option<iroh::Endpoint>,
    /// The listener and the runtime it runs on, kept for as long as the hub.
    router: Option<iroh::protocol::Router>,
    runtime: tokio::runtime::Runtime,
}

/// The real market for one row: the hub it shares, and the row's own
/// statement, terms, journal and status file.
pub(crate) struct Live {
    hub: Arc<Hub>,
    /// The statement, or why it could not be read. A missing statement
    /// ends nothing by itself: a signed order is still followed, and an
    /// open post is withdrawn with this as the reason (R-3).
    statement: Result<Statement, String>,
    program: Hash,
    /// Seconds from posting to the funding and the delivery deadline.
    funding_window: u64,
    delivery_window: u64,
    /// Where a settled artifact that passes the checker is also written,
    /// with its order (`post-tasks`). `None` for the standing bounty.
    delivered: Option<PathBuf>,
    journal: Shared,
    /// The status file (R-5) and the last error it reported.
    status: PathBuf,
    last_error: Option<(u64, String)>,
    /// Tasks prepared and not yet posted.
    prepared: Vec<(Hash, Task)>,
    /// What the other rows could still be funded for, as the last step
    /// was told (`Market::reserve`): payouts never dig into it.
    reserved: u64,
}

impl Live {
    /// Pay `shares` one at a time with the buyer's wallet and its own gas,
    /// and say how each ended as a journal line. An RPC failure leaves the
    /// share owed.
    fn pay_shares(&mut self, shares: &[crate::payout::Share]) -> Res<Vec<Entry>> {
        let world = &self.hub.world;
        let domain = crate::relay::transfer::domain_separator(
            &world.domain.name,
            &world.domain.version,
            world.chain.id,
            world.token,
        );
        let mut wallet = crate::payout::ChainWallet {
            chain: &world.chain,
            token: world.token,
            key: &self.hub.keys.wallet,
            committed: u128::from(self.reserved),
        };
        let now = wall_clock()?;
        let mut lines = Vec::new();
        for share in shares {
            let line = match crate::payout::pay(
                std::slice::from_ref(share),
                &mut wallet,
                &self.hub.keys.wallet,
                &domain,
                now,
                3_600,
            ) {
                Ok(out) => match out.into_iter().next().map(|(_, p)| p) {
                    Some(crate::payout::Paid::Sent(tx)) => {
                        println!(
                            "bounty: paid {} to {} for order {} in tx {tx}",
                            share.amount,
                            hex(&share.party),
                            hex(&share.order)
                        );
                        Entry::Paid {
                            share: share.clone(),
                            transaction: Some(tx),
                        }
                    }
                    Some(crate::payout::Paid::AlreadyPaid) => Entry::Paid {
                        share: share.clone(),
                        transaction: None,
                    },
                    Some(crate::payout::Paid::Waiting) | None => Entry::Owed {
                        share: share.clone(),
                    },
                },
                Err(error) => {
                    println!("bounty: degraded: a share stays owed: {error}");
                    Entry::Owed {
                        share: share.clone(),
                    }
                }
            };
            lines.push(line);
        }
        Ok(lines)
    }
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
        self.hub.desk.lock().map_err(|_| "desk poisoned".into())
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
            asset: self.hub.world.token,
            maximum_amount: U256::from(price).to_be_bytes(),
            verifier: self.hub.world.verifier,
            program: self.program,
            fund_by,
            deliver_by,
            buyer_node: board::node_bytes(&self.hub.node)?,
            buyer_key_binding: self.hub.keys.binding(),
            salt,
            buyer_address: crate::watch::posted_hint(&self.hub.bind, &self.hub.relay)?,
        })
    }
    fn id_of(&self, task: &Task) -> Hash {
        nucleus_board_reference::id(
            self.hub.world.chain.id,
            self.hub.board.address,
            self.hub.keys.address(),
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
    fn reserve(&mut self, reserved: u64) {
        self.reserved = reserved;
    }
    fn savings(
        &mut self,
        order: &OrderRef,
        cap: u64,
        referral: Option<(Address, Hash)>,
    ) -> Res<Vec<Entry>> {
        // Attribution, when the desk is given a library and reads every
        // settlement of its vault; otherwise no author is paid.
        let attributed = match crate::attribution::Library::from_environment()? {
            None => None,
            Some(library) => {
                let from = std::env::var(crate::attribution::FROM_VARIABLE)
                    .ok()
                    .and_then(|t| t.trim().parse().ok())
                    .unwrap_or(0);
                let settled = crate::attribution::read_settlements(
                    &self.hub.world.chain,
                    self.hub.world.deployment.vault,
                    from,
                )?;
                crate::attribution::attribute(&settled, &library, &order.digest)
            }
        };
        let authors = attributed
            .as_ref()
            .map(|a| a.authors.clone())
            .unwrap_or_default();
        if let Some(a) = &attributed {
            self.desk()?.publish_attribution(&a.published);
        }
        let split = qed_savings::split(
            &qed_savings::Rule::MODEL,
            u128::from(cap),
            u128::from(order.amount),
            referral.is_some(),
            authors.len() as u128,
        );
        let shares =
            crate::payout::shares(order.digest, referral.map(|(r, _)| r), &authors, &split);
        if shares.is_empty() {
            return Ok(vec![]);
        }
        println!(
            "bounty: order {} saved {} under its cap; {} shares to pay",
            hex(&order.digest),
            cap.saturating_sub(order.amount),
            shares.len()
        );
        self.pay_shares(&shares)
    }
    fn pay_owed(&mut self, owed: &[crate::payout::Share]) -> Res<Vec<Entry>> {
        let lines = self.pay_shares(owed)?;
        // Only lines that change something: a share still owed is already
        // journaled owed.
        Ok(lines
            .into_iter()
            .filter(|l| matches!(l, Entry::Paid { .. }))
            .collect())
    }
    fn now(&mut self) -> Res<u64> {
        wall_clock()
    }
    fn block(&mut self) -> Res<u64> {
        self.hub.board.latest_block()
    }
    fn wallet(&mut self) -> Res<u64> {
        units(self.hub.world.balance(self.hub.keys.address())?)
    }
    fn ether(&mut self) -> Res<(u128, u128)> {
        // What `Chain::send` offers per gas: the node's price plus 5 %.
        let price = self
            .hub
            .world
            .chain
            .rpc("eth_gasPrice", json!([]))?
            .as_str()
            .and_then(|text| u128::from_str_radix(text.trim_start_matches("0x"), 16).ok())
            .ok_or("eth_gasPrice: a quantity expected")?
            .saturating_mul(21)
            / 20;
        Ok((
            self.hub.world.chain.balance(self.hub.keys.address())?,
            price,
        ))
    }
    fn prepare(&mut self, price: u64) -> Res<TaskRef> {
        let now = wall_clock()?;
        let salt = random32()?;
        let task = self.task_with(
            price,
            now + self.funding_window,
            now + self.delivery_window,
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
        let (posted_id, receipt) = self.hub.board.post(&self.hub.keys.wallet, &posted)?;
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
        let poster = self.hub.world.chain.call(
            [0; 20],
            self.hub.board.address,
            &nucleus_board_reference::poster_of_call(task),
        )?;
        Ok(poster.get(12..32) == Some(&self.hub.keys.address()[..]))
    }
    fn desk_open(&mut self, task: Hash) -> Res<bool> {
        let mut desk = self.desk()?;
        // A window that is due closes here as well as on a seller's request.
        desk.tick();
        Ok(desk.open_for_offers(&task))
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
        if self.hub.board.withdrawn(task.id)? {
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
        let buyer = hex(&self.hub.keys.address());
        let count = |block: &str| -> Res<Value> {
            self.hub
                .world
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
        let (open, posted, settled, refunded, failures, spent) = match locked(&self.journal) {
            Ok(journal) => {
                let ledger = journal.ledger();
                (
                    ledger.open.clone(),
                    ledger.posted,
                    ledger.settled,
                    ledger.refunded,
                    ledger.failures,
                    ledger.spent,
                )
            }
            Err(_) => (None, 0, 0, 0, 0, 0),
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
            "lastRpcAnswer": self.hub.world.chain.last_answer(),
            "open": open,
            "lastError": self.last_error.as_ref().map(|(at, error)| json!({"at": at, "error": error})),
            "posted": posted,
            "settled": settled,
            "refunded": refunded,
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
        if self.hub.board.withdrawn(task)? {
            return Ok("(already withdrawn)".into());
        }
        let receipt = self.hub.board.withdraw(&self.hub.keys.wallet, task)?;
        println!(
            "bounty: withdrew task {} in tx {}",
            hex(&task),
            receipt.transaction
        );
        Ok(receipt.transaction)
    }
    fn phase(&mut self, order: &OrderRef) -> Res<Phase> {
        Ok(match phase_of(&self.hub.world, order.digest)? {
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
            self.hub.world.deployment.rules.form(),
            &self.hub.world.chain,
            self.hub.world.deployment.vault,
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
        let recorded = self.hub.world.chain.call(
            [0; 20],
            self.hub.world.deployment.vault,
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
                    if let Some(dir) = &self.delivered {
                        fs::create_dir_all(dir)?;
                        fs::write(dir.join("delivered.ndjson"), &artifact)?;
                        fs::write(
                            dir.join("order.json"),
                            serde_json::to_vec_pretty(&WireOrder::from_order(&order.order))?,
                        )?;
                    }
                    Ok(())
                }
                Err(refusal) => Err(format!("{refusal:?}")),
            },
        )
    }
    fn refund(&mut self, order: &OrderRef) -> Res<String> {
        let receipt = self.hub.world.chain.send(
            &self.hub.keys.wallet,
            Some(self.hub.world.deployment.vault),
            0,
            &refund_data(self.hub.world.deployment.rules.form(), &order.order),
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
        if self.hub.world.deployment.rules.form() == vault::Form::Second {
            return Ok("(paid by the refund itself)".into());
        }
        let buyer = self.hub.keys.address();
        if self.hub.world.owed(buyer)?.is_zero() {
            return Ok("(nothing owed)".into());
        }
        let receipt = self.hub.world.chain.send(
            &self.hub.keys.wallet,
            Some(self.hub.world.deployment.vault),
            0,
            &third::claimCall {
                payee: A::from(buyer),
                asset: A::from(self.hub.world.token),
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
        buyer[12..].copy_from_slice(&self.hub.keys.address());
        let logs = self.hub.world.chain.logs(
            &json!({
                "address": hex(&self.hub.world.deployment.vault),
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
        "bounty-ledger: {} lines; posted {}; settled {} (the tasks used up); refunded {}; withdrawn for this buyer's failures {}; spent {}; open: {open}; checkpoint block {}",
        ledger.lines,
        ledger.posted,
        ledger.settled,
        ledger.refunded,
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
        // The standing bounty posts again after a window ends, and does not
        // check its ether (unchanged by the ladder's gaps, 2026-11-16).
        posts: None,
        gas: None,
    };
    if limits.price == 0 || limits.price > limits.budget {
        return Err("the price must be positive and within the budget".into());
    }
    // The hint is part of each post's ID: one no seller takes would be paid
    // for and could never be answered (`bounty-close` still withdraws one).
    crate::watch::posted_hint(bind, &iroh_net::Relay::from_environment()?)?;
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
            "bounty: price {} budget {} tasks {} pause {}s; journal has spent {} over {} posts, {} settled (the tasks used up), {} refunded and {} withdrawn for this buyer's failures",
            limits.price,
            limits.budget,
            limits.tasks,
            limits.pause,
            ledger.spent,
            ledger.posted,
            ledger.settled,
            ledger.refunded,
            ledger.failures
        );
    }
    let stop = run(limits, &journal, &mut market)?;
    let journal = locked(&journal)?;
    println!(
        "bounty: stopped: {stop}; spent {} over {} posts ({} settled)",
        journal.ledger().spent,
        journal.ledger().posted,
        journal.ledger().settled
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
    let statement_path = statement;
    let statement = fs::read(statement_path)
        .map_err(|error| format!("the statement file {statement_path} cannot be read: {error}"));
    let post_window: u64 = post_window.parse()?;
    let terms = Terms {
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
        program: unhex(program)?
            .try_into()
            .map_err(|_| "program id length")?,
        funding_window: post_window,
        delivery_window: post_window + DELIVERY_AFTER_FUNDING,
    };
    live_with(
        deployment,
        board_address,
        keyfile,
        statement,
        terms,
        Path::new(journal),
        bind,
        None,
    )
}

/// What a post commits to beyond the statement: the policy's claim, axioms
/// and artifact limit, the program, and the two windows from posting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub claim: String,
    pub permitted_axioms: Vec<String>,
    pub maximum_artifact_bytes: u32,
    pub program: Hash,
    pub funding_window: u64,
    pub delivery_window: u64,
}

/// The live market for a statement (or why it cannot be read) and terms,
/// and the journal at `journal_path`: a hub serving one row. The standing
/// bounty and a one-row `post-tasks` start here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn live_with(
    deployment: &str,
    board_address: &str,
    keyfile: &str,
    statement: Result<Vec<u8>, String>,
    terms: Terms,
    journal_path: &Path,
    bind: &str,
    delivered: Option<PathBuf>,
) -> Res<(Live, Shared)> {
    let mut hub = Hub::open(deployment, board_address, keyfile, bind)?;
    let journal = hub.journal(journal_path)?;
    hub.listen(std::slice::from_ref(&journal), journal_path)?;
    let market = Arc::new(hub).row(statement, terms, journal.clone(), journal_path, delivered)?;
    Ok((market, journal))
}

impl Hub {
    /// The deployment, board and keys, and the node: bound, not yet serving.
    pub(crate) fn open(
        deployment: &str,
        board_address: &str,
        keyfile: &str,
        bind: &str,
    ) -> Res<Self> {
        let world = World::read(deployment)?;
        if !Path::new(keyfile).exists() {
            return Err("key file does not exist".into());
        }
        let keys = Keys::load_or_create(keyfile)?;
        let board = Board {
            chain: world.chain.clone(),
            address: address_arg(board_address)?,
        };
        if board.vault()? != world.deployment.vault {
            return Err("the board is for another vault than this deployment's".into());
        }
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
        let mut desk = Desk::new(
            world.deployment.clone(),
            world.domain.clone(),
            keys.wallet.clone(),
        );
        desk.accept_bases(world.bases.clone());
        if let Some(seconds) = crate::desk::window_from_environment()? {
            println!(
                "bounty: offers are collected for {seconds} s after the first, and the least is signed for"
            );
            desk.collect_offers(seconds);
        }
        Ok(Self {
            world,
            board,
            keys,
            bind: bind.to_owned(),
            relay,
            node,
            desk: Arc::new(Mutex::new(desk)),
            store,
            endpoint: Some(endpoint),
            router: None,
            runtime,
        })
    }

    /// The journal at `path` for this chain, vault, board, token and buyer,
    /// created if absent.
    pub(crate) fn journal(&self, path: &Path) -> Res<Shared> {
        Ok(Arc::new(Mutex::new(Journal::open(
            path,
            Header {
                chain: self.world.chain.id,
                vault: self.world.deployment.vault,
                board: self.board.address,
                token: self.world.token,
                buyer: self.keys.address(),
                block: self.board.latest_block()?,
            },
        )?)))
    }

    /// Serve the desk for these rows' journals. A signature is journaled,
    /// before it leaves the desk, in the journal of the row whose post it
    /// is for (rule 3; `ladder::route`, `offer_routed` in
    /// proofs/commerce/LadderMulti.lean); a signature for a task no row
    /// holds is not released. Every offer and review the desk answers is
    /// recorded beside the first row's journal, and its signed summary
    /// served at GET /deliveries (docs/rfcs/qed-deliveries-2026-11-14.md):
    /// one node serves one summary.
    pub(crate) fn listen(&mut self, journals: &[Shared], record_beside: &Path) -> Res<()> {
        let endpoint = self.endpoint.take().ok_or("the desk is already serving")?;
        let mut desk = self.desk.lock().map_err(|_| "desk poisoned")?;
        let for_desk = journals.to_vec();
        desk.record_signatures(Box::new(move |signed| {
            crate::ladder::record_signature(&for_desk, signed)?;
            println!(
                "bounty: signed order {} for seller {} at {}",
                hex(&signed.digest),
                hex(&signed.order.seller),
                U256::from_be_bytes(signed.order.amount)
            );
            Ok(())
        }));
        // The authors' wallets come from `ours.txt` beside the journal;
        // without it every seller is outside.
        let ours_path = record_beside.with_file_name("ours.txt");
        let ours = crate::deliveries::ours(&ours_path)?;
        println!(
            "bounty: delivery record {}; {} of the authors' wallets in {}",
            record_beside.with_extension("deliveries.jsonl").display(),
            ours.len(),
            ours_path.display()
        );
        desk.record_attempts(Box::new(crate::deliveries::Record::open(
            &record_beside.with_extension("deliveries.jsonl"),
            &record_beside.with_extension("deliveries.jws"),
            self.keys.address(),
            self.keys.possession.clone(),
            ours,
        )?));
        drop(desk);
        self.router = Some({
            let _guard = self.runtime.enter();
            iroh_net::serve_with(endpoint, self.desk.clone(), Some(&self.store))
        });
        println!(
            "bounty: buyer {} node {} (relay {:?})",
            hex(&self.keys.address()),
            self.node,
            self.relay
        );
        Ok(())
    }

    /// The market for one row of this desk.
    pub(crate) fn row(
        self: Arc<Self>,
        statement: Result<Vec<u8>, String>,
        terms: Terms,
        journal: Shared,
        journal_path: &Path,
        delivered: Option<PathBuf>,
    ) -> Res<Live> {
        let statement = match statement {
            Ok(bytes) => Ok(Statement {
                policy: Policy {
                    statement_sha256: Sha256::digest(&bytes).into(),
                    claim: terms.claim.clone(),
                    permitted_axioms: terms.permitted_axioms.clone(),
                    maximum_artifact_bytes: terms.maximum_artifact_bytes,
                },
                blake3: self
                    .runtime
                    .block_on(crate::blobs::add(&self.store, bytes.clone()))?,
                bytes,
            }),
            Err(why) => {
                println!("bounty: degraded: {why}");
                Err(why)
            }
        };
        Ok(Live {
            hub: self,
            statement,
            program: terms.program,
            funding_window: terms.funding_window,
            delivery_window: terms.delivery_window,
            delivered,
            journal,
            status: journal_path.with_extension("status.json"),
            last_error: None,
            prepared: vec![],
            reserved: 0,
        })
    }
}

#[cfg(test)]
mod tests;
