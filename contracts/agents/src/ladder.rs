//! One desk holding several ladder rows: one process, one iroh node, one
//! listener, and one journal per row (`OUT_DIR/journal.jsonl`), with offers
//! routed by task ID and the wallet checked across the rows.
//!
//!   nucleus-buyer post-tasks DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...
//!
//! Why one process (docs/rfcs/qed-ladder-multi-row-desk-2026-11-27.md):
//! every post names the buyer's node, and the node key is the buyer's, so N
//! one-row processes on one key are N processes claiming one node; the
//! relay keeps one active connection per node, so a seller reaches only the
//! desk that connected last. And a one-row desk checks every deposit from
//! the shared wallet against its own journal (rule 8), so one row's funded
//! order stops every other row's restart.
//!
//! The model is proofs/commerce/LadderMulti.lean. Each row is still the
//! one-shot journal of `tasks.rs` (`LadderPost.lean`): `bounty::step` with
//! `tasks::limits`. What a desk with several rows adds is here, each rule
//! named after the definition it mirrors, and `the_lean_table` below replays
//! the model's worked examples G1 to G8:
//! - `route`: a signature goes to the journal of the row whose post it is
//!   for; for a task no row holds, nothing is signed (`offer_routed`,
//!   `offer_refused`);
//! - `exposure` and `covered`: a row posts only when the wallet covers its
//!   cap on top of what every other row could still be funded for
//!   (`no_overcommit`, `funding_covered`);
//! - `unexplained`: the restart's deposit check is over the union of the
//!   rows' journals (`restart_admitted`);
//! - `run`: the rows are stepped in turn in one thread, so the wallet's one
//!   nonce lane is used by one row at a time, and a row that stops or fails
//!   leaves the others running; nothing a row does writes another row's
//!   journal (`journal_frame`).
use crate::bounty::{
    self, Health, Ledger, Limits, Market, Next, Open, OrderRef, Phase, Shared, Stop,
};
use crate::desk::Signed;
use crate::prelude::*;
use nucleus_proof_commerce::Hash;

/// `route`: the row whose journal holds the post `task`, or `None` when no
/// row does.
pub fn route(opens: &[Option<Open>], task: Hash) -> Option<usize> {
    opens
        .iter()
        .position(|open| matches!(open, Some(Open::Posted(posted)) if posted.id == task))
}

/// `expo`: what a row could still be funded for. Its cap while an intent or
/// a post is open; its cap while a signed order is unfunded and inside its
/// funding window; nothing otherwise (a funded order's deposit has already
/// left the wallet). `phase` is asked only for a signed order inside its
/// window.
pub fn exposure(
    open: &Option<Open>,
    now: u64,
    phase: &mut dyn FnMut(&OrderRef) -> Res<Phase>,
) -> Res<u64> {
    Ok(match open {
        None => 0,
        Some(Open::Intent(task) | Open::Posted(task)) => task.price,
        Some(Open::Signed(task, _)) if now > task.fund_by => 0,
        Some(Open::Signed(task, order)) => match phase(order)? {
            Phase::Empty => task.price,
            Phase::Funded | Phase::Settled | Phase::Refunded => 0,
        },
    })
}

/// `coveredWith .model`: a row's cap on top of what the desk has committed
/// is within the wallet.
pub fn covered(price: u64, committed: u64, wallet: u64) -> bool {
    price.saturating_add(committed) <= wallet
}

/// `explainsWith .model`, negated: the first deposit that no row's journal
/// signed for.
pub fn unexplained(ledgers: &[Ledger], deposits: &[Hash]) -> Option<Hash> {
    deposits
        .iter()
        .find(|digest| !ledgers.iter().any(|ledger| ledger.signed.contains(digest)))
        .copied()
}

/// The desk's `on_sign`: journal a signature, before it leaves the desk, in
/// the journal of the row whose post it is for. An error releases nothing.
pub fn record_signature(journals: &[Shared], signed: &Signed) -> Result<(), String> {
    let amount = u64::try_from(U256::from_be_bytes(signed.order.amount))
        .map_err(|_| "amount above u64".to_owned())?;
    let mut opens = vec![];
    for journal in journals {
        let journal = journal.lock().map_err(|_| "journal poisoned".to_owned())?;
        opens.push(journal.ledger().open.clone());
    }
    let row = route(&opens, signed.id)
        .ok_or_else(|| format!("no row of this desk holds task {}", hex(&signed.id)))?;
    journals[row]
        .lock()
        .map_err(|_| "journal poisoned".to_owned())?
        .record(bounty::Entry::Signed {
            task: signed.id,
            order: OrderRef {
                digest: signed.digest,
                amount,
                order: signed.order.clone(),
            },
        })
        .map_err(|e| e.to_string())
}

/// One row of a desk.
pub struct Row<'a> {
    pub name: String,
    pub limits: Limits,
    pub journal: Shared,
    pub market: &'a mut dyn Market,
}

/// How a row ended: its `Stop`, or the error that stopped it.
pub type Ended = Result<Stop, String>;

fn open_of(journal: &Shared) -> Res<Option<Open>> {
    Ok(journal
        .lock()
        .map_err(|_| "journal poisoned")?
        .ledger()
        .open
        .clone())
}

/// `committed` over every row but `row`: what they could still be funded
/// for, each asked of its own market.
fn reserved_for(rows: &mut [Row<'_>], row: usize) -> Res<u64> {
    let mut total: u64 = 0;
    for (index, other) in rows.iter_mut().enumerate() {
        if index == row {
            continue;
        }
        let open = open_of(&other.journal)?;
        let now = other.market.now()?;
        let market = &mut *other.market;
        total = total.saturating_add(exposure(&open, now, &mut |order| market.phase(order))?);
    }
    Ok(total)
}

/// Seconds before a round that failed transiently runs again: doubled after
/// each such round, up to the most (R-2, as `bounty::run`).
const RETRY_FIRST: u64 = 15;
const RETRY_MOST: u64 = 300;
/// Seconds between rounds when no row moved and none asked for less.
const POLL: u64 = 15;

/// Step every row in turn until each has stopped. Before the first round,
/// every deposit from this buyer must be explained by one of the journals;
/// a deposit none of them signed for stops the whole desk, since it is the
/// wallet's. A row that stops (its `Stop`) or fails (any error that is not
/// transient) is reported, its post is taken off the desk, and the other
/// rows go on. `idle` waits between rounds when no row moved.
pub fn run(rows: &mut [Row<'_>], idle: &mut dyn FnMut(u64) -> Res<()>) -> Res<Vec<Ended>> {
    let journals: Vec<Shared> = rows.iter().map(|row| row.journal.clone()).collect();
    let mut ended: Vec<Option<Ended>> = rows.iter().map(|_| None).collect();
    let mut first = vec![true; rows.len()];
    let mut attributed = false;
    let mut failures: u32 = 0;
    loop {
        let mut transient = false;
        if !attributed {
            match bounty::attribute_all(&journals, &mut *rows[0].market) {
                Ok(()) => attributed = true,
                Err(error) if crate::chain::is_transient(&*error) => {
                    println!("ladder: degraded: checking deposits: {error}");
                    transient = true;
                }
                Err(error) => {
                    for row in rows.iter_mut() {
                        row.market.report(&Health::Failed {
                            error: error.to_string(),
                        });
                    }
                    return Err(error);
                }
            }
        }
        let mut moved = false;
        let mut wait = POLL;
        if attributed {
            for index in 0..rows.len() {
                if ended[index].is_some() {
                    continue;
                }
                let outcome = open_of(&rows[index].journal).and_then(|open| {
                    let reserved = if open.is_none() {
                        reserved_for(rows, index)?
                    } else {
                        0
                    };
                    let row = &mut rows[index];
                    bounty::step(
                        row.limits,
                        &row.journal,
                        &mut *row.market,
                        first[index],
                        reserved,
                    )
                });
                let row = &mut rows[index];
                match outcome {
                    Ok(next) => {
                        row.market.report(&Health::Ok);
                        first[index] = false;
                        match next {
                            Next::Stop(stop) => {
                                println!("ladder: {}: stopped: {stop}", row.name);
                                ended[index] = Some(Ok(stop));
                                moved = true;
                            }
                            Next::Wait(seconds) => wait = wait.min(seconds),
                            Next::Moved => moved = true,
                        }
                    }
                    Err(error) if crate::chain::is_transient(&*error) => {
                        println!("ladder: {}: degraded: {error}", row.name);
                        row.market.report(&Health::Degraded {
                            error: error.to_string(),
                            failures: failures + 1,
                            retry_in: RETRY_FIRST,
                        });
                        transient = true;
                    }
                    Err(error) => {
                        println!(
                            "ladder: {}: failed: {error}; the other rows go on",
                            row.name
                        );
                        row.market.report(&Health::Failed {
                            error: error.to_string(),
                        });
                        // A row that failed stops answering offers, as its
                        // own process did when it exited.
                        if let Ok(Some(Open::Posted(task))) = open_of(&row.journal) {
                            let _ = row.market.close_desk(task.id);
                        }
                        ended[index] = Some(Err(error.to_string()));
                    }
                }
            }
        }
        if ended.iter().all(Option::is_some) {
            return Ok(ended.into_iter().flatten().collect());
        }
        if transient {
            failures += 1;
            idle(
                RETRY_FIRST
                    .saturating_mul(1 << (failures - 1).min(5))
                    .min(RETRY_MOST),
            )?;
        } else {
            failures = 0;
            if !moved {
                idle(wait)?;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
