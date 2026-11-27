//! A buyer posting one task per task file, each journaled, and waiting at
//! one desk until every task ends; and the two commands that finish a task
//! the process could not.
//!
//!   nucleus-buyer post-tasks    DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...
//!   nucleus-buyer task-withdraw DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...
//!   nucleus-buyer task-refund   DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...
//!
//! A task file says what `post` fixes in the binary: which statement, which
//! declaration is the claim, which axioms the checker may admit, how large a
//! delivered artifact may be, the program that judges it, the most the buyer
//! pays, and how long the post stays open for funding and for delivery:
//!
//!   {"name": "gate-soundness",
//!    "statement": "statement.ndjson",          (relative to the task file)
//!    "claim": "Nucleus.Claim",
//!    "permittedAxioms": ["propext", "Classical.choice", "Quot.sound"],
//!    "maximumArtifactBytes": 90000,
//!    "program": "0x…",
//!    "maximumPrice": 2000000,
//!    "fundingWindowSeconds": 1209600,
//!    "deliveryWindowSeconds": 2592000}
//!
//! Both windows run from the moment of posting.
//!
//! Since 2026-11-16 (the merge ladder's gaps 1 to 3, section 10 of
//! docs/rfcs/qed-nucleus-merge-ladder-2026-11-14.md) a task is the standing
//! bounty's journal run as a one-shot: `bounty::run` with `Limits { tasks: 1,
//! posts: Some(1), gas: Some(LADDER_GAS) }` over `OUT_DIR/journal.jsonl`.
//! The journal's moves are `Ledger::apply`'s; nothing here decides a move.
//! The semantics, with the theorems, are proofs/commerce/LadderPost.lean:
//! - the intent is journaled before the post, and a restart resolves it from
//!   the board and the buyer's pending nonce, never by posting again: one
//!   journal makes at most one post (`at_most_one_post`);
//! - `task-withdraw` withdraws a journaled post nobody was signed for
//!   (`bounty::close`; `journaled_post_is_withdrawable`);
//! - `task-refund` refunds and claims back a funded order past its delivery
//!   deadline (`bounty::finish`; `late_funded_order_is_refundable`), and
//!   refuses before it;
//! - nothing is posted unless the wallet holds the cap in tokens
//!   (`Stop::Wallet`) and `LADDER_GAS` at twice today's price in ether
//!   (`Stop::Gas`; `intent_only_when_covered`).
//!
//! One task per journal, several journals per desk (since 2026-11-27,
//! `ladder.rs`; proofs/commerce/LadderMulti.lean): each `OUT_DIR TASK.json`
//! pair is a row with its own `OUT_DIR/journal.jsonl`, and every row is
//! served by one process on the buyer's one node. Offers are routed to a
//! row by task ID; a row posts only when the wallet covers its cap on top of
//! what the other rows could still be funded for; a restart checks the
//! deposits against the union of the rows' journals. With one pair the
//! command is the one-row desk it was from 2026-11-16, and a journal it
//! wrote resumes unchanged. From 2026-11-16 to 2026-11-27 it took one task
//! file: two ladder posts from one wallet meant two processes claiming one
//! node, of which a seller reached only the last to connect, and each
//! refused to restart over the other's deposit (rule 8 on one journal).
//! Before 2026-11-16 the command took several task files and kept nothing
//! on disk until a settlement.
use crate::bounty::{self, Limits, Shared, Stop, Terms};
use crate::ladder;
use crate::prelude::*;
use crate::relay::{MAXIMUM_GAS_PER_CALL, relayed_artifact_bytes};
use crate::statement::{PERMITTED_AXIOMS, Row};
use crate::world::*;
use nucleus_proof_commerce::Hash;
use std::{path::PathBuf, sync::Arc};

/// Gas the buyer's own transactions for one task can take, from measured
/// receipts, each with `Chain::send`'s 10 % over its estimate: `post` 58,893
/// (Base, 2026-11-13), `withdraw` 47,545 (Arbitrum Sepolia, 2026-11-16),
/// `refund` REFUND_GAS and `claim` 82,203 (Base, 2026-11-13). A task never
/// needs both a withdrawal and a refund, so the sum has room.
pub const LADDER_GAS: u128 = (58_893 + 47_545 + REFUND_GAS + 82_203) * 11 / 10;
/// `refund` on the third-form vault.
pub const REFUND_GAS: u128 = 70_000;

/// The shortest funding window a task file may ask for. The desk refuses an
/// offer that leaves less than a minute to fund; a post shorter than this
/// could not be answered at all.
pub const MINIMUM_FUNDING_WINDOW: u64 = 300;

/// One task to post.
#[derive(Clone, Debug)]
pub struct Spec {
    pub name: String,
    /// A ladder row (`"row": "S0001"`): the claim is then
    /// `Statements.S<id>.claim`, the axioms exactly the three, and the
    /// proof's module path follows from the row (`statement.rs`).
    pub row: Option<Row>,
    pub statement: Vec<u8>,
    pub policy: Policy,
    pub program: Hash,
    pub maximum: u64,
    pub funding_window: u64,
    pub delivery_window: u64,
}

/// Why a task file is refused. Nothing is posted from a refused file.
#[derive(Debug, PartialEq, Eq)]
pub enum SpecError {
    /// A field is absent or of the wrong JSON type.
    Field(&'static str),
    /// The statement is empty, or is NDJSON that does not end in a newline,
    /// so no artifact could continue it.
    Statement,
    /// The claim name is empty.
    Claim,
    /// An axiom name is empty or listed twice.
    Axiom,
    /// The artifact limit is zero or does not fit 32 bits.
    ArtifactLimit,
    /// The program ID is not 32 bytes of hex, or is zero.
    Program,
    /// The price cap is zero.
    Price,
    /// The funding window is shorter than `MINIMUM_FUNDING_WINDOW`, or the
    /// delivery window does not end after it.
    Windows,
    /// The row is not `S` and digits, or the claim is not the row's, or the
    /// axioms are not exactly the ladder's three.
    Row,
}
impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Field(name) => write!(f, "`{name}` is missing or of the wrong type"),
            Self::Statement => write!(
                f,
                "the statement is empty, or NDJSON that does not end in a newline"
            ),
            Self::Claim => write!(f, "the claim name is empty"),
            Self::Axiom => write!(f, "an axiom name is empty or listed twice"),
            Self::ArtifactLimit => write!(f, "the artifact limit is zero or too large"),
            Self::Program => write!(f, "the program ID is not 32 non-zero bytes of hex"),
            Self::Price => write!(f, "the price cap is zero"),
            Self::Windows => write!(
                f,
                "the funding window is under {MINIMUM_FUNDING_WINDOW} s or delivery does not end after it"
            ),
            Self::Row => write!(
                f,
                "the row is malformed, or its claim is not Statements.<row>.claim, or its axioms are not the three"
            ),
        }
    }
}
impl std::error::Error for SpecError {}

impl Spec {
    /// A task from its file's JSON and the bytes its `statement` path names.
    pub fn parse(value: &Value, statement: Vec<u8>) -> Result<Self, SpecError> {
        let text = |name: &'static str| value[name].as_str().ok_or(SpecError::Field(name));
        let number = |name: &'static str| value[name].as_u64().ok_or(SpecError::Field(name));
        // An artifact can continue a statement that ends at a record end: an
        // export v2 file always does (its records delimit themselves; it
        // starts with the v2 header), an NDJSON file when it ends in a
        // newline. The same rule as `ends_at_a_record_end` in the checker.
        let at_record_end = statement.starts_with(&nucleus_proof_acceptance::EXPORT_V2_MAGIC)
            || statement.last() == Some(&b'\n');
        if statement.is_empty() || !at_record_end {
            return Err(SpecError::Statement);
        }
        let claim = text("claim")?;
        if claim.is_empty() {
            return Err(SpecError::Claim);
        }
        let mut permitted_axioms: Vec<String> = vec![];
        for axiom in value["permittedAxioms"]
            .as_array()
            .ok_or(SpecError::Field("permittedAxioms"))?
        {
            let axiom = axiom.as_str().ok_or(SpecError::Field("permittedAxioms"))?;
            if axiom.is_empty() || permitted_axioms.iter().any(|a| a == axiom) {
                return Err(SpecError::Axiom);
            }
            permitted_axioms.push(axiom.to_owned());
        }
        let maximum_artifact_bytes = u32::try_from(number("maximumArtifactBytes")?)
            .ok()
            .filter(|limit| *limit > 0)
            .ok_or(SpecError::ArtifactLimit)?;
        let program: Hash = unhex(text("program")?)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .filter(|id: &Hash| *id != [0; 32])
            .ok_or(SpecError::Program)?;
        let maximum = number("maximumPrice")?;
        if maximum == 0 {
            return Err(SpecError::Price);
        }
        let funding_window = number("fundingWindowSeconds")?;
        let delivery_window = number("deliveryWindowSeconds")?;
        if funding_window < MINIMUM_FUNDING_WINDOW || delivery_window <= funding_window {
            return Err(SpecError::Windows);
        }
        let row = match value.get("row") {
            None | Some(Value::Null) => None,
            Some(row) => {
                let row = row
                    .as_str()
                    .and_then(|text| Row::parse(text).ok())
                    .ok_or(SpecError::Row)?;
                if claim != row.claim() || permitted_axioms != PERMITTED_AXIOMS {
                    return Err(SpecError::Row);
                }
                Some(row)
            }
        };
        Ok(Self {
            name: text("name")?.to_owned(),
            row,
            policy: Policy {
                statement_sha256: Sha256::digest(&statement).into(),
                claim: claim.to_owned(),
                permitted_axioms,
                maximum_artifact_bytes,
            },
            statement,
            program,
            maximum,
            funding_window,
            delivery_window,
        })
    }

    /// Read a task file; its `statement` path is relative to the file.
    pub fn read(path: &str) -> Res<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path)?)?;
        let statement = value["statement"]
            .as_str()
            .ok_or(SpecError::Field("statement"))?;
        let statement = Path::new(path)
            .parent()
            .unwrap_or(Path::new("."))
            .join(statement);
        Ok(
            Self::parse(&value, fs::read(statement)?)
                .map_err(|error| format!("{path}: {error}"))?,
        )
    }

    /// Whether a seller could ever fund an order with this task's delivery
    /// deadline on this vault. The third form refuses a deposit whose
    /// delivery deadline is more than `maximum_term` after the funding
    /// block, and a seller takes the posted deadline as the order's; a
    /// delivery window longer than the term would make the post unanswerable
    /// until late in its life.
    pub fn fits(&self, rules: &vault::Rules) -> bool {
        match rules {
            vault::Rules::Second => true,
            vault::Rules::Third { maximum_term, .. } => self.delivery_window <= *maximum_term,
        }
    }
}

/// One row of a desk: its task, its journal and its market.
struct DeskRow {
    spec: Spec,
    journal: Shared,
    market: bounty::Live,
}

/// Whether a row's journal may be created, or must already exist (the other
/// rows `task-withdraw` and `task-refund` read for rule 8 only).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Journals {
    Create,
    OthersExist,
}

/// The terms a post commits to, from its task file.
fn terms_of(spec: &Spec) -> Terms {
    Terms {
        claim: spec.policy.claim.clone(),
        permitted_axioms: spec.policy.permitted_axioms.clone(),
        maximum_artifact_bytes: spec.policy.maximum_artifact_bytes,
        program: spec.program,
        funding_window: spec.funding_window,
        delivery_window: spec.delivery_window,
    }
}

/// The task files of `OUT_DIR TASK.json` pairs, refused unless each row and
/// each `OUT_DIR` is named once (a row with two journals could be posted
/// twice; two rows in one journal would refuse each other's intent).
fn read_rows(deployment: &str, pairs: &[String]) -> Res<Vec<(Spec, PathBuf)>> {
    let world = World::read(deployment)?;
    let mut rows: Vec<(Spec, PathBuf)> = vec![];
    for pair in pairs.chunks(2) {
        let [out, file] = pair else {
            return Err("task files come in OUT_DIR TASK.json pairs".into());
        };
        let spec = Spec::read(file)?;
        if !spec.fits(&world.deployment.rules) {
            return Err(format!(
                "{file}: the delivery window is longer than this vault's maximum term, so no seller could fund the order"
            )
            .into());
        }
        let out = PathBuf::from(out);
        if named_twice(&rows, &spec, &out) {
            return Err(format!(
                "{file}: its row or OUT_DIR {} is named twice; each row has one journal",
                out.display()
            )
            .into());
        }
        rows.push((spec, out));
    }
    Ok(rows)
}

/// Whether `spec` or `out` is already a row of `rows`: the same name, the
/// same ladder row, or the same `OUT_DIR` (the model's `ids.Nodup`).
fn named_twice(rows: &[(Spec, PathBuf)], spec: &Spec, out: &Path) -> bool {
    rows.iter().any(|(other, dir)| {
        other.name == spec.name || (other.row.is_some() && other.row == spec.row) || dir == out
    })
}

/// One desk for task files given as `OUT_DIR TASK.json` pairs: one hub (one
/// node, one listener), and per row `OUT_DIR/journal.jsonl`, its status
/// file and its market. With one pair this is the desk `post-tasks` ran
/// before rows could share one.
fn desk(
    deployment: &str,
    board_address: &str,
    keyfile: &str,
    bind: &str,
    pairs: &[String],
    journals: Journals,
) -> Res<Vec<DeskRow>> {
    let rows = read_rows(deployment, pairs)?;
    let mut hub = bounty::Hub::open(deployment, board_address, keyfile, bind)?;
    let mut opened = vec![];
    for (index, (spec, out)) in rows.iter().enumerate() {
        let path = out.join("journal.jsonl");
        if index > 0 && journals == Journals::OthersExist && !path.exists() {
            return Err(format!(
                "{}: no journal; the other rows' journals are read, never started",
                path.display()
            )
            .into());
        }
        fs::create_dir_all(out)?;
        opened.push((hub.journal(&path)?, path, spec.name.clone()));
    }
    let shared: Vec<Shared> = opened.iter().map(|(journal, ..)| journal.clone()).collect();
    hub.listen(&shared, &opened[0].1)?;
    let hub = Arc::new(hub);
    rows.into_iter()
        .zip(opened)
        .map(|((spec, out), (journal, path, name))| {
            let market = hub.clone().row(
                Ok(spec.statement.clone()),
                terms_of(&spec),
                journal.clone(),
                &path,
                Some(out.join(name)),
            )?;
            Ok(DeskRow {
                spec,
                journal,
                market,
            })
        })
        .collect()
}

fn usage(command: &str) -> String {
    format!(
        "usage: nucleus-buyer {command} DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]..."
    )
}

/// The arguments before the pairs, and the pairs.
fn split(command: &str, args: &[String]) -> Res<([String; 4], Vec<String>)> {
    match args {
        [deployment, board, keyfile, bind, pairs @ ..]
            if !pairs.is_empty() && pairs.len() % 2 == 0 =>
        {
            Ok((
                [
                    deployment.clone(),
                    board.clone(),
                    keyfile.clone(),
                    bind.clone(),
                ],
                pairs.to_vec(),
            ))
        }
        _ => Err(format!(
            "{} (one OUT_DIR TASK.json pair per row; each row's journal is OUT_DIR/journal.jsonl)",
            usage(command)
        )
        .into()),
    }
}

/// The one-shot limits for a task: at most one post, one settlement, the
/// cap as the whole budget, and the wallet checked in tokens and in ether.
pub fn limits(spec: &Spec) -> Limits {
    Limits {
        price: spec.maximum,
        budget: spec.maximum,
        tasks: 1,
        pause: 0,
        posts: Some(1),
        gas: Some(LADDER_GAS),
    }
}

fn ledger_of(journal: &Shared) -> Res<bounty::Ledger> {
    Ok(journal
        .lock()
        .map_err(|_| "journal poisoned")?
        .ledger()
        .clone())
}

/// `post-tasks`: post each row's task once (or resume it from its journal)
/// and follow it to its end, all rows on one desk. Exit 0 only when every
/// row ended in a settlement whose artifact the Lean checker accepted; any
/// other end is each row's typed `Stop` or error.
pub fn post_tasks(args: &[String]) -> Res<()> {
    let ([deployment, board_address, keyfile, bind], pairs) = split("post-tasks", args)?;
    let mut rows = desk(
        &deployment,
        &board_address,
        &keyfile,
        &bind,
        &pairs,
        Journals::Create,
    )?;
    // The relayer's reach, on the post's face: a seller whose artifact is
    // larger settles with its own ether (relay.rs, MAXIMUM_GAS_PER_CALL).
    let reach = relayed_artifact_bytes(MAXIMUM_GAS_PER_CALL);
    for row in &rows {
        println!(
            "post-tasks: {}: artifacts up to {} bytes; the relayer's {} gas cap settles up to {reach} bytes{}",
            row.spec.name,
            row.spec.policy.maximum_artifact_bytes,
            MAXIMUM_GAS_PER_CALL,
            if row.spec.policy.maximum_artifact_bytes as usize > reach {
                "; a seller with a larger artifact pays its own settle"
            } else {
                ""
            }
        );
    }
    let ended: Vec<ladder::Ended> = if let [row] = rows.as_mut_slice() {
        // One row: the one-row desk, as before rows could share one.
        vec![Ok(bounty::run(
            limits(&row.spec),
            &row.journal,
            &mut row.market,
        )?)]
    } else {
        let mut desk: Vec<ladder::Row> = rows
            .iter_mut()
            .map(|row| ladder::Row {
                name: row.spec.name.clone(),
                limits: limits(&row.spec),
                journal: row.journal.clone(),
                market: &mut row.market,
            })
            .collect();
        ladder::run(&mut desk, &mut |seconds| {
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            Ok(())
        })?
    };
    let mut unsettled = vec![];
    for (row, end) in rows.iter().zip(&ended) {
        let ledger = ledger_of(&row.journal)?;
        let stop = match end {
            Ok(stop) => stop.to_string(),
            Err(error) => format!("failed: {error}"),
        };
        println!(
            "post-tasks: {}: stopped: {stop}; posted {}, settled {}, refunded {}, spent {}",
            row.spec.name, ledger.posted, ledger.settled, ledger.refunded, ledger.spent
        );
        if end != &Ok(Stop::TaskLimit) {
            unsettled.push(format!("{}: {stop}", row.spec.name));
        }
    }
    match (ended.as_slice(), unsettled.is_empty()) {
        (_, true) => Ok(()),
        // One row: its typed `Stop`, as before.
        ([Ok(stop)], false) => Err(Box::new(stop.clone())),
        _ => Err(unsettled.join("; ").into()),
    }
}

/// `task-withdraw`: withdraw the first row's post if nobody was signed for
/// it (resolving an intent first, as a restart does), and end its journal.
/// Further pairs are the desk's other rows, whose journals are read so that
/// their deposits are explained (rule 8), and never written. The desk must
/// not be running.
pub fn task_withdraw(args: &[String]) -> Res<()> {
    let ([deployment, board_address, keyfile, bind], pairs) = split("task-withdraw", args)?;
    let mut rows = desk(
        &deployment,
        &board_address,
        &keyfile,
        &bind,
        &pairs,
        Journals::OthersExist,
    )?;
    let others: Vec<Shared> = rows[1..].iter().map(|row| row.journal.clone()).collect();
    let row = &mut rows[0];
    bounty::close_beside(&row.journal, &others, &mut row.market)?;
    let ledger = ledger_of(&row.journal)?;
    println!(
        "task-withdraw: {}: nothing open; posted {}, settled {}",
        row.spec.name, ledger.posted, ledger.settled
    );
    Ok(())
}

/// `task-refund`: end the first row's signed order now: refund and claim a
/// funded order past its delivery deadline, or journal its settlement or
/// lapse. Refuses (`bounty::Unfinished`) when nothing is due yet. Further
/// pairs are read as for `task-withdraw`. The desk must not be running.
pub fn task_refund(args: &[String]) -> Res<()> {
    let ([deployment, board_address, keyfile, bind], pairs) = split("task-refund", args)?;
    let mut rows = desk(
        &deployment,
        &board_address,
        &keyfile,
        &bind,
        &pairs,
        Journals::OthersExist,
    )?;
    let others: Vec<Shared> = rows[1..].iter().map(|row| row.journal.clone()).collect();
    let row = &mut rows[0];
    bounty::finish_beside(&row.journal, &others, &mut row.market)?;
    let ledger = ledger_of(&row.journal)?;
    println!(
        "task-refund: {}: the order ended; refunded {}, settled {}, spent {}",
        row.spec.name, ledger.refunded, ledger.settled, ledger.spent
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> Value {
        json!({
            "name": "t", "statement": "s.ndjson", "claim": "Nucleus.Claim",
            "permittedAxioms": ["propext", "Classical.choice", "Quot.sound"],
            "maximumArtifactBytes": 90000,
            "program": format!("0x{}", "11".repeat(32)),
            "maximumPrice": 2_000_000u64,
            "fundingWindowSeconds": 1_209_600u64,
            "deliveryWindowSeconds": 2_592_000u64,
        })
    }
    fn statement() -> Vec<u8> {
        b"{\"meta\":1}\n".to_vec()
    }

    #[test]
    fn a_task_file_fixes_the_policy_the_post_commits_to() {
        let spec = Spec::parse(&file(), statement()).unwrap();
        assert_eq!(spec.policy.claim, "Nucleus.Claim");
        assert_eq!(
            spec.policy.permitted_axioms,
            ["propext", "Classical.choice", "Quot.sound"]
        );
        assert_eq!(spec.policy.maximum_artifact_bytes, 90_000);
        assert_eq!(
            spec.policy.statement_sha256,
            <[u8; 32]>::from(Sha256::digest(statement()))
        );
        assert_eq!(spec.maximum, 2_000_000);
        assert_eq!(
            (spec.funding_window, spec.delivery_window),
            (1_209_600, 2_592_000)
        );
        // Another axiom list is another policy, so another post.
        let mut other = file();
        other["permittedAxioms"] = json!(["propext"]);
        assert_ne!(
            Spec::parse(&other, statement()).unwrap().policy.hash(),
            spec.policy.hash()
        );
    }

    #[test]
    fn a_task_file_that_could_not_be_answered_is_refused() {
        let with = |name: &str, value: Value| {
            let mut changed = file();
            changed[name] = value;
            Spec::parse(&changed, statement()).unwrap_err()
        };
        assert_eq!(with("claim", json!("")), SpecError::Claim);
        assert_eq!(with("claim", json!(7)), SpecError::Field("claim"));
        assert_eq!(with("permittedAxioms", json!(["a", "a"])), SpecError::Axiom);
        assert_eq!(with("permittedAxioms", json!([""])), SpecError::Axiom);
        assert_eq!(
            with("permittedAxioms", json!("propext")),
            SpecError::Field("permittedAxioms")
        );
        assert_eq!(
            with("maximumArtifactBytes", json!(0)),
            SpecError::ArtifactLimit
        );
        assert_eq!(
            with("maximumArtifactBytes", json!(u64::from(u32::MAX) + 1)),
            SpecError::ArtifactLimit
        );
        assert_eq!(with("program", json!("0x1234")), SpecError::Program);
        assert_eq!(
            with("program", json!(format!("0x{}", "00".repeat(32)))),
            SpecError::Program
        );
        assert_eq!(with("maximumPrice", json!(0)), SpecError::Price);
        assert_eq!(
            with("fundingWindowSeconds", json!(MINIMUM_FUNDING_WINDOW - 1)),
            SpecError::Windows
        );
        assert_eq!(
            with("deliveryWindowSeconds", json!(1_209_600u64)),
            SpecError::Windows
        );
        assert_eq!(
            Spec::parse(&file(), b"no newline".to_vec()).unwrap_err(),
            SpecError::Statement
        );
        assert_eq!(
            Spec::parse(&file(), vec![]).unwrap_err(),
            SpecError::Statement
        );
        // An export v2 statement ends at a record end without a newline: it is
        // taken, and pinned by the hash of its v2 bytes.
        // (The file is only read for its shape here; the checker decodes it.)
        let v2 = [
            &nucleus_proof_acceptance::EXPORT_V2_MAGIC[..],
            &[0x13, 0x07],
        ]
        .concat();
        let spec = Spec::parse(&file(), v2.clone()).unwrap();
        use sha2::Digest as _;
        assert_eq!(
            spec.policy.statement_sha256,
            <[u8; 32]>::from(sha2::Sha256::digest(&v2))
        );
        // Without the header the same bytes are NDJSON with no final newline.
        assert_eq!(
            Spec::parse(&file(), vec![0x13, 0x07]).unwrap_err(),
            SpecError::Statement
        );
    }

    #[test]
    fn a_ladder_task_names_its_row_and_the_rows_claim_and_axioms() {
        let mut ladder = file();
        ladder["row"] = json!("S0001");
        ladder["claim"] = json!("Statements.S0001.claim");
        let spec = Spec::parse(&ladder, statement()).unwrap();
        assert_eq!(spec.row, Some(Row::parse("S0001").unwrap()));
        // The proof's path is part of the terms, derived from the row.
        assert_eq!(
            spec.row.as_ref().unwrap().proof_path(),
            Path::new("Statements/S0001/Proof.lean")
        );
        // A row whose claim is another name, or another row's.
        for claim in ["Nucleus.Claim", "Statements.S0002.claim"] {
            let mut other = ladder.clone();
            other["claim"] = json!(claim);
            assert_eq!(
                Spec::parse(&other, statement()).unwrap_err(),
                SpecError::Row
            );
        }
        // A ladder row permits exactly the three axioms, in order.
        let mut fewer = ladder.clone();
        fewer["permittedAxioms"] = json!(["propext"]);
        assert_eq!(
            Spec::parse(&fewer, statement()).unwrap_err(),
            SpecError::Row
        );
        let mut malformed = ladder.clone();
        malformed["row"] = json!("s1");
        assert_eq!(
            Spec::parse(&malformed, statement()).unwrap_err(),
            SpecError::Row
        );
        // A task file with no row is not a ladder task, as before.
        assert_eq!(Spec::parse(&file(), statement()).unwrap().row, None);
    }

    #[test]
    fn task_files_come_in_pairs_one_row_each() {
        let args = |n: usize| -> Vec<String> { (0..n).map(|i| format!("a{i}")).collect() };
        // One pair is the one-row command as before; more pairs are rows.
        for n in [6, 8, 10] {
            let (fixed, pairs) = split("post-tasks", &args(n)).unwrap();
            assert_eq!((fixed.len(), pairs.len()), (4, n - 4));
        }
        for n in [4, 5, 7] {
            let error = split("post-tasks", &args(n)).unwrap_err().to_string();
            assert!(error.contains("OUT_DIR TASK.json pair per row"), "{error}");
        }
        // Each row once: by name, by ladder row, and by OUT_DIR.
        let row = |name: &str, ladder: Option<&str>| {
            let mut value = file();
            value["name"] = json!(name);
            if let Some(ladder) = ladder {
                value["row"] = json!(ladder);
                value["claim"] = json!(format!("Statements.{ladder}.claim"));
            }
            Spec::parse(&value, statement()).unwrap()
        };
        let rows = vec![
            (row("S0001", Some("S0001")), PathBuf::from("s0001/out")),
            (row("S0007", Some("S0007")), PathBuf::from("s0007/out")),
        ];
        let s0006 = row("S0006", Some("S0006"));
        assert!(!named_twice(&rows, &s0006, Path::new("s0006/out")));
        assert!(named_twice(&rows, &s0006, Path::new("s0001/out")));
        assert!(named_twice(&rows, &row("S0001", None), Path::new("x")));
        assert!(named_twice(
            &rows,
            &row("other", Some("S0007")),
            Path::new("x")
        ));
    }

    #[test]
    fn a_delivery_window_past_the_vaults_term_does_not_fit() {
        let spec = Spec::parse(&file(), statement()).unwrap();
        let third = |maximum_term| vault::Rules::Third {
            maximum_term,
            registry: [9; 20],
        };
        assert!(spec.fits(&third(2_592_000)));
        assert!(!spec.fits(&third(2_591_999)));
        assert!(spec.fits(&vault::Rules::Second));
    }
}
