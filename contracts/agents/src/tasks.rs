//! A buyer posting one task from a task file, journaled, and waiting at its
//! desk until the task ends; and the two commands that finish a task the
//! process could not.
//!
//!   nucleus-buyer post-tasks    DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json
//!   nucleus-buyer task-withdraw DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json
//!   nucleus-buyer task-refund   DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json
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
//! One task per process and per journal: the journal holds one open task,
//! and a restart attributes every deposit from this buyer to it (rule 8), so
//! two ladder posts from one wallet at once are refused at the second's
//! first deposit. Before 2026-11-16 the command took several task files and
//! kept nothing on disk until a settlement.
use crate::bounty::{self, Limits, Stop, Terms, live_with};
use crate::prelude::*;
use crate::relay::{MAXIMUM_GAS_PER_CALL, relayed_artifact_bytes};
use crate::world::*;
use nucleus_proof_commerce::Hash;

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
        Ok(Self {
            name: text("name")?.to_owned(),
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

/// The journal, the live market and the task, for one task file.
fn ladder(
    deployment: &str,
    board_address: &str,
    keyfile: &str,
    bind: &str,
    out: &str,
    file: &str,
) -> Res<(Spec, bounty::Live, bounty::Shared)> {
    let spec = Spec::read(file)?;
    let world = World::read(deployment)?;
    if !spec.fits(&world.deployment.rules) {
        return Err(format!(
            "{file}: the delivery window is longer than this vault's maximum term, so no seller could fund the order"
        )
        .into());
    }
    fs::create_dir_all(out)?;
    let out = Path::new(out);
    let terms = Terms {
        claim: spec.policy.claim.clone(),
        permitted_axioms: spec.policy.permitted_axioms.clone(),
        maximum_artifact_bytes: spec.policy.maximum_artifact_bytes,
        program: spec.program,
        funding_window: spec.funding_window,
        delivery_window: spec.delivery_window,
    };
    let (market, journal) = live_with(
        deployment,
        board_address,
        keyfile,
        Ok(spec.statement.clone()),
        terms,
        &out.join("journal.jsonl"),
        bind,
        Some(out.join(&spec.name)),
    )?;
    Ok((spec, market, journal))
}

fn usage(command: &str) -> String {
    format!("usage: nucleus-buyer {command} DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json")
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

/// `post-tasks`: post the task once (or resume it from the journal) and
/// follow it to its end. Exit 0 only for a settlement whose artifact the
/// Lean checker accepted; any other end is the typed `Stop`.
pub fn post_tasks(args: &[String]) -> Res<()> {
    let [deployment, board_address, keyfile, bind, out, file] = args else {
        return Err(format!(
            "{} (one task file: one journal, OUT_DIR/journal.jsonl)",
            usage("post-tasks")
        )
        .into());
    };
    let (spec, mut market, journal) = ladder(deployment, board_address, keyfile, bind, out, file)?;
    // The relayer's reach, on the post's face: a seller whose artifact is
    // larger settles with its own ether (relay.rs, MAXIMUM_GAS_PER_CALL).
    let reach = relayed_artifact_bytes(MAXIMUM_GAS_PER_CALL);
    println!(
        "post-tasks: {}: artifacts up to {} bytes; the relayer's {} gas cap settles up to {reach} bytes{}",
        spec.name,
        spec.policy.maximum_artifact_bytes,
        MAXIMUM_GAS_PER_CALL,
        if spec.policy.maximum_artifact_bytes as usize > reach {
            "; a seller with a larger artifact pays its own settle"
        } else {
            ""
        }
    );
    let stop = bounty::run(limits(&spec), &journal, &mut market)?;
    let ledger = journal
        .lock()
        .map_err(|_| "journal poisoned")?
        .ledger()
        .clone();
    println!(
        "post-tasks: {}: stopped: {stop}; posted {}, settled {}, refunded {}, spent {}",
        spec.name, ledger.posted, ledger.settled, ledger.refunded, ledger.spent
    );
    match stop {
        Stop::TaskLimit => Ok(()),
        other => Err(Box::new(other)),
    }
}

/// `task-withdraw`: withdraw the journal's post if nobody was signed for it
/// (resolving an intent first, as a restart does), and end the journal. The
/// `post-tasks` process for it must not be running.
pub fn task_withdraw(args: &[String]) -> Res<()> {
    let [deployment, board_address, keyfile, bind, out, file] = args else {
        return Err(usage("task-withdraw").into());
    };
    let (spec, mut market, journal) = ladder(deployment, board_address, keyfile, bind, out, file)?;
    bounty::close(&journal, &mut market)?;
    let ledger = journal
        .lock()
        .map_err(|_| "journal poisoned")?
        .ledger()
        .clone();
    println!(
        "task-withdraw: {}: nothing open; posted {}, settled {}",
        spec.name, ledger.posted, ledger.settled
    );
    Ok(())
}

/// `task-refund`: end the journal's signed order now: refund and claim a
/// funded order past its delivery deadline, or journal its settlement or
/// lapse. Refuses (`bounty::Unfinished`) when nothing is due yet. The
/// `post-tasks` process for it must not be running.
pub fn task_refund(args: &[String]) -> Res<()> {
    let [deployment, board_address, keyfile, bind, out, file] = args else {
        return Err(usage("task-refund").into());
    };
    let (spec, mut market, journal) = ladder(deployment, board_address, keyfile, bind, out, file)?;
    bounty::finish(&journal, &mut market)?;
    let ledger = journal
        .lock()
        .map_err(|_| "journal poisoned")?
        .ledger()
        .clone();
    println!(
        "task-refund: {}: the order ended; refunded {}, settled {}, spent {}",
        spec.name, ledger.refunded, ledger.settled, ledger.spent
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
