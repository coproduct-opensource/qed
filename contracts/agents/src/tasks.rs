//! A buyer posting several tasks from task files and waiting at one desk.
//!
//!   nucleus-buyer post-tasks DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json...
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
//! Both windows run from the moment of posting. One process serves every
//! statement and signs for every task, from one iroh endpoint, so the posts
//! go out one after another from one wallet and cannot collide on a nonce.
//! A task can be answered only while this process is up.
//!
//! For each task it signs for the first offer that passes review, then
//! believes only the chain and the Lean checker, as `post` does. It withdraws
//! a task whose funding deadline passes with nothing signed.
use crate::board::{self, Board, Task};
use crate::desk::{Desk, Outcome, Posted, Signed};
use crate::iroh_net;
use crate::post::{phase_of, settled_artifact};
use crate::prelude::*;
use crate::world::*;
use nucleus_proof_acceptance::accept;
use nucleus_proof_commerce::Hash;
use std::{
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

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

/// Where one posted task stands for this process.
enum Standing {
    Open,
    Signed(Box<Signed>),
    Done,
}

struct Running {
    spec: Spec,
    id: Hash,
    task: Task,
    standing: Standing,
}

pub fn post_tasks(args: &[String]) -> Res<()> {
    let [deployment, board_address, keyfile, bind, out, files @ ..] = args else {
        return Err(
            "usage: nucleus-buyer post-tasks DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json..."
                .into(),
        );
    };
    if files.is_empty() {
        return Err("no task file given".into());
    }
    let world = World::read(deployment)?;
    let keys = Keys::load_or_create(keyfile)?;
    let board = Board {
        chain: world.chain.clone(),
        address: address_arg(board_address)?,
    };
    if board.vault()? != world.deployment.vault {
        return Err("the board is for another vault than this deployment's".into());
    }
    // Every file is read and checked before anything is posted.
    let mut specs = vec![];
    for file in files {
        let spec = Spec::read(file)?;
        if !spec.fits(&world.deployment.rules) {
            return Err(format!(
                "{file}: the delivery window is longer than this vault's maximum term, so no seller could fund the order"
            )
            .into());
        }
        specs.push(spec);
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

    let from_block = board.latest_block()?;
    let desk = Arc::new(Mutex::new({
        let mut desk = Desk::new(
            world.deployment.clone(),
            world.domain.clone(),
            keys.wallet.clone(),
        );
        desk.accept_bases(world.bases.clone());
        desk
    }));
    let _router = {
        let _guard = runtime.enter();
        iroh_net::serve_with(endpoint, desk.clone(), Some(&store))
    };
    println!(
        "buyer: {} holds {}; node {node} at {bind} (relay {relay:?}); {} task file(s)",
        hex(&keys.address()),
        world.balance(keys.address())?,
        specs.len()
    );

    // Post one after another: each post is confirmed before the next is sent.
    let mut running = vec![];
    for spec in specs {
        let blake3 = runtime.block_on(crate::blobs::add(&store, spec.statement.clone()))?;
        let now = wall_clock()?;
        let task = Task {
            statement_sha256: spec.policy.statement_sha256,
            statement_blake3: blake3,
            policy_hash: spec.policy.hash(),
            asset: world.token,
            maximum_amount: U256::from(spec.maximum).to_be_bytes(),
            verifier: world.verifier,
            program: spec.program,
            fund_by: now + spec.funding_window,
            deliver_by: now + spec.delivery_window,
            buyer_node: board::node_bytes(&node)?,
            buyer_key_binding: keys.binding(),
            salt: random32()?,
            buyer_address: match relay {
                iroh_net::Relay::None => bind.clone(),
                iroh_net::Relay::Default | iroh_net::Relay::Url(_) => String::new(),
            },
        };
        if let Some(refusal) = task.refusal(now) {
            return Err(
                format!("{}: the board would refuse this task: {refusal}", spec.name).into(),
            );
        }
        let id = nucleus_board_reference::id(world.chain.id, board.address, keys.address(), &task);
        // On the desk before it is on the board, so the first seller to see
        // the post finds it.
        desk.lock().map_err(|_| "desk poisoned")?.open(Posted::new(
            id,
            task.clone(),
            spec.policy.clone(),
        )?);
        let (posted_id, receipt) = board.post(&keys.wallet, &task)?;
        if posted_id != id {
            return Err("the board gave the task another ID than the reference".into());
        }
        println!(
            "buyer: {}: posted task {} in tx {} (gas {}); statement {} bytes, sha256 {}; cap {}; fund by {}, deliver by {}",
            spec.name,
            hex(&id),
            receipt.transaction,
            receipt.gas_used,
            spec.statement.len(),
            hex(&spec.policy.statement_sha256),
            spec.maximum,
            task.fund_by,
            task.deliver_by
        );
        running.push(Running {
            spec,
            id,
            task,
            standing: Standing::Open,
        });
    }

    // Follow every task to its end.
    let mut unsettled = 0usize;
    while running
        .iter()
        .any(|r| !matches!(r.standing, Standing::Done))
    {
        for r in running.iter_mut() {
            let now = wall_clock()?;
            match &r.standing {
                Standing::Done => {}
                Standing::Open => {
                    let signed = desk.lock().map_err(|_| "desk poisoned")?.signed(&r.id);
                    if let Some(signed) = signed {
                        println!(
                            "buyer: {}: signed order {} for seller {} at {}; watching the vault",
                            r.spec.name,
                            hex(&signed.digest),
                            hex(&signed.order.seller),
                            U256::from_be_bytes(signed.order.amount)
                        );
                        r.standing = Standing::Signed(Box::new(signed));
                    } else if now > r.task.fund_by {
                        // Abandonment: nobody was signed for in time.
                        if desk.lock().map_err(|_| "desk poisoned")?.withdraw(&r.id) {
                            let withdrawn = board.withdraw(&keys.wallet, r.id)?;
                            println!(
                                "buyer: {}: no offer was signed for before the funding deadline; withdrawn in tx {}",
                                r.spec.name, withdrawn.transaction
                            );
                            unsettled += 1;
                            r.standing = Standing::Done;
                        }
                    }
                }
                Standing::Signed(signed) => {
                    let outcome = match phase_of(&world, signed.digest)? {
                        2 => Some(Outcome::Settled),
                        1 if now > signed.order.deliver_by => Some(Outcome::Refundable),
                        0 if now > signed.order.fund_by => Some(Outcome::Lapsed),
                        _ => None,
                    };
                    let Some(outcome) = outcome else { continue };
                    desk.lock()
                        .map_err(|_| "desk poisoned")?
                        .finish(&r.id, outcome);
                    match outcome {
                        Outcome::Settled => {
                            // Trust nothing a seller said: the artifact comes
                            // from the chain and the checker decides.
                            let artifact = settled_artifact(
                                world.deployment.rules.form(),
                                &world.chain,
                                world.deployment.vault,
                                signed.digest,
                                from_block,
                            )?;
                            let accepted = accept(&signed.policy, &r.spec.statement, &artifact)
                                .map_err(|e| {
                                    format!(
                                        "{}: the settled artifact is refused by the checker: {e:?}",
                                        r.spec.name
                                    )
                                })?;
                            let recorded = world.chain.call(
                                [0; 20],
                                world.deployment.vault,
                                &artifactOfCall {
                                    d: signed.digest.into(),
                                }
                                .abi_encode(),
                            )?;
                            if recorded != keccak(&artifact) {
                                return Err(
                                    "the vault recorded another artifact for this order".into()
                                );
                            }
                            let dir = Path::new(out).join(&r.spec.name);
                            fs::create_dir_all(&dir)?;
                            fs::write(dir.join("delivered.ndjson"), &artifact)?;
                            fs::write(
                                dir.join("order.json"),
                                serde_json::to_vec_pretty(
                                    &nucleus_proof_commerce::vault::wire::WireOrder::from_order(
                                        &signed.order,
                                    ),
                                )?,
                            )?;
                            println!(
                                "buyer: {}: settled; {} byte artifact passes the Lean checker ({})",
                                r.spec.name,
                                artifact.len(),
                                accepted.proof
                            );
                        }
                        Outcome::Refundable => {
                            unsettled += 1;
                            println!(
                                "buyer: {}: funded but not delivered by the deadline; refund is open for order {}",
                                r.spec.name,
                                hex(&signed.digest)
                            );
                        }
                        Outcome::Lapsed => {
                            unsettled += 1;
                            println!("buyer: {}: the seller never funded the order", r.spec.name);
                        }
                    }
                    r.standing = Standing::Done;
                }
            }
        }
        sleep(Duration::from_secs(5));
    }
    if unsettled == 0 {
        Ok(())
    } else {
        Err(format!("{unsettled} task(s) ended without a settlement").into())
    }
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
