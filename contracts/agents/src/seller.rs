//! The seller: a harness around a prover command.
//!
//! For each request it writes the buyer's statement to a job directory, runs
//! the configured prover on it, and checks what comes back with the Lean
//! checker. Only then does it offer an order (`job.rs` makes that order the
//! only one possible). When the buyer pays with a signed authorization for
//! exactly that order, the seller relays `fund`, produces the settlement
//! proof, and relays `settle`.
//!
//!   POST /work            {policy, statement}  -> 202, Location: /work/<job>
//!   GET  /work/<job>                           -> 202 working | 402 offer | 200 artifact | refusal
//!   POST /work/<job>      PAYMENT-SIGNATURE    -> 202
//!
//! Every request carries a fresh DPoP proof; a job answers only to the key
//! that made it. Limits, stated: one job at a time; the statement travels
//! inline and is at most `MAXIMUM_STATEMENT` bytes; jobs and the replay set
//! live in memory and are forgotten on restart.

use crate::job::{Accepted, Begin, Declined, NotTaken, Quoted, Received, Step, Table, View, check};
use crate::message::{Handler, MAXIMUM_STATEMENT, Reply, Request, Via};
use crate::prelude::*;
use crate::support::{BaseOffer, RealProofs, policy_from};
use crate::worker::{ClearToProve, ClearToSettle, Limits, Sealer, Venue, work};
use crate::world::*;
use nucleus_proof_acceptance::vault_program;
use nucleus_proof_commerce::{
    vault::wire as vault_wire,
    x402::wire::{
        BuyerDeclaration, REQUIRED_HEADER, RESPONSE_HEADER, SIGNATURE_HEADER, request_hash,
    },
};
use std::{
    collections::HashSet,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub type Jobs = Arc<Mutex<Table>>;

/// What this seller offers and where: fixed for the life of the process.
#[derive(Clone)]
pub struct Terms {
    pub deployment: vault::Deployment,
    pub domain: x402::TokenDomain,
    pub token: Address,
    pub verifier: Address,
    /// Image ID of the proof program this seller proves with.
    pub program: [u8; 32],
    pub seller: Address,
    /// Price of one job in the token's smallest unit.
    pub price: u64,
    /// How long the buyer has to fund after a quote.
    pub fund_seconds: u64,
    /// How long after the quote delivery may take.
    pub deliver_seconds: u64,
    /// A checked base this seller builds on, if it has one.
    pub base: Option<BaseOffer>,
}
impl Terms {
    /// This seller's order for a request, as of `now`. `limits`, when given,
    /// are the latest funding and delivery deadlines the buyer said it would
    /// sign for; the order's deadlines are the earlier of those and this
    /// seller's own.
    fn order(
        &self,
        received: &Received,
        now: u64,
        limits: Option<(u64, u64)>,
    ) -> Res<vault::Order> {
        let (fund_cap, deliver_cap) = limits.unwrap_or((u64::MAX, u64::MAX));
        Ok(vault::Order {
            buyer: received.buyer(),
            seller: self.seller,
            asset: self.token,
            amount: U256::from(self.price).to_be_bytes(),
            verifier: self.verifier,
            program: self.program,
            policy_hash: received.policy().hash(),
            // The configured base, when the statement begins with its bytes.
            base: match &self.base {
                Some(base) if received.statement().starts_with(&base.bytes) => base.id,
                _ => [0; 32],
            },
            fund_by: (now + self.fund_seconds).min(fund_cap),
            deliver_by: (now + self.deliver_seconds).min(deliver_cap),
            salt: random32()?,
            context: received.context(),
        })
    }
}

/// The prover command. Run as `COMMAND [ARGS...] STATEMENT_PATH ARTIFACT_PATH`
/// with no shell. It succeeds by exiting 0 having written the artifact.
#[derive(Clone)]
pub struct Prover {
    pub command: Vec<String>,
    pub timeout: Duration,
    pub work: PathBuf,
}
impl Prover {
    pub(crate) fn run(&self, id: &str, statement: &[u8], limit: u32) -> Result<Vec<u8>, Declined> {
        let failed = |why: String| Declined::NoArtifact(why);
        let (program, arguments) = self
            .command
            .split_first()
            .ok_or_else(|| failed("no prover command configured".into()))?;
        let directory = self.work.join(id.trim_start_matches("0x"));
        fs::create_dir_all(&directory).map_err(|e| failed(e.to_string()))?;
        let (statement_path, artifact_path) = (
            directory.join("statement.ndjson"),
            directory.join("artifact.ndjson"),
        );
        fs::write(&statement_path, statement).map_err(|e| failed(e.to_string()))?;
        let _ = fs::remove_file(&artifact_path);
        let mut child = Command::new(program)
            .args(arguments)
            .arg(&statement_path)
            .arg(&artifact_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| failed(format!("prover did not start: {e}")))?;
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(failed("prover timed out".into()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(failed(e.to_string())),
            }
        };
        if !status.success() {
            return Err(failed(format!("prover exited with {status}")));
        }
        let size = fs::metadata(&artifact_path)
            .map_err(|_| failed("prover wrote no artifact".into()))?
            .len();
        if size > u64::from(limit) {
            return Err(Declined::ArtifactTooLarge);
        }
        fs::read(&artifact_path).map_err(|e| failed(e.to_string()))
    }
}

/// What happens once a quote is paid for. The real one talks to the chain and
/// the zero-knowledge prover; tests substitute one that only records.
pub trait Settler: Send {
    fn start(&self, id: String, accepted: Accepted, jobs: Jobs);
}

/// Fund, check, prove, check, settle (`worker.rs`), on a worker thread.
pub struct OnChain {
    pub chain: Chain,
    pub wallet: SigningKey,
    pub proofs: RealProofs,
    pub deployment: vault::Deployment,
    pub token: Address,
    pub base: Option<BaseOffer>,
    pub limits: Limits,
    /// A gas relayer for `fund`, `settle` and `claim`, if configured
    /// (docs/rfcs/qed-relayer-2026-11-13.md, R-1 to R-4).
    pub relayer: Option<Arc<dyn crate::relay::RelayApi>>,
    /// R-2: how long to wait for a relayed transaction.
    pub relayer_wait: Duration,
}
impl OnChain {
    /// One call to the vault: through the relayer when there is one, checked
    /// on chain; otherwise, or when the relayer does not deliver, with this
    /// seller's own gas.
    fn deliver(
        &self,
        label: &str,
        data: &[u8],
        until: Option<u64>,
        done: &dyn Fn() -> Res<bool>,
    ) -> Res<crate::relay::Delivered> {
        crate::relay::Submission {
            chain: &self.chain,
            relayer: self.relayer.as_deref(),
            vault: self.deployment.vault,
            data,
            wait: self.relayer_wait,
            until,
            poll: Duration::from_secs(3),
            label,
        }
        .run(done, &|| {
            self.chain
                .send(&self.wallet, Some(self.deployment.vault), 0, data)
        })
    }
    /// The vault's phase for an order: 0 empty, 1 funded, 2 settled.
    fn phase(&self, order: &vault::Order) -> Res<u8> {
        let digest = vault::digest(&self.deployment, order);
        self.chain
            .call(
                [0; 20],
                self.deployment.vault,
                &crate::world::phaseCall { d: digest.into() }.abi_encode(),
            )?
            .last()
            .copied()
            .ok_or_else(|| "phase reply".into())
    }
    /// The royalty this seller priced an order on: its configured base's
    /// rate when the order names that base, and nothing otherwise.
    pub fn quoted_royalty(&self, order: &vault::Order) -> U256 {
        match &self.base {
            Some(base) if base.id == order.base && order.base != [0; 32] => {
                U256::from_be_bytes(order.amount) * U256::from(base.bps) / U256::from(10_000u64)
            }
            _ => U256::ZERO,
        }
    }
    /// Relay `fund`, produce the settlement proof, relay `settle`. Returns
    /// the x402 `PAYMENT-RESPONSE` value and the artifact. `at` is told which
    /// step is beginning.
    pub fn settle(
        &self,
        id: &str,
        accepted: Accepted,
        at: &dyn Fn(Step),
    ) -> Res<(String, Vec<u8>)> {
        let order = accepted.funding.order().clone();
        let done = work(
            self,
            self,
            &self.limits,
            self.quoted_royalty(&order),
            id,
            &accepted,
            at,
        )?;
        let me = address_of(&self.wallet);
        let paid = U256::from_be_slice(
            &self.chain.call(
                me,
                self.token,
                &crate::balanceOfCall {
                    account: A::from(me),
                }
                .abi_encode(),
            )?,
        );
        println!("seller: balance {paid}");
        let response = json!({
            "success": true, "transaction": done.fund_transaction, "network": format!("eip155:{}", self.deployment.chain_id),
            "payer": hex(&order.buyer), "amount": U256::from_be_bytes(order.amount).to_string(),
            "extensions": {"nucleus-vault": {"settlement": done.settle_transaction}},
        });
        Ok((
            B64.encode(serde_json::to_vec(&response)?),
            accepted.artifact,
        ))
    }
}
impl Venue for OnChain {
    fn fund(&self, order: &vault::Order, signature: &[u8]) -> Res<String> {
        let data = fund_data(self.deployment.rules.form(), order, signature);
        let until = order.fund_by.saturating_sub(self.limits.settle_margin / 2);
        let funded = self.deliver("fund", &data, Some(until), &|| Ok(self.phase(order)? >= 1))?;
        println!("seller: funded: {funded:?}");
        Ok(funded
            .transaction()
            .unwrap_or("(funded by another transaction)")
            .to_owned())
    }
    fn booked_royalty(&self, digest: nucleus_proof_commerce::Hash) -> Res<U256> {
        match self.deployment.rules.form() {
            // The second form has no royalty.
            vault::Form::Second => Ok(U256::ZERO),
            vault::Form::Third => {
                let reply = self.chain.call(
                    address_of(&self.wallet),
                    self.deployment.vault,
                    &third::royaltyOfCall { d: digest.into() }.abi_encode(),
                )?;
                // (address payee, uint256 amount)
                let amount = reply.get(32..64).ok_or("royaltyOf reply too short")?;
                Ok(U256::from_be_slice(amount))
            }
        }
    }
    fn now(&self) -> Res<u64> {
        self.chain.timestamp()
    }
    fn settle(
        &self,
        _clear: ClearToSettle,
        order: &vault::Order,
        artifact: &[u8],
        seal: Vec<u8>,
    ) -> Res<String> {
        let data = settle_data(self.deployment.rules.form(), order, artifact, seal);
        let until = order
            .deliver_by
            .saturating_sub(self.limits.settle_margin / 2);
        let settled = self.deliver(
            "settle",
            &data,
            Some(until),
            &|| Ok(self.phase(order)? == 2),
        )?;
        println!("seller: settled: {settled:?}");
        Ok(settled
            .transaction()
            .unwrap_or("(settled by another transaction)")
            .to_owned())
    }
    /// The third form books the seller's share; it is paid by a claim, which
    /// the seller makes for itself here. If the claim fails the share stays
    /// booked and anyone can claim it later.
    fn collect(&self, _order: &vault::Order) {
        if self.deployment.rules.form() != vault::Form::Third {
            return;
        }
        let me = address_of(&self.wallet);
        let claim = third::claimCall {
            payee: A::from(me),
            asset: A::from(self.token),
        }
        .abi_encode();
        let owed = || -> Res<U256> {
            Ok(U256::from_be_slice(
                &self.chain.call(
                    [0; 20],
                    self.deployment.vault,
                    &third::owedCall {
                        payee: A::from(me),
                        asset: A::from(self.token),
                    }
                    .abi_encode(),
                )?,
            ))
        };
        match self.deliver("claim", &claim, None, &|| Ok(owed()?.is_zero())) {
            Ok(claimed) => println!("seller: claimed its share: {claimed:?}"),
            Err(error) => println!("seller: COULD NOT CLAIM its share: {error}"),
        }
    }
}
impl Sealer for OnChain {
    fn seal(&self, _clear: &ClearToProve, id: &str, accepted: &Accepted) -> Res<Vec<u8>> {
        let order = accepted.funding.order();
        let form = self.deployment.rules.form();
        let input = vault_program::Input {
            form,
            chain_id: self.deployment.chain_id,
            vault: self.deployment.vault,
            order: order.clone(),
            policy: accepted.policy.clone(),
            statement: accepted.statement.clone(),
            artifact: accepted.artifact.clone(),
        };
        // One set of proof files per job, so a later job does not overwrite them.
        let name = format!("settlement-{}", id.trim_start_matches("0x"));
        // An order that names a base carries the witness for it and is
        // proved on the base's receipt.
        let based = self.base.as_ref().filter(|base| base.id == order.base);
        if order.base != [0; 32] && based.is_none() {
            return Err("the order names a base this seller does not hold".into());
        }
        let witness = based.map(|base| vault_program::BaseWitness {
            length: u32::try_from(base.bytes.len()).unwrap_or(u32::MAX),
            payee: base.payee,
            bps: base.bps,
        });
        let encoded = match form {
            vault::Form::Second => input.encode(),
            vault::Form::Third => vault_program::encode_with_base(&input, witness.as_ref()),
        };
        self.proofs.seal(
            form,
            &name,
            &encoded,
            based.map(|base| base.receipt.as_path()),
        )
    }
}
impl Settler for OnChain {
    fn start(&self, id: String, accepted: Accepted, jobs: Jobs) {
        let this = OnChain {
            chain: self.chain.clone(),
            wallet: self.wallet.clone(),
            proofs: self.proofs.clone(),
            deployment: self.deployment.clone(),
            token: self.token,
            base: self.base.clone(),
            limits: self.limits,
            relayer: self.relayer.clone(),
            relayer_wait: self.relayer_wait,
        };
        std::thread::spawn(move || {
            let at = |step: Step| {
                if let Ok(mut table) = jobs.lock() {
                    table.step(&id, step);
                }
            };
            let outcome = this.settle(&id, accepted, &at).map_err(|error| {
                println!("seller: job {id} failed: {error}");
                error.to_string()
            });
            if let Ok(mut table) = jobs.lock() {
                table.finished(&id, outcome);
            }
        });
    }
}

/// A refusal with the status it is answered with.
struct Refusal(u16, String);
fn refuse<T>(status: u16, why: impl ToString) -> Result<T, Refusal> {
    Err(Refusal(status, why.to_string()))
}

pub struct Seller {
    terms: Terms,
    prover: Prover,
    settler: Box<dyn Settler>,
    seen: HashSet<String>,
    jobs: Jobs,
    clock: fn() -> u64,
}

fn system_clock() -> u64 {
    wall_clock().unwrap_or(0)
}

impl Seller {
    pub fn new(terms: Terms, prover: Prover, settler: Box<dyn Settler>) -> Self {
        Self {
            terms,
            prover,
            settler,
            seen: HashSet::new(),
            jobs: Jobs::default(),
            clock: system_clock,
        }
    }
    pub fn jobs(&self) -> Jobs {
        self.jobs.clone()
    }

    /// Answer one request. Never panics on what a caller sends.
    pub fn handle(&mut self, via: &Via, request: &Request) -> Reply {
        match self.route(via, request) {
            Ok(reply) => reply,
            Err(Refusal(status, why)) => {
                println!("seller: refused ({status}): {why}");
                Reply::text(status, &why)
            }
        }
    }

    /// Proof of possession for exactly this request (`dpop::authenticate`).
    fn authenticate(&mut self, via: &Via, request: &Request) -> Result<[u8; 32], Refusal> {
        crate::dpop::authenticate(via, request, (self.clock)(), &mut self.seen)
            .map_err(|(status, why)| Refusal(status, why))
    }

    fn route(&mut self, via: &Via, request: &Request) -> Result<Reply, Refusal> {
        let job = request.path.strip_prefix("/work/");
        match (request.method.as_str(), request.path.as_str(), job) {
            ("POST", "/work", _) => {
                let owner = self.authenticate(via, request)?;
                self.receive(via, request, owner)
            }
            ("GET", _, Some(id)) => {
                let owner = self.authenticate(via, request)?;
                self.status(id, owner)
            }
            ("POST", _, Some(id)) => {
                let owner = self.authenticate(via, request)?;
                self.pay(id, owner, request)
            }
            _ => refuse(404, "no such resource"),
        }
    }

    /// A new request: bind it to the key, then let the prover try.
    fn receive(&mut self, via: &Via, request: &Request, owner: [u8; 32]) -> Result<Reply, Refusal> {
        let uri = format!("{}/work", via.base);
        let body: Value =
            serde_json::from_slice(&request.body).or_else(|e| refuse(400, format!("body: {e}")))?;
        let policy =
            policy_from(&body["policy"]).or_else(|e| refuse(400, format!("policy: {e}")))?;
        let statement = B64
            .decode(body["statement"].as_str().unwrap_or_default())
            .or_else(|_| refuse(400, "statement is not base64"))?;
        let declared: BuyerDeclaration = request
            .headers
            .get("nucleus-buyer")
            .and_then(|header| B64.decode(header).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .map_or_else(
                || refuse(400, "NUCLEUS-BUYER header missing or malformed"),
                Ok,
            )?;
        if unhex(&declared.key_binding).ok().as_deref() != Some(&owner[..]) {
            return refuse(
                401,
                "the declared key is not the key that proved possession",
            );
        }
        let buyer = address_arg(&declared.wallet).or_else(|e| refuse(400, e))?;
        let context = vault_wire::context(request_hash("POST", &uri, &request.body), owner);
        let received = match Received::new(
            owner,
            buyer,
            context,
            uri,
            policy,
            statement,
            MAXIMUM_STATEMENT,
        ) {
            Ok(received) => received,
            Err(Declined::StatementTooLarge) => return refuse(413, Declined::StatementTooLarge),
            Err(declined) => return refuse(422, declined),
        };
        let id = received.id();
        let begun = self
            .jobs
            .lock()
            .map_or_else(|_| refuse(500, "job table poisoned"), Ok)?
            .begin(&id, owner);
        match begun {
            Begin::Busy => return refuse(503, "busy with another job"),
            Begin::Exists => {}
            Begin::Started => {
                let (terms, prover, jobs, clock) = (
                    self.terms.clone(),
                    self.prover.clone(),
                    self.jobs.clone(),
                    self.clock,
                );
                println!(
                    "seller: job {id} from buyer {}: {} byte statement; running the prover",
                    hex(&buyer),
                    received.statement().len()
                );
                std::thread::spawn(move || {
                    let outcome = quote(&terms, &prover, received, clock, None);
                    match &outcome {
                        Ok(quoted) => println!(
                            "seller: job {id} proved and checked; offering order {}",
                            hex(&quoted.digest())
                        ),
                        Err(declined) => println!("seller: job {id} declined: {declined}"),
                    }
                    if let Ok(mut table) = jobs.lock() {
                        table.proved(&id, outcome);
                    }
                });
            }
        }
        Ok(Reply::new(202).with("Location", format!("/work/{}", received_id(context))))
    }

    fn status(&mut self, id: &str, owner: [u8; 32]) -> Result<Reply, Refusal> {
        let view = self
            .jobs
            .lock()
            .map_or_else(|_| refuse(500, "job table poisoned"), Ok)?
            .view(id, owner, (self.clock)());
        Ok(match view {
            View::Unknown => return refuse(404, "no such job"),
            View::NotYours => return refuse(403, "this job belongs to another key"),
            View::Proving => Reply::new(202).with("Nucleus-Job", "quoting".into()),
            View::Declined(why) => return refuse(422, why),
            View::Quoted { order, uri } => {
                let offer = vault_wire::requirements(
                    &self.terms.deployment,
                    &self.terms.domain,
                    &order,
                    60,
                );
                let header = vault_wire::required_header(json!({"url": uri}), offer)
                    .or_else(|e| refuse(500, format!("{e:?}")))?;
                Reply::text(402, "{}").with(REQUIRED_HEADER, header)
            }
            View::Working(step) => Reply::new(202).with(
                "Nucleus-Job",
                match step {
                    Step::Funding => "funding",
                    Step::Proving => "proving",
                    Step::Settling => "settling",
                }
                .into(),
            ),
            View::Settled { response, artifact } => Reply {
                status: 200,
                headers: vec![(RESPONSE_HEADER.to_owned(), response)],
                body: artifact,
            },
            View::Failed(why) => return refuse(500, why),
            View::Expired => return refuse(410, "the quote expired unfunded"),
        })
    }

    /// The buyer's signed authorization for the quoted order.
    fn pay(&mut self, id: &str, owner: [u8; 32], request: &Request) -> Result<Reply, Refusal> {
        let Some(payment) = request.headers.get(&SIGNATURE_HEADER.to_ascii_lowercase()) else {
            return refuse(400, "PAYMENT-SIGNATURE missing");
        };
        let now = (self.clock)();
        let funding =
            vault_wire::admit_header(&self.terms.deployment, &self.terms.domain, payment, 60, now)
                .or_else(|e| refuse(400, format!("payment refused: {e:?}")))?;
        let taken = self
            .jobs
            .lock()
            .map_or_else(|_| refuse(500, "job table poisoned"), Ok)?
            .take(id, owner, funding, now);
        match taken {
            Ok(accepted) => {
                println!("seller: job {id} paid for; funding, proving, settling");
                self.settler
                    .start(id.to_owned(), accepted, self.jobs.clone());
                Ok(Reply::new(202).with("Location", format!("/work/{id}")))
            }
            Err(NotTaken::Unknown) => refuse(404, "no such job"),
            Err(NotTaken::NotYours) => refuse(403, "this job belongs to another key"),
            Err(NotTaken::NotQuoted) => refuse(409, "this job has no open quote"),
            Err(NotTaken::OtherOrder) => refuse(409, "payment is not for the quoted order"),
        }
    }
}

impl Handler for Seller {
    fn handle(&mut self, via: &Via, request: &Request) -> Reply {
        Seller::handle(self, via, request)
    }
}

fn received_id(context: [u8; 32]) -> String {
    hex(&context)
}

/// Prover, then checker, then this seller's order. The order is made only
/// after the artifact has passed. `limits` as for `Terms::order`.
pub(crate) fn quote(
    terms: &Terms,
    prover: &Prover,
    received: Received,
    clock: fn() -> u64,
    limits: Option<(u64, u64)>,
) -> Result<Quoted, Declined> {
    let artifact = prover.run(
        &received.id(),
        received.statement(),
        received.policy().maximum_artifact_bytes,
    )?;
    let checked = check(&received, artifact)?;
    let now = clock();
    let order = terms
        .order(&received, now, limits)
        .map_err(|e| Declined::NotAdmissible(e.to_string()))?;
    let digest = vault::admissible(&terms.deployment, &order, now)
        .map_err(|e| Declined::NotAdmissible(format!("{e:?}")))?;
    Quoted::new(received, checked, order, digest)
}

/// The seller's configuration file (JSON).
pub struct Config {
    pub deployment: String,
    pub keys: String,
    /// Socket address for the iroh endpoint, for example `127.0.0.1:4450`.
    pub iroh_bind: Option<String>,
    /// Socket address for the optional HTTP adapter.
    pub http_listen: Option<String>,
    /// `"relay"`: `none` (the default), `default`, or an `https://` relay URL.
    pub relay: crate::iroh_net::Relay,
    pub prover: Vec<String>,
    pub prover_timeout: Duration,
    pub price: u64,
    pub proofs: RealProofs,
    pub work: PathBuf,
    /// Exit after this many settled jobs. Absent: run until stopped.
    pub stop_after: Option<usize>,
    /// `"base": {"file", "receipt", "payee", "bps"}`: a checked base this
    /// seller builds on.
    pub base: Option<BaseOffer>,
    /// `"settleMarginSeconds"` (default 120) and `"expectedProvingSeconds"`
    /// (default 900): see `worker.rs`.
    pub limits: Limits,
    /// `"relayer"`: the URL of a gas relayer (`relay.rs`). Absent: this
    /// seller pays its own gas.
    pub relayer: Option<String>,
    /// `"relayerWaitSeconds"` (default 120): R-2.
    pub relayer_wait: Duration,
}
impl Config {
    pub fn read(path: &str) -> Res<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path)?)?;
        let text = |name: &str| -> Res<String> {
            Ok(value[name]
                .as_str()
                .ok_or_else(|| format!("{name} missing"))?
                .to_owned())
        };
        let optional = |name: &str| value[name].as_str().map(str::to_owned);
        Ok(Self {
            deployment: text("deployment")?,
            keys: text("keys")?,
            iroh_bind: optional("irohBind"),
            http_listen: optional("httpListen"),
            relay: match &value["relay"] {
                Value::Null => crate::iroh_net::Relay::None,
                Value::String(text) => crate::iroh_net::Relay::parse(text)?,
                _ => return Err("relay must be a string".into()),
            },
            prover: value["prover"]
                .as_array()
                .ok_or("prover missing")?
                .iter()
                .map(|part| part.as_str().map(str::to_owned).ok_or("prover argument"))
                .collect::<Result<_, _>>()?,
            prover_timeout: Duration::from_secs(
                value["proverTimeoutSeconds"].as_u64().unwrap_or(600),
            ),
            price: text("price")?.parse()?,
            proofs: RealProofs {
                host: text("proofHost")?,
                groth16: crate::support::Groth16::from_config(
                    value["groth16"].as_str(),
                    optional("groth16Data"),
                    optional("dockerDir"),
                )?,
                out: PathBuf::from(text("workDir")?).join("proofs"),
                third: crate::support::ThirdProgram::from_config(value["proofProgram"].as_str())?,
            },
            work: PathBuf::from(text("workDir")?).join("jobs"),
            stop_after: value["stopAfter"].as_u64().map(|n| n as usize),
            relayer: match optional("relayer") {
                Some(url)
                    if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1")) =>
                {
                    return Err(
                        "a relayer must be https:// (or http://127.0.0.1 for a local test)".into(),
                    );
                }
                other => other,
            },
            relayer_wait: Duration::from_secs(value["relayerWaitSeconds"].as_u64().unwrap_or(120)),
            limits: Limits {
                settle_margin: value["settleMarginSeconds"]
                    .as_u64()
                    .unwrap_or(Limits::default().settle_margin),
                expected_proving: value["expectedProvingSeconds"]
                    .as_u64()
                    .unwrap_or(Limits::default().expected_proving),
            },
            base: match value.get("base") {
                None | Some(Value::Null) => None,
                Some(base) => {
                    let part = |name: &str| -> Res<String> {
                        Ok(base[name]
                            .as_str()
                            .ok_or_else(|| format!("base.{name} missing"))?
                            .to_owned())
                    };
                    let bytes = fs::read(part("file")?)?;
                    Some(BaseOffer {
                        id: nucleus_proof_acceptance::base::id(&bytes),
                        bytes: Arc::new(bytes),
                        receipt: PathBuf::from(part("receipt")?),
                        payee: crate::world::address_arg(&part("payee")?)?,
                        bps: part("bps")?.parse()?,
                    })
                }
            },
        })
    }
}

/// Build the seller a configuration describes. Reads the chain.
pub fn from_config(config: &Config) -> Res<(Seller, Keys)> {
    let (terms, prover, settler, keys) = parts(config)?;
    Ok((Seller::new(terms, prover, Box::new(settler)), keys))
}

/// What a configuration describes, read against the chain: the terms, the
/// prover, and the settlement worker.
pub fn parts(config: &Config) -> Res<(Terms, Prover, OnChain, Keys)> {
    let world = World::read(&config.deployment)?;
    let keys = Keys::load_or_create(&config.keys)?;
    let program = config.proofs.program(world.deployment.rules.form())?;
    let terms = Terms {
        deployment: world.deployment.clone(),
        domain: world.domain.clone(),
        token: world.token,
        verifier: world.verifier,
        program,
        seller: keys.address(),
        price: config.price,
        fund_seconds: 900,
        deliver_seconds: 3 * 3600,
        base: config.base.clone(),
    };
    let settler = OnChain {
        chain: world.chain.clone(),
        wallet: keys.wallet.clone(),
        proofs: config.proofs.clone(),
        deployment: world.deployment.clone(),
        token: world.token,
        base: config.base.clone(),
        limits: config.limits,
        relayer: config.relayer.as_ref().map(|url| {
            Arc::new(crate::relay::RelayClient::new(url, keys.possession.clone()))
                as Arc<dyn crate::relay::RelayApi>
        }),
        relayer_wait: config.relayer_wait,
    };
    let prover = Prover {
        command: config.prover.clone(),
        timeout: config.prover_timeout,
        work: config.work.clone(),
    };
    println!(
        "seller: wallet {}; vault {} on chain {}; price {}; program {}",
        hex(&keys.address()),
        hex(&world.deployment.vault),
        world.deployment.chain_id,
        config.price,
        hex(&program)
    );
    Ok((terms, prover, settler, keys))
}
