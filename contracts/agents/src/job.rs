//! The seller's side of one job, as states and the only moves between them.
//!
//! ```text
//! Received ──prover──▶ Proving ──artifact passes the checker──▶ Quoted
//!                         │                                       │
//!                         └──no artifact, or refused──▶ Declined  ├─ funding deadline passes ─▶ Expired
//!                                                                 │
//!                               buyer's signed authorization for exactly the quoted order
//!                                                                 ▼
//!                      Accepted ─fund tx─▶ Funded ─zk proof─▶ Settling ─settle tx─▶ Settled
//!                          └──────────────── any step fails ───────────────────▶ Failed
//! ```
//!
//! Two rules are carried by types rather than by care:
//!
//! - **No offer without a checked artifact.** A `Quoted` can only be built
//!   from a `Checked`, and only `check` makes a `Checked`, by running the Lean
//!   checker on the artifact against the buyer's own policy and statement.
//! - **A quote is accepted once.** `Quoted::accept` takes the quote by value,
//!   so the same quote cannot start two fundings.
//!
//! What this file does not decide: whether funds moved (the chain does) and
//! whether the delivered artifact is acceptable to the buyer (the buyer runs
//! the checker itself).
use crate::chain::{Address, hex};
use nucleus_proof_acceptance::{Policy, accept};
use nucleus_proof_commerce::{Hash, vault};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Why a seller will not quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declined {
    /// The statement's SHA-256 is not the one the policy pins.
    StatementNotPinned,
    StatementTooLarge,
    /// The prover command produced nothing usable, with what it reported.
    NoArtifact(String),
    ArtifactTooLarge,
    /// The checker refused the prover's artifact.
    NotAccepted(String),
    /// The order this seller would offer is not admissible to the vault.
    NotAdmissible(String),
}
impl std::fmt::Display for Declined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatementNotPinned => write!(f, "statement is not the one the policy pins"),
            Self::StatementTooLarge => write!(f, "statement too large"),
            Self::NoArtifact(why) => write!(f, "no proof found: {why}"),
            Self::ArtifactTooLarge => write!(f, "proof exceeds the policy's size limit"),
            Self::NotAccepted(why) => write!(f, "proof refused by the checker: {why}"),
            Self::NotAdmissible(why) => write!(f, "order not admissible: {why}"),
        }
    }
}

/// A buyer's request, bound to the key that proved possession when making it.
#[derive(Clone, Debug)]
pub struct Received {
    /// Thumbprint of the buyer's possession key. Only this key may poll or pay.
    owner: Hash,
    buyer: Address,
    /// Digest of the request and the buyer's key; goes into the order.
    context: Hash,
    /// The URI the buyer's proof named, repeated in the offer.
    uri: String,
    policy: Policy,
    statement: Vec<u8>,
}
impl Received {
    pub fn new(
        owner: Hash,
        buyer: Address,
        context: Hash,
        uri: String,
        policy: Policy,
        statement: Vec<u8>,
        maximum_statement: usize,
    ) -> Result<Self, Declined> {
        if statement.len() > maximum_statement {
            return Err(Declined::StatementTooLarge);
        }
        let digest: Hash = Sha256::digest(&statement).into();
        if digest != policy.statement_sha256 {
            return Err(Declined::StatementNotPinned);
        }
        Ok(Self {
            owner,
            buyer,
            context,
            uri,
            policy,
            statement,
        })
    }
    pub fn owner(&self) -> Hash {
        self.owner
    }
    pub fn buyer(&self) -> Address {
        self.buyer
    }
    pub fn context(&self) -> Hash {
        self.context
    }
    pub fn uri(&self) -> &str {
        &self.uri
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }
    /// The job's name: the context, which already binds request and key.
    pub fn id(&self) -> String {
        hex(&self.context)
    }
}

/// An artifact the Lean checker accepted for one request. Private fields: the
/// only way to get one is `check`.
#[derive(Clone, Debug)]
pub struct Checked {
    artifact: Vec<u8>,
    proof: String,
}
impl Checked {
    pub fn artifact(&self) -> &[u8] {
        &self.artifact
    }
    /// Name of the declaration that proves the claim.
    pub fn proof(&self) -> &str {
        &self.proof
    }
}

/// Run the checker on what the prover produced.
pub fn check(received: &Received, artifact: Vec<u8>) -> Result<Checked, Declined> {
    let limit = usize::try_from(received.policy.maximum_artifact_bytes).unwrap_or(usize::MAX);
    if artifact.len() > limit {
        return Err(Declined::ArtifactTooLarge);
    }
    let accepted = accept(&received.policy, &received.statement, &artifact)
        .map_err(|refusal| Declined::NotAccepted(format!("{refusal:?}")))?;
    Ok(Checked {
        artifact,
        proof: accepted.proof,
    })
}

/// An offer the seller can stand behind: it holds the proof.
#[derive(Debug)]
pub struct Quoted {
    received: Received,
    checked: Checked,
    order: vault::Order,
    digest: Hash,
}
impl Quoted {
    /// `order` must be this seller's order for this request; `digest` its
    /// digest under the deployment.
    pub fn new(
        received: Received,
        checked: Checked,
        order: vault::Order,
        digest: Hash,
    ) -> Result<Self, Declined> {
        if order.policy_hash != received.policy.hash()
            || order.context != received.context
            || order.buyer != received.buyer
        {
            return Err(Declined::NotAdmissible(
                "order does not carry this request's policy, context and buyer".into(),
            ));
        }
        Ok(Self {
            received,
            checked,
            order,
            digest,
        })
    }
    pub fn order(&self) -> &vault::Order {
        &self.order
    }
    pub fn uri(&self) -> &str {
        &self.received.uri
    }
    pub fn digest(&self) -> Hash {
        self.digest
    }
    /// Take the buyer's admitted authorization. It must be for exactly the
    /// quoted order. Consumes the quote; on refusal the quote comes back.
    pub fn accept(self, funding: vault::Funding) -> Result<Accepted, Box<Quoted>> {
        if funding.digest() != self.digest || funding.order() != &self.order {
            return Err(Box::new(self));
        }
        Ok(Accepted {
            policy: self.received.policy,
            statement: self.received.statement,
            artifact: self.checked.artifact,
            funding,
        })
    }
}

/// A quote the buyer has paid for with a signed authorization. Everything the
/// worker needs to fund, prove and settle.
#[derive(Debug)]
pub struct Accepted {
    pub policy: Policy,
    pub statement: Vec<u8>,
    pub artifact: Vec<u8>,
    pub funding: vault::Funding,
}

/// Where an accepted job is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Relaying `fund`.
    Funding,
    /// Funded on chain; producing the settlement proof.
    Proving,
    /// Relaying `settle`.
    Settling,
}

#[derive(Debug)]
pub enum State {
    /// The prover command is running.
    Proving,
    Declined(Declined),
    Quoted(Box<Quoted>),
    Working(Step),
    Settled {
        /// The x402 `PAYMENT-RESPONSE` header value.
        response: String,
        artifact: Vec<u8>,
    },
    Failed(String),
    Expired,
}

/// What the owner of a job is told when it asks.
#[derive(Debug, PartialEq, Eq)]
pub enum View {
    Unknown,
    /// The asking key is not the key that made the job.
    NotYours,
    Proving,
    Declined(String),
    /// The order on offer and the URI it was asked at.
    Quoted {
        order: Box<vault::Order>,
        uri: String,
    },
    Working(Step),
    Settled {
        response: String,
        artifact: Vec<u8>,
    },
    Failed(String),
    Expired,
}

/// Why a quote could not be taken up.
#[derive(Debug, PartialEq, Eq)]
pub enum NotTaken {
    Unknown,
    NotYours,
    /// The job is not at a quote: still proving, declined, already accepted,
    /// finished or expired.
    NotQuoted,
    /// The authorization is for a different order than the one quoted.
    OtherOrder,
}

struct Entry {
    owner: Hash,
    state: State,
}

/// All jobs of one seller process. In memory: a restart forgets them.
#[derive(Default)]
pub struct Table {
    jobs: HashMap<String, Entry>,
}
impl Table {
    /// Whether a job is occupying the prover or the settlement worker.
    fn occupied(&self) -> bool {
        self.jobs.values().any(|entry| match entry.state {
            State::Proving | State::Working(_) => true,
            State::Declined(_)
            | State::Quoted(_)
            | State::Settled { .. }
            | State::Failed(_)
            | State::Expired => false,
        })
    }
    /// Start a job. One at a time: refused while another job is proving or
    /// working. Asking again for a job that exists is not an error.
    pub fn begin(&mut self, id: &str, owner: Hash) -> Begin {
        if let Some(entry) = self.jobs.get(id) {
            return if entry.owner == owner {
                Begin::Exists
            } else {
                Begin::Busy
            };
        }
        if self.occupied() {
            return Begin::Busy;
        }
        self.jobs.insert(
            id.to_owned(),
            Entry {
                owner,
                state: State::Proving,
            },
        );
        Begin::Started
    }
    /// The prover finished. Only a job that is proving moves.
    pub fn proved(&mut self, id: &str, outcome: Result<Quoted, Declined>) {
        if let Some(entry) = self.jobs.get_mut(id)
            && matches!(entry.state, State::Proving)
        {
            entry.state = match outcome {
                Ok(quoted) => State::Quoted(Box::new(quoted)),
                Err(declined) => State::Declined(declined),
            };
        }
    }
    /// Turn quotes whose funding deadline has passed into `Expired`.
    fn expire(&mut self, now: u64) {
        for entry in self.jobs.values_mut() {
            if let State::Quoted(quoted) = &entry.state
                && quoted.order.fund_by < now
            {
                entry.state = State::Expired;
            }
        }
    }
    pub fn view(&mut self, id: &str, asker: Hash, now: u64) -> View {
        self.expire(now);
        let Some(entry) = self.jobs.get(id) else {
            return View::Unknown;
        };
        if entry.owner != asker {
            return View::NotYours;
        }
        match &entry.state {
            State::Proving => View::Proving,
            State::Declined(why) => View::Declined(why.to_string()),
            State::Quoted(quoted) => View::Quoted {
                order: Box::new(quoted.order.clone()),
                uri: quoted.received.uri.clone(),
            },
            State::Working(step) => View::Working(*step),
            State::Settled { response, artifact } => View::Settled {
                response: response.clone(),
                artifact: artifact.clone(),
            },
            State::Failed(why) => View::Failed(why.clone()),
            State::Expired => View::Expired,
        }
    }
    /// Take up a quote with the buyer's admitted authorization. On success
    /// the job is `Working(Funding)` and the caller owns the `Accepted`.
    pub fn take(
        &mut self,
        id: &str,
        asker: Hash,
        funding: vault::Funding,
        now: u64,
    ) -> Result<Accepted, NotTaken> {
        self.expire(now);
        let Some(entry) = self.jobs.get_mut(id) else {
            return Err(NotTaken::Unknown);
        };
        if entry.owner != asker {
            return Err(NotTaken::NotYours);
        }
        let state = std::mem::replace(&mut entry.state, State::Working(Step::Funding));
        match state {
            State::Quoted(quoted) => match quoted.accept(funding) {
                Ok(accepted) => Ok(accepted),
                Err(quoted) => {
                    entry.state = State::Quoted(quoted);
                    Err(NotTaken::OtherOrder)
                }
            },
            other @ (State::Proving
            | State::Declined(_)
            | State::Working(_)
            | State::Settled { .. }
            | State::Failed(_)
            | State::Expired) => {
                entry.state = other;
                Err(NotTaken::NotQuoted)
            }
        }
    }
    /// The worker reports progress. Only a working job moves.
    pub fn step(&mut self, id: &str, step: Step) {
        if let Some(entry) = self.jobs.get_mut(id)
            && matches!(entry.state, State::Working(_))
        {
            entry.state = State::Working(step);
        }
    }
    /// The worker finished. Only a working job moves.
    pub fn finished(&mut self, id: &str, outcome: Result<(String, Vec<u8>), String>) {
        if let Some(entry) = self.jobs.get_mut(id)
            && matches!(entry.state, State::Working(_))
        {
            entry.state = match outcome {
                Ok((response, artifact)) => State::Settled { response, artifact },
                Err(why) => State::Failed(why),
            };
        }
    }
    pub fn settled(&self) -> usize {
        self.jobs
            .values()
            .filter(|entry| matches!(entry.state, State::Settled { .. }))
            .count()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Begin {
    Started,
    /// The same key asked for the same job again.
    Exists,
    /// Another job holds the prover, or the ID belongs to another key.
    Busy,
}
