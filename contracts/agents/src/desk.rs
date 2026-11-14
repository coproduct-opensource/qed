//! The buyer's side of a posted task, as states and the only moves between
//! them, and the desk that answers sellers.
//!
//! ```text
//! Posted ──a seller's offer passes review──▶ Offered ──sign once──▶ Signed(seller)
//!   │                                                                 │
//!   └─ withdrawn by the buyer ─▶ Withdrawn        vault shows settled ├─▶ Settled
//!                                    delivery deadline passed, funded ├─▶ Refundable
//!                                 funding deadline passed, not funded └─▶ Lapsed
//! ```
//!
//! Rules carried by types:
//!
//! - **Nothing is signed for an offer that was not reviewed against this
//!   post.** `Posted::sign` takes an `Offered`, and only `Posted::review`
//!   makes one, for that post's ID.
//! - **A post is signed for once.** `Posted::sign` takes the post by value;
//!   the desk replaces the state before signing, so a second offer finds no
//!   open post. First offer that passes review wins (owner decision 6).
//!
//! What the desk does not decide: whether the seller funds, proves or
//! settles (the chain shows that), and whether the delivered artifact is
//! acceptable (the buyer runs the checker itself).
//!
//! A known cost of signing for the first passing offer: the authorization is
//! then in a stranger's hands. Anyone may relay `fund` with it, and if no
//! proof follows, the deposit is the buyer's again only after the delivery
//! deadline the buyer agreed to.
//!
//!   GET  /task/<id>           -> 200 {"policy": ...}
//!   POST /task/<id>/offer     PAYMENT-REQUIRED -> 200 PAYMENT-SIGNATURE | refusal
//!
//!   GET  /deliveries          -> 200 the signed summary of delivery attempts
//!
//! Every request carries a fresh DPoP proof from the seller, bound to the
//! seller's node as iroh authenticated it.
//!
//! Every offer and review is a delivery attempt. A desk given a `Recorder`
//! reports each one, with its outcome and typed reason, before it answers
//! (`contracts/deliveries`; docs/rfcs/qed-deliveries-2026-11-14.md).
use crate::board::{self, Task};
use crate::message::{Handler, Reply, Request, Via};
use crate::prelude::*;
use crate::support::policy_json;
use nucleus_proof_commerce::{
    Hash,
    vault::wire::{self as vault_wire, OfferError, ReviewedOffer},
    x402::wire::{REQUIRED_HEADER, SIGNATURE_HEADER},
};
/// How the desk answered a delivery attempt (`qed_deliveries::Outcome`).
pub use qed_deliveries::{Outcome as Answer, Reason, Route};
use std::collections::{HashMap, HashSet};

/// A funding deadline must leave the seller at least this long to relay.
const MINIMUM_FUNDING_LEAD: u64 = 60;

/// Why an offer was not signed for.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// No task with this ID was posted from this desk.
    Unknown,
    /// The task was posted but is no longer open: signed for, withdrawn or over.
    NotOpen,
    /// The offer fails the review every vault offer gets: wrong buyer, token,
    /// policy or context; a judge the post did not name; over the cap; a
    /// delivery deadline later than posted; not admissible to the vault.
    Offer(OfferError),
    /// The order's funding deadline is later than the one posted.
    LateFunding,
    /// The offer passed review and its signature could not be recorded
    /// first, so none was released; the post is closed.
    NotRecorded,
}
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "no such task"),
            Self::NotOpen => write!(f, "this task is no longer open"),
            Self::Offer(error) => write!(f, "offer refused: {error}"),
            Self::LateFunding => write!(f, "funding deadline is later than posted"),
            Self::NotRecorded => write!(
                f,
                "this task is no longer open: the authorization could not be recorded, so none was signed"
            ),
        }
    }
}
impl Refused {
    /// The record's reason for this refusal. Exhaustive: a new refusal does
    /// not compile until it has one (ADR 0007 E-1).
    pub fn reason(&self) -> Reason {
        match self {
            Self::Unknown => Reason::UnknownTask,
            Self::NotOpen => Reason::NotOpen,
            Self::LateFunding => Reason::Deadline,
            Self::NotRecorded => Reason::NotRecorded,
            Self::Offer(error) => match error {
                OfferError::Wire(_) | OfferError::NoSingleOffer => Reason::Malformed,
                OfferError::Vault(_) => Reason::Inadmissible,
                OfferError::NotMyOrder => Reason::TermsMismatch,
                OfferError::UntrustedJudge => Reason::UntrustedJudge,
                OfferError::OverBudget => Reason::OverLimit,
                OfferError::Deadline => Reason::Deadline,
                OfferError::UnsupportedBase => Reason::UnsupportedBase,
            },
        }
    }
    fn status(&self) -> u16 {
        match self {
            Self::Unknown => 404,
            Self::NotOpen | Self::NotRecorded => 409,
            Self::Offer(_) | Self::LateFunding => 422,
        }
    }
}

/// One delivery attempt as the desk saw it, for a `Recorder`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub at: u64,
    pub route: Route,
    /// The task the path named, when it is a well-formed ID.
    pub task: Option<Hash>,
    pub outcome: Answer,
    /// The thumbprint of the key the seller proved possession of.
    pub seller_key: Option<Hash>,
    /// The seller address the offer named, when one could be read. The
    /// recorder classifies it and does not keep it.
    pub named_seller: Option<Address>,
}

/// Where a desk reports delivery attempts, and what it serves at
/// `GET /deliveries`.
pub trait Recorder: Send {
    fn record(&mut self, seen: &Seen);
    /// The current signed summary, or why there is none.
    fn signed_summary(&self) -> Result<String, String>;
}

/// The seller address a `PAYMENT-REQUIRED` header names, if it can be read.
/// Read for classification only; nothing here trusts it.
pub fn named_seller(header: &str) -> Option<Address> {
    let bytes = B64.decode(header.trim()).ok()?;
    let required: vault_wire::PaymentRequired = serde_json::from_slice(&bytes).ok()?;
    let mut offers = required
        .accepts
        .iter()
        .filter(|offer| offer.scheme == vault_wire::SCHEME);
    let (Some(offer), None) = (offers.next(), offers.next()) else {
        return None;
    };
    unhex(&offer.extra.order.seller).ok()?.try_into().ok()
}

fn task_of(id: &str) -> Option<Hash> {
    if id.len() != 66 || !id.starts_with("0x") {
        return None;
    }
    unhex(id).ok()?.try_into().ok()
}

/// A task this buyer posted and has not signed for.
#[derive(Clone, Debug)]
pub struct Posted {
    id: Hash,
    task: Task,
    policy: Policy,
}
impl Posted {
    /// `policy` must be the one the task's hash commits to, pinning the
    /// task's statement.
    pub fn new(id: Hash, task: Task, policy: Policy) -> Result<Self, &'static str> {
        if policy.hash() != task.policy_hash || policy.statement_sha256 != task.statement_sha256 {
            return Err("the policy is not the one the task commits to");
        }
        Ok(Self { id, task, policy })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn task(&self) -> &Task {
        &self.task
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    /// Review a seller's x402 offer against this post. Everything the post
    /// said is enforced here, before anything is signed.
    /// `bases` are the base libraries this buyer accepts an order naming,
    /// with the registry entry it priced each from; an order naming any other
    /// base is refused.
    pub fn review(
        &self,
        deployment: &vault::Deployment,
        domain: &x402::TokenDomain,
        wallet: Address,
        header: &str,
        now: u64,
        bases: &[(Hash, vault::Entry)],
    ) -> Result<Offered, Refused> {
        let intent = vault_wire::Intent {
            wallet,
            asset: self.task.asset,
            policy_hash: self.task.policy_hash,
            context: board::context(self.id, self.task.buyer_key_binding),
            maximum_amount: self.task.maximum_amount,
            verifiers: vec![self.task.verifier],
            programs: vec![self.task.program],
            fund_no_earlier_than: now + MINIMUM_FUNDING_LEAD,
            deliver_no_later_than: self.task.deliver_by,
            bases: bases.to_vec(),
        };
        let reviewed = vault_wire::review_offer(deployment, domain, header, &intent, now)
            .map_err(Refused::Offer)?;
        if reviewed.order().fund_by > self.task.fund_by {
            return Err(Refused::LateFunding);
        }
        Ok(Offered {
            id: self.id,
            reviewed,
        })
    }
    /// Sign the token authorization for a reviewed offer. Consumes the post.
    /// An `Offered` made for another post is refused and the post comes back.
    pub fn sign(
        self,
        offered: Offered,
        deployment: &vault::Deployment,
        wallet: &SigningKey,
    ) -> Result<Signed, Box<Posted>> {
        if offered.id != self.id {
            return Err(Box::new(self));
        }
        let order = offered.reviewed.order().clone();
        let signature = crate::sign(wallet, offered.reviewed.signing_digest());
        match vault_wire::signature_header(deployment, offered.reviewed, &signature) {
            Ok(payment) => Ok(Signed {
                id: self.id,
                digest: vault::digest(deployment, &order),
                order,
                payment,
                policy: self.policy,
            }),
            Err(_) => Err(Box::new(self)),
        }
    }
}

/// An offer that passed review for one post. Private fields: the only way to
/// get one is `Posted::review`.
#[derive(Debug)]
pub struct Offered {
    id: Hash,
    reviewed: ReviewedOffer,
}
impl Offered {
    pub fn order(&self) -> &vault::Order {
        self.reviewed.order()
    }
}

/// A post the buyer has signed one authorization for.
#[derive(Clone, Debug)]
pub struct Signed {
    pub id: Hash,
    pub order: vault::Order,
    /// The order's digest under the vault: what the chain is asked about.
    pub digest: Hash,
    /// The x402 `PAYMENT-SIGNATURE` value given to the seller.
    pub payment: String,
    pub policy: Policy,
}

/// How a signed order ended, as the buyer read it from the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Settled,
    /// Funded and past the delivery deadline: `refund` is open to anyone.
    Refundable,
    /// The funding deadline passed with no deposit: the authorization is dead.
    Lapsed,
}

#[derive(Debug)]
pub enum State {
    Posted(Box<Posted>),
    Signed(Box<Signed>),
    Over(Outcome),
    Withdrawn,
}

/// The buyer's posts and the key that signs for them. In memory: a restart
/// forgets them, and the replay set with them.
pub struct Desk {
    deployment: vault::Deployment,
    domain: x402::TokenDomain,
    wallet: SigningKey,
    tasks: HashMap<String, State>,
    seen: HashSet<String>,
    clock: fn() -> u64,
    /// Called with a signed order before its authorization is returned to
    /// the seller. If it fails, nothing is returned and the post is closed.
    on_sign: Option<Record>,
    /// Base libraries an order may name, each with the registry entry it was
    /// priced from (the deployment file's `bases`). Empty: no base accepted.
    bases: Vec<(Hash, vault::Entry)>,
    /// Told of every delivery attempt; serves `GET /deliveries`.
    recorder: Option<Box<dyn Recorder>>,
}

/// What a desk calls before releasing a signature: somewhere durable to
/// write the order first.
pub type Record = Box<dyn FnMut(&Signed) -> Result<(), String> + Send>;

fn system_clock() -> u64 {
    crate::world::wall_clock().unwrap_or(0)
}

impl Desk {
    pub fn new(
        deployment: vault::Deployment,
        domain: x402::TokenDomain,
        wallet: SigningKey,
    ) -> Self {
        Self {
            deployment,
            domain,
            wallet,
            tasks: HashMap::new(),
            seen: HashSet::new(),
            clock: system_clock,
            on_sign: None,
            bases: Vec::new(),
            recorder: None,
        }
    }
    /// Report every delivery attempt to `recorder` before it is answered,
    /// and serve its signed summary at `GET /deliveries`.
    pub fn record_attempts(&mut self, recorder: Box<dyn Recorder>) {
        self.recorder = Some(recorder);
    }
    /// Accept orders naming these base libraries, priced from these registry
    /// entries. Without this a desk refuses any order that names a base.
    pub fn accept_bases(&mut self, bases: Vec<(Hash, vault::Entry)>) {
        self.bases = bases;
    }
    /// Record every signed order with `record` before its authorization
    /// leaves this desk.
    pub fn record_signatures(&mut self, record: Record) {
        self.on_sign = Some(record);
    }
    /// Put a posted task on the desk.
    pub fn open(&mut self, posted: Posted) {
        self.tasks
            .insert(hex(&posted.id), State::Posted(Box::new(posted)));
    }
    /// The order this desk signed for a task, if it has.
    pub fn signed(&self, id: &Hash) -> Option<Signed> {
        match self.tasks.get(&hex(id)) {
            Some(State::Signed(signed)) => Some((**signed).clone()),
            _ => None,
        }
    }
    /// Whether the task is still open to offers.
    pub fn open_for_offers(&self, id: &Hash) -> bool {
        matches!(self.tasks.get(&hex(id)), Some(State::Posted(_)))
    }
    /// The buyer withdrew the task. Only an open post moves.
    pub fn withdraw(&mut self, id: &Hash) -> bool {
        match self.tasks.get_mut(&hex(id)) {
            Some(state @ State::Posted(_)) => {
                *state = State::Withdrawn;
                true
            }
            _ => false,
        }
    }
    /// The chain showed how a signed order ended. Only a signed post moves.
    pub fn finish(&mut self, id: &Hash, outcome: Outcome) {
        if let Some(state @ State::Signed(_)) = self.tasks.get_mut(&hex(id)) {
            *state = State::Over(outcome);
        }
    }

    /// Review a seller's offer exactly as `offer` would, and stop there:
    /// nothing is signed and the post stays open. Returns the digest of the
    /// order that would have been signed for.
    pub fn review_only(&self, id: &str, header: &str, now: u64) -> Result<Hash, Refused> {
        let Some(state) = self.tasks.get(id) else {
            return Err(Refused::Unknown);
        };
        let State::Posted(posted) = state else {
            return Err(Refused::NotOpen);
        };
        let offered = posted.review(
            &self.deployment,
            &self.domain,
            address_of(&self.wallet),
            header,
            now,
            &self.bases,
        )?;
        Ok(vault::digest(&self.deployment, offered.order()))
    }

    /// A seller's offer for a task: review it, and sign for the first that
    /// passes. Returns the `PAYMENT-SIGNATURE` value.
    pub fn offer(&mut self, id: &str, header: &str, now: u64) -> Result<String, Refused> {
        let Some(state) = self.tasks.get_mut(id) else {
            return Err(Refused::Unknown);
        };
        let State::Posted(posted) = &*state else {
            return Err(Refused::NotOpen);
        };
        let offered = posted.review(
            &self.deployment,
            &self.domain,
            address_of(&self.wallet),
            header,
            now,
            &self.bases,
        )?;
        // The post leaves the table before it is signed for, so nothing can
        // sign for it twice.
        let State::Posted(posted) = std::mem::replace(state, State::Withdrawn) else {
            return Err(Refused::NotOpen);
        };
        match posted.sign(offered, &self.deployment, &self.wallet) {
            Ok(signed) => {
                // Durable before released: an authorization nobody recorded
                // is one no budget can account for. On failure the post stays
                // closed and the signature is dropped here.
                if let Some(record) = self.on_sign.as_mut()
                    && let Err(why) = record(&signed)
                {
                    println!("buyer: not releasing a signature that could not be recorded: {why}");
                    return Err(Refused::NotRecorded);
                }
                let payment = signed.payment.clone();
                *state = State::Signed(Box::new(signed));
                Ok(payment)
            }
            Err(posted) => {
                *state = State::Posted(posted);
                Err(Refused::NotOpen)
            }
        }
    }

    /// Tell the recorder, if any, of one delivery attempt.
    fn note(&mut self, seen: Seen) {
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.record(&seen);
        }
    }

    fn route(&mut self, via: &Via, request: &Request) -> Result<Reply, (u16, String)> {
        let now = (self.clock)();
        if request.path == "/deliveries" {
            crate::dpop::authenticate(via, request, now, &mut self.seen)?;
            return match (request.method.as_str(), self.recorder.as_ref()) {
                ("GET", Some(recorder)) => match recorder.signed_summary() {
                    Ok(jws) => Ok(Reply::text(200, &jws)),
                    Err(why) => Err((503, format!("no signed summary: {why}"))),
                },
                ("GET", None) => Err((404, "this desk keeps no record of deliveries".into())),
                _ => Err((404, "no such resource".into())),
            };
        }
        let Some(rest) = request.path.strip_prefix("/task/") else {
            return Err((404, "no such resource".into()));
        };
        // Offers and reviews are delivery attempts, recorded however they end.
        let attempt = match (
            request.method.as_str(),
            rest.strip_suffix("/offer"),
            rest.strip_suffix("/review"),
        ) {
            ("POST", Some(id), _) => Some((Route::Offer, id.to_owned())),
            ("POST", _, Some(id)) => Some((Route::Review, id.to_owned())),
            _ => None,
        };
        let header = request
            .headers
            .get(&REQUIRED_HEADER.to_ascii_lowercase())
            .cloned();
        let seen = |outcome, seller_key| {
            attempt.as_ref().map(|(route, id)| Seen {
                at: now,
                route: *route,
                task: task_of(id),
                outcome,
                seller_key,
                named_seller: header.as_deref().and_then(named_seller),
            })
        };
        let seller = match crate::dpop::authenticate(via, request, now, &mut self.seen) {
            Ok(seller) => seller,
            Err(refusal) => {
                if let Some(s) = seen(Answer::Refused(Reason::Unauthenticated), None) {
                    self.note(s);
                }
                return Err(refusal);
            }
        };
        let Some((route, id)) = attempt.clone() else {
            // Not an attempt: the policy of a posted task.
            return match (request.method.as_str(), self.tasks.get(rest)) {
                ("GET", Some(State::Posted(posted))) => Ok(Reply::text(
                    200,
                    &json!({"policy": policy_json(&posted.policy)}).to_string(),
                )),
                ("GET", Some(_)) => Err((409, Refused::NotOpen.to_string())),
                ("GET", None) => Err((404, Refused::Unknown.to_string())),
                _ => Err((404, "no such resource".into())),
            };
        };
        let Some(header) = header.clone() else {
            if let Some(s) = seen(Answer::Refused(Reason::Malformed), Some(seller)) {
                self.note(s);
            }
            return Err((400, "PAYMENT-REQUIRED missing".into()));
        };
        let result = match route {
            // A review asks what an offer would get and commits the buyer to
            // nothing: no signature is made and the post stays open.
            Route::Review => self.review_only(&id, &header, now).map(|digest| {
                println!(
                    "buyer: reviewed, without signing, an offer for task {id} from the key {} at node {}: order {} would be signed for",
                    hex(&seller),
                    via.peer.as_deref().unwrap_or("(none)"),
                    hex(&digest)
                );
                Reply::text(
                    200,
                    &json!({"review": "passes", "order": hex(&digest)}).to_string(),
                )
            }),
            Route::Offer => self.offer(&id, &header, now).map(|payment| {
                println!(
                    "buyer: signed for task {id}; offer came from the key {} at node {}",
                    hex(&seller),
                    via.peer.as_deref().unwrap_or("(none)")
                );
                Reply::new(200).with(SIGNATURE_HEADER, payment)
            }),
        };
        let outcome = match (&result, route) {
            (Ok(_), Route::Offer) => Answer::Accepted,
            (Ok(_), Route::Review) => Answer::Reviewed,
            (Err(refused), _) => Answer::Refused(refused.reason()),
        };
        if let Some(s) = seen(outcome, Some(seller)) {
            self.note(s);
        }
        result.map_err(|refused| (refused.status(), refused.to_string()))
    }
}

impl Handler for Desk {
    fn handle(&mut self, via: &Via, request: &Request) -> Reply {
        match self.route(via, request) {
            Ok(reply) => reply,
            Err((status, why)) => {
                println!("buyer: refused ({status}): {why}");
                Reply::text(status, &why)
            }
        }
    }
}
