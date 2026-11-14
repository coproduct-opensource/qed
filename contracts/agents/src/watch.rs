//! The seller answering the task board.
//!
//! `nucleus-seller watch CONFIG.json` reads the board's notices from the
//! chain. For each posted task it could serve, it fetches the buyer's policy
//! and statement from the buyer's node, runs the same harness as a direct
//! request (prover command, then the Lean checker: `job.rs`), and only then
//! dials the buyer with an x402 offer for an order that fits the post. If the
//! buyer signs, it relays `fund`, proves, and relays `settle`.
//!
//! Stated limits: one task at a time, in the order the chain announced them;
//! a task is tried once per process; a blob's size is checked after it has
//! been fetched, not before; what was tried is kept in memory.
use crate::board::{self, Board, PostedTask};
use crate::buyer::ask;
use crate::iroh_net::IrohTransport;
use crate::job::{Accepted, Declined, Received, Step};
use crate::message::{MAXIMUM_STATEMENT, Reply, Transport};
use crate::prelude::*;
use crate::seller::{self, Prover, Terms, quote};
use crate::support::policy_from;
use crate::world::wall_clock;
use nucleus_proof_commerce::{
    Hash,
    vault::wire as vault_wire,
    x402::wire::{REQUIRED_HEADER, SIGNATURE_HEADER},
};
use std::collections::{BTreeMap, HashSet};

/// The post must leave at least this long to relay `fund` after an offer.
const MINIMUM_FUNDING_ROOM: u64 = 120;
/// The post must leave at least this long to prove and settle.
const MINIMUM_DELIVERY_ROOM: u64 = 1_800;

/// Why a seller did not take, or did not win, a posted task.
#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    /// The post is for a vault this seller does not settle through.
    OtherVault,
    OtherAsset,
    /// The post names a verifier or program this seller does not prove for.
    OtherJudge,
    /// The buyer's cap is below this seller's price.
    Price,
    /// Too little time left to fund, or to prove and settle.
    Deadline,
    /// The buyer's node could not be reached or did not answer usefully.
    Unreachable(String),
    /// The post's address hint is not one this seller will dial.
    UnsafeAddress(String),
    /// The policy the buyer served is not the one the post commits to.
    PolicyNotPosted,
    /// The harness would not quote: statement not as pinned, no proof found,
    /// proof refused by the checker, order not admissible.
    Declined(Declined),
    /// The buyer refused the offer, with its status and reason.
    Refused(u16, String),
    /// The buyer answered with something that is not a valid authorization
    /// for the offered order.
    BadPayment(String),
}
impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtherVault => write!(f, "posted for another vault"),
            Self::OtherAsset => write!(f, "posted in another token"),
            Self::OtherJudge => write!(f, "posted for another verifier or program"),
            Self::Price => write!(f, "the cap is below this seller's price"),
            Self::Deadline => write!(f, "too little time left"),
            Self::Unreachable(why) => write!(f, "buyer unreachable: {why}"),
            Self::UnsafeAddress(why) => write!(f, "address hint refused: {why}"),
            Self::PolicyNotPosted => write!(f, "the served policy is not the posted one"),
            Self::Declined(declined) => write!(f, "{declined}"),
            Self::Refused(status, why) => write!(f, "buyer refused the offer ({status}): {why}"),
            Self::BadPayment(why) => write!(f, "buyer's payment refused: {why}"),
        }
    }
}

/// Whether this seller could serve a post at all, before contacting anyone.
pub fn wanted(terms: &Terms, posted: &PostedTask, now: u64) -> Result<(), Skip> {
    let task = &posted.task;
    if posted.vault != terms.deployment.vault {
        return Err(Skip::OtherVault);
    }
    if task.asset != terms.token {
        return Err(Skip::OtherAsset);
    }
    if task.verifier != terms.verifier || task.program != terms.program {
        return Err(Skip::OtherJudge);
    }
    if U256::from_be_bytes(task.maximum_amount) < U256::from(terms.price) {
        return Err(Skip::Price);
    }
    if task.fund_by < now + MINIMUM_FUNDING_ROOM || task.deliver_by < now + MINIMUM_DELIVERY_ROOM {
        return Err(Skip::Deadline);
    }
    Ok(())
}

/// The longest address hint a seller reads. A post may carry up to 128
/// bytes; a bracketed IPv6 socket address needs at most 47.
const MAXIMUM_HINT: usize = 64;

fn private_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        // 100.64.0.0/10, carrier-grade NAT
        || (a == 100 && (64..128).contains(&b))
        // 0.0.0.0/8
        || a == 0
}

/// A post's address hint, vetted before anything is dialled. The hint is
/// written by whoever posted and is not authenticated: without this a post
/// could point every seller's node at a host inside the seller's own network.
///
/// `Ok(None)`: no hint; the node ID is the only route, which needs a relay
/// mode. `Ok(Some(_))`: a public socket address. With `allow_private`, used
/// for tests on one machine, any well-formed socket address is taken.
pub fn peer_hint(
    hint: &str,
    relay: &crate::iroh_net::Relay,
    allow_private: bool,
) -> Result<Option<std::net::SocketAddr>, Skip> {
    if hint.is_empty() {
        return match relay {
            crate::iroh_net::Relay::None => Err(Skip::UnsafeAddress(
                "the post has no address and this seller uses no relay".into(),
            )),
            crate::iroh_net::Relay::Default | crate::iroh_net::Relay::Url(_) => Ok(None),
        };
    }
    if hint.len() > MAXIMUM_HINT {
        return Err(Skip::UnsafeAddress("longer than a socket address".into()));
    }
    // A socket address and nothing else: no host names, no schemes.
    let address: std::net::SocketAddr = hint
        .parse()
        .map_err(|_| Skip::UnsafeAddress("not a socket address".into()))?;
    if address.port() == 0 {
        return Err(Skip::UnsafeAddress("port 0".into()));
    }
    if allow_private {
        return Ok(Some(address));
    }
    let private = match address.ip() {
        std::net::IpAddr::V4(ip) => private_v4(ip),
        std::net::IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                // fc00::/7, unique local
                || first & 0xfe00 == 0xfc00
                // fe80::/10, link local
                || first & 0xffc0 == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(private_v4)
        }
    };
    if private {
        return Err(Skip::UnsafeAddress(
            "a loopback, private, link-local, multicast or unspecified address".into(),
        ));
    }
    Ok(Some(address))
}

/// The address hint a buyer bound at `bind` posts in this relay mode. With a
/// relay the node ID is enough and none is posted. With none, the bind
/// address is the hint, and it is part of the task's ID on the board, so a
/// hint no seller takes can never be answered: it is refused here, before
/// anything is posted. The test is the seller's own (`peer_hint`, in its
/// one-machine form), and an unspecified address, which names no host to
/// dial, is refused too.
pub fn posted_hint(bind: &str, relay: &crate::iroh_net::Relay) -> Res<String> {
    match relay {
        crate::iroh_net::Relay::None => {
            let refused = |why: String| -> Res<String> {
                Err(format!(
                    "no seller would take the address hint {bind:?} ({why}); with no relay \
                     (NUCLEUS_RELAY unset or `none`) the bind address is posted, so bind a \
                     reachable address and port, or set NUCLEUS_RELAY=default"
                )
                .into())
            };
            match peer_hint(bind, &crate::iroh_net::Relay::None, true) {
                Ok(Some(address)) if address.ip().is_unspecified() => {
                    refused("an unspecified address".into())
                }
                Ok(Some(_)) => Ok(bind.to_owned()),
                Ok(None) => refused("empty".into()),
                Err(Skip::UnsafeAddress(why)) => refused(why),
                Err(other) => refused(other.to_string()),
            }
        }
        crate::iroh_net::Relay::Default | crate::iroh_net::Relay::Url(_) => Ok(String::new()),
    }
}

/// How a seller reaches the buyer that posted a task.
pub trait BuyerLink {
    /// `iroh://<buyer node>`: what proofs to this buyer name before the path.
    fn base(&self) -> String;
    /// The policy the buyer serves for the task.
    fn policy(&self, id: &Hash) -> Res<Policy>;
    /// The bytes with the task's BLAKE3 hash.
    fn statement(&self, blake3: &Hash) -> Res<Vec<u8>>;
    /// Present an offer; the reply carries `PAYMENT-SIGNATURE` on success.
    fn offer(&self, id: &Hash, header: String) -> Res<Reply>;
    /// Present an offer for review only: the buyer says whether it would
    /// sign, and signs nothing. A link that cannot ask says so.
    fn review(&self, _id: &Hash, _header: String) -> Res<Reply> {
        Err("this link cannot ask for a review".into())
    }
}

/// The buyer's node over iroh, at the node ID and address hint a post gives.
pub struct IrohBuyer<'a> {
    transport: IrohTransport,
    store: crate::blobs::Store,
    keys: &'a Keys,
}
impl<'a> IrohBuyer<'a> {
    /// For tests on one machine: no relay, and the post's address hint is
    /// taken even when it is a loopback or private address.
    pub fn new(keys: &'a Keys, posted: &PostedTask) -> Result<Self, Skip> {
        Self::new_in(keys, posted, &crate::iroh_net::Relay::None, true)
    }
    /// In a relay mode the posted node ID is enough, and the post's address
    /// hint, when it has one and passes `peer_hint`, is only an extra route.
    pub fn new_in(
        keys: &'a Keys,
        posted: &PostedTask,
        relay: &crate::iroh_net::Relay,
        allow_private: bool,
    ) -> Result<Self, Skip> {
        let hint = peer_hint(&posted.task.buyer_address, relay, allow_private)?;
        let unreachable = |error: Box<dyn std::error::Error>| Skip::Unreachable(error.to_string());
        let node = board::node_text(&posted.task.buyer_node).map_err(unreachable)?;
        let address = match hint {
            Some(address) => format!("iroh:{node}@{address}"),
            None => format!("iroh:{node}"),
        };
        let transport = IrohTransport::new_in(keys.node, &address, relay).map_err(unreachable)?;
        let store = {
            let _guard = transport.runtime.enter();
            crate::blobs::store()
        };
        Ok(Self {
            transport,
            store,
            keys,
        })
    }
}
impl BuyerLink for IrohBuyer<'_> {
    fn base(&self) -> String {
        self.transport.base()
    }
    fn policy(&self, id: &Hash) -> Res<Policy> {
        let reply = ask(
            &self.transport,
            self.keys,
            "GET",
            &board::path(id),
            BTreeMap::new(),
            vec![],
        )?;
        if reply.status != 200 {
            return Err(
                format!("{} {}", reply.status, String::from_utf8_lossy(&reply.body)).into(),
            );
        }
        let body: Value = serde_json::from_slice(&reply.body)?;
        policy_from(&body["policy"])
    }
    fn statement(&self, blake3: &Hash) -> Res<Vec<u8>> {
        self.transport
            .runtime
            .block_on(crate::blobs::fetch(
                &self.transport.endpoint,
                &self.store,
                self.transport.seller.clone(),
                *blake3,
            ))
            .map_err(Into::into)
    }
    fn offer(&self, id: &Hash, header: String) -> Res<Reply> {
        ask(
            &self.transport,
            self.keys,
            "POST",
            &board::offer_path(id),
            [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
            vec![],
        )
    }
    fn review(&self, id: &Hash, header: String) -> Res<Reply> {
        ask(
            &self.transport,
            self.keys,
            "POST",
            &board::review_path(id),
            [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
            vec![],
        )
    }
}

/// Answer one posted task: fetch, prove, check, offer, and take the buyer's
/// signed authorization. Returns what the settlement worker needs. Nothing
/// here touches the chain.
pub fn answer(
    terms: &Terms,
    prover: &Prover,
    posted: &PostedTask,
    buyer: &dyn BuyerLink,
    clock: fn() -> u64,
) -> Result<Accepted, Skip> {
    let (quoted, header) = prepare(terms, prover, posted, buyer, clock)?;
    let reply = buyer
        .offer(&posted.id, header)
        .map_err(|error| Skip::Unreachable(error.to_string()))?;
    if reply.status != 200 {
        return Err(Skip::Refused(
            reply.status,
            String::from_utf8_lossy(&reply.body).into_owned(),
        ));
    }
    let payment = reply
        .header(SIGNATURE_HEADER)
        .ok_or_else(|| Skip::BadPayment("PAYMENT-SIGNATURE missing".into()))?;
    let funding = vault_wire::admit_header(&terms.deployment, &terms.domain, payment, 60, clock())
        .map_err(|e| Skip::BadPayment(format!("{e:?}")))?;
    quoted
        .accept(funding)
        .map_err(|_| Skip::BadPayment("the authorization is for another order".into()))
}

/// What a review-only run established: this seller holds an artifact the
/// checker passes for the task, and the buyer's desk said it would sign for
/// this order. Nothing was signed and nothing touched the chain.
#[derive(Debug, PartialEq, Eq)]
pub struct Reviewed {
    /// Digest of the order the seller offered.
    pub order: Hash,
    /// The buyer's reply body.
    pub reply: String,
}

/// Everything `answer` does up to the offer, then ask the buyer only whether
/// it would sign. For a seller run with `quoteOnly`: it never receives an
/// authorization, so it can never fund.
pub fn review(
    terms: &Terms,
    prover: &Prover,
    posted: &PostedTask,
    buyer: &dyn BuyerLink,
    clock: fn() -> u64,
) -> Result<Reviewed, Skip> {
    let (quoted, header) = prepare(terms, prover, posted, buyer, clock)?;
    let reply = buyer
        .review(&posted.id, header)
        .map_err(|error| Skip::Unreachable(error.to_string()))?;
    let body = String::from_utf8_lossy(&reply.body).into_owned();
    if reply.status != 200 {
        return Err(Skip::Refused(reply.status, body));
    }
    // A reply carrying an authorization is not a review; a seller that asked
    // for a review does not take one.
    if reply.header(SIGNATURE_HEADER).is_some() {
        return Err(Skip::BadPayment(
            "the buyer answered a review with an authorization".into(),
        ));
    }
    Ok(Reviewed {
        order: vault::digest(&terms.deployment, quoted.order()),
        reply: body,
    })
}

/// Fetch, prove, check and build the offer for one posted task. Nothing here
/// touches the chain, and the buyer has been asked only for its policy and
/// statement.
fn prepare(
    terms: &Terms,
    prover: &Prover,
    posted: &PostedTask,
    buyer: &dyn BuyerLink,
    clock: fn() -> u64,
) -> Result<(crate::job::Quoted, String), Skip> {
    wanted(terms, posted, clock())?;
    let task = &posted.task;
    let unreachable = |error: Box<dyn std::error::Error>| Skip::Unreachable(error.to_string());
    let policy = buyer.policy(&posted.id).map_err(unreachable)?;
    if policy.hash() != task.policy_hash || policy.statement_sha256 != task.statement_sha256 {
        return Err(Skip::PolicyNotPosted);
    }
    let statement = buyer
        .statement(&task.statement_blake3)
        .map_err(unreachable)?;
    let uri = format!("{}{}", buyer.base(), board::offer_path(&posted.id));
    // The same harness as a direct request: the statement must be the one the
    // policy pins, and no order exists until the checker has passed a proof.
    let received = Received::new(
        task.buyer_key_binding,
        posted.poster,
        board::context(posted.id, task.buyer_key_binding),
        uri.clone(),
        policy,
        statement,
        MAXIMUM_STATEMENT,
    )
    .map_err(Skip::Declined)?;
    let quoted = quote(
        terms,
        prover,
        received,
        clock,
        Some((task.fund_by, task.deliver_by)),
    )
    .map_err(Skip::Declined)?;
    let offer = vault_wire::requirements(&terms.deployment, &terms.domain, quoted.order(), 60);
    let header = vault_wire::required_header(json!({"url": uri}), offer)
        .map_err(|e| Skip::Declined(Declined::NotAdmissible(format!("{e:?}"))))?;
    Ok((quoted, header))
}

fn system_clock() -> u64 {
    wall_clock().unwrap_or(0)
}

/// `nucleus-seller watch CONFIG.json`. The configuration is the seller's
/// (`seller::Config`), plus `board` (address), and optionally `startBlock`
/// (default: the latest block when the seller starts), `pollSeconds`
/// (default 5), `allowPrivatePeers` (default false: a post whose address
/// hint is a loopback or private address is passed over) and `quoteOnly`
/// (default false; when true the seller goes as far as a checked artifact
/// and the buyer's review of its offer, takes no authorization, and sends
/// nothing to the chain; `stopAfter` then counts reviewed offers), and
/// `onlyPoster` (an address: answer only that poster's tasks).
pub fn watch(args: &[String]) -> Res<()> {
    let [path] = args else {
        return Err("usage: nucleus-seller watch CONFIG.json".into());
    };
    let config = seller::Config::read(path)?;
    let extra: Value = serde_json::from_slice(&fs::read(path)?)?;
    let (terms, prover, on_chain, keys) = seller::parts(&config)?;
    let board = Board {
        chain: on_chain.chain.clone(),
        address: crate::world::address_arg(extra["board"].as_str().ok_or("board missing")?)?,
    };
    if board.vault()? != terms.deployment.vault {
        return Err("the board is for another vault than this seller's deployment".into());
    }
    let poll = std::time::Duration::from_secs(extra["pollSeconds"].as_u64().unwrap_or(5));
    let allow_private = extra["allowPrivatePeers"].as_bool().unwrap_or(false);
    let quote_only = extra["quoteOnly"].as_bool().unwrap_or(false);
    // `onlyPoster`: answer only tasks posted by this address (a dedicated
    // test, leaving every other buyer's tasks alone).
    let only_poster = match extra["onlyPoster"].as_str() {
        Some(text) => Some(crate::world::address_arg(text)?),
        None => None,
    };

    let mut cursor = match extra["startBlock"].as_u64() {
        Some(block) => block,
        None => board.latest_block()?,
    };
    println!(
        "seller: watching board {} from block {cursor}; this node {}",
        hex(&board.address),
        iroh::SecretKey::from_bytes(&keys.node).public()
    );
    let mut queue: Vec<PostedTask> = vec![];
    let mut tried: HashSet<Hash> = HashSet::new();
    let mut settled = 0usize;
    loop {
        let latest = board.latest_block()?;
        if latest >= cursor {
            for notice in board.notices(cursor, latest)? {
                match notice {
                    board::Notice::Posted(posted) => queue.push(*posted),
                    board::Notice::Withdrawn(id) => {
                        tried.insert(id);
                    }
                }
            }
            cursor = latest + 1;
        }
        for posted in std::mem::take(&mut queue) {
            if !tried.insert(posted.id) {
                continue;
            }
            let id = hex(&posted.id);
            if only_poster.is_some_and(|only| only != posted.poster) {
                println!("seller: task {id} is another poster's; left alone");
                continue;
            }
            if board.withdrawn(posted.id)? {
                println!("seller: task {id} was withdrawn");
                continue;
            }
            println!(
                "seller: task {id} posted by {} for at most {}",
                hex(&posted.poster),
                U256::from_be_bytes(posted.task.maximum_amount)
            );
            if quote_only {
                // As far as a reviewed offer and no further: this seller
                // takes no authorization, so it cannot fund.
                let reviewed = wanted(&terms, &posted, system_clock())
                    .and_then(|()| IrohBuyer::new_in(&keys, &posted, &config.relay, allow_private))
                    .and_then(|buyer| review(&terms, &prover, &posted, &buyer, system_clock));
                match reviewed {
                    Ok(reviewed) => {
                        println!(
                            "seller: task {id}: quote only: artifact passes the checker; the buyer would sign for order {} ({}). Nothing signed, nothing funded",
                            hex(&reviewed.order),
                            reviewed.reply
                        );
                        settled += 1;
                    }
                    Err(skip) => println!("seller: task {id} not taken: {skip}"),
                }
                continue;
            }
            // Whether the post is for this seller's vault, token and judge is
            // settled before its address hint is read or anything is dialled.
            let accepted = wanted(&terms, &posted, system_clock())
                .and_then(|()| IrohBuyer::new_in(&keys, &posted, &config.relay, allow_private))
                .and_then(|buyer| answer(&terms, &prover, &posted, &buyer, system_clock));
            let accepted = match accepted {
                Ok(accepted) => accepted,
                Err(skip) => {
                    println!("seller: task {id} not taken: {skip}");
                    continue;
                }
            };
            println!(
                "seller: buyer signed for order {}; funding, proving, settling",
                hex(&accepted.funding.digest())
            );
            let at = |step: Step| println!("seller: task {id}: {step:?}");
            match on_chain.settle(&id, accepted, &at) {
                Ok(_) => settled += 1,
                Err(error) => println!("seller: task {id} failed: {error}"),
            }
        }
        if config.stop_after.is_some_and(|limit| settled >= limit) {
            return Ok(());
        }
        std::thread::sleep(poll);
    }
}
