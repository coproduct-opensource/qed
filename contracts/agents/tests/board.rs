//! Trading through the task board, without a chain: a buyer's desk behind a
//! real iroh endpoint on the loopback interface (no relay, no address
//! lookup), serving its statement as a blob, and a seller answering a posted
//! task as `nucleus-seller watch` does once it has read the post.
//!
//! Each refusal below was driven red once by deleting the check it tests;
//! docs/rfcs/proof-commerce-task-board-2026-11-12.md has the table.
use nucleus_board_reference::{self as reference, PostedTask, Task};
use nucleus_commerce_agents::{
    blobs, board,
    buyer::ask,
    desk::{Desk, Posted, Refused},
    dpop::dpop_make,
    iroh_net::{self, IrohTransport},
    job::Declined,
    message::{Reply, Request, Transport},
    seller::{Prover, Terms},
    support::Keys,
    watch::{BuyerLink, IrohBuyer, Skip, answer, wanted},
    world::wall_clock,
};
use nucleus_proof_acceptance::Policy;
use nucleus_proof_commerce::{
    vault::{self, wire as vault_wire},
    x402::{
        TokenDomain,
        wire::{REQUIRED_HEADER, SIGNATURE_HEADER},
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

const STATEMENT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/task.ndjson");
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proof-acceptance/core/tests/fixtures"
);
const CHAIN: u64 = 421614;
const BOARD: [u8; 20] = [0xb0; 20];
const TOKEN: [u8; 20] = [0x33; 20];
const VERIFIER: [u8; 20] = [0x44; 20];
const PROGRAM: [u8; 32] = [0x55; 32];
const CAP: u64 = 300_000;
const PRICE: u64 = 250_000;

fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "board-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
fn keys(name: &str) -> Keys {
    Keys::load_or_create(scratch(name).join("keys").to_str().unwrap()).unwrap()
}
fn deployment() -> vault::Deployment {
    vault::Deployment {
        chain_id: CHAIN,
        vault: [0x11; 20],
        treasury: [0x22; 20],
        fee_bps: 25,
        maximum_fee_bps: 100,
        rules: nucleus_proof_commerce::vault::Rules::Second,
    }
}
fn domain() -> TokenDomain {
    TokenDomain {
        name: "USD Coin".into(),
        version: "2".into(),
    }
}
fn policy() -> Policy {
    Policy {
        statement_sha256: Sha256::digest(STATEMENT).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
fn now() -> u64 {
    wall_clock().unwrap()
}

/// A buyer that has "posted" one task: its desk and its statement blob are
/// served on an iroh endpoint. The post itself is handed to the seller
/// directly, as if read from the chain.
struct Buyer {
    _runtime: tokio::runtime::Runtime,
    _router: iroh::protocol::Router,
    desk: Arc<Mutex<Desk>>,
    keys: Keys,
    node: String,
    posted: PostedTask,
}
impl Buyer {
    /// `served` is what the blob store holds; `change` edits the task after
    /// its hashes are set.
    fn with(served: &[u8], change: fn(&mut Task)) -> Self {
        let keys = keys("buyer");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime
            .block_on(async {
                iroh_net::endpoint(keys.node, "127.0.0.1:0".parse().unwrap())
                    .await
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        let node = endpoint.id().to_string();
        let address = iroh_net::address_text(&endpoint)
            .unwrap()
            .split_once('@')
            .unwrap()
            .1
            .to_owned();
        let store = {
            let _guard = runtime.enter();
            blobs::store()
        };
        let blake3 = runtime
            .block_on(blobs::add(&store, served.to_vec()))
            .unwrap();
        let policy = policy();
        let mut task = Task {
            statement_sha256: policy.statement_sha256,
            statement_blake3: blake3,
            policy_hash: policy.hash(),
            asset: TOKEN,
            maximum_amount: vault_amount(CAP),
            verifier: VERIFIER,
            program: PROGRAM,
            fund_by: now() + 1_800,
            deliver_by: now() + 4 * 3_600,
            buyer_node: board::node_bytes(&node).unwrap(),
            buyer_key_binding: keys.binding(),
            salt: [9; 32],
            buyer_address: address,
        };
        change(&mut task);
        let id = reference::id(CHAIN, BOARD, keys.address(), &task);
        let mut desk = Desk::new(deployment(), domain(), keys.wallet.clone());
        desk.open(Posted::new(id, task.clone(), policy).unwrap());
        let desk = Arc::new(Mutex::new(desk));
        let router = {
            let _guard = runtime.enter();
            iroh_net::serve_with(endpoint, desk.clone(), Some(&store))
        };
        let posted = PostedTask {
            id,
            poster: keys.address(),
            vault: deployment().vault,
            task,
        };
        Self {
            _runtime: runtime,
            _router: router,
            desk,
            keys,
            node,
            posted,
        }
    }
    fn new() -> Self {
        Self::with(STATEMENT, |_| {})
    }
    fn address(&self) -> String {
        format!("iroh:{}@{}", self.node, self.posted.task.buyer_address)
    }
    fn dial(&self, keys: &Keys) -> IrohTransport {
        IrohTransport::new(keys.node, &self.address()).unwrap()
    }
    fn open(&self) -> bool {
        self.desk.lock().unwrap().open_for_offers(&self.posted.id)
    }
}
fn vault_amount(units: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&units.to_be_bytes());
    word
}

struct Seller {
    keys: Keys,
    terms: Terms,
    prover: Prover,
}
impl Seller {
    fn with_artifact(artifact: &str) -> Self {
        let keys = keys("seller");
        let terms = Terms {
            deployment: deployment(),
            domain: domain(),
            token: TOKEN,
            verifier: VERIFIER,
            program: PROGRAM,
            seller: keys.address(),
            price: PRICE,
            fund_seconds: 900,
            deliver_seconds: 3 * 3600,
            base: None,
        };
        let prover = Prover {
            command: vec![
                env!("CARGO_BIN_EXE_nucleus-fixture-prover").into(),
                format!("{FIXTURES}/task.ndjson"),
                artifact.into(),
            ],
            timeout: Duration::from_secs(30),
            work: scratch("jobs"),
        };
        Self {
            keys,
            terms,
            prover,
        }
    }
    fn new() -> Self {
        Self::with_artifact(&format!("{FIXTURES}/suffix.ndjson"))
    }
    fn answer(&self, buyer: &Buyer) -> Result<nucleus_commerce_agents::job::Accepted, Skip> {
        let link = IrohBuyer::new(&self.keys, &buyer.posted).unwrap();
        answer(&self.terms, &self.prover, &buyer.posted, &link, now)
    }
    /// This seller's order for the buyer's task, with one change.
    fn order(&self, buyer: &Buyer, change: fn(&mut vault::Order)) -> vault::Order {
        let task = &buyer.posted.task;
        let mut order = vault::Order {
            buyer: buyer.posted.poster,
            seller: self.keys.address(),
            asset: TOKEN,
            amount: vault_amount(PRICE),
            verifier: VERIFIER,
            program: PROGRAM,
            policy_hash: task.policy_hash,
            base: [0; 32],
            fund_by: now() + 900,
            deliver_by: now() + 3 * 3600,
            salt: [7; 32],
            context: board::context(buyer.posted.id, task.buyer_key_binding),
        };
        change(&mut order);
        order
    }
    /// Present an order to the buyer's desk as an x402 offer.
    fn offer(&self, buyer: &Buyer, order: &vault::Order) -> Reply {
        let header = vault_wire::required_header(
            serde_json::json!({"url": "test"}),
            vault_wire::requirements(&deployment(), &domain(), order, 60),
        )
        .unwrap();
        ask(
            &buyer.dial(&self.keys),
            &self.keys,
            "POST",
            &board::offer_path(&buyer.posted.id),
            [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
            vec![],
        )
        .unwrap()
    }
}
fn text(reply: &Reply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
}

#[test]
fn a_seller_that_read_the_post_proves_offers_and_is_signed_for_once() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    assert!(buyer.open());
    let accepted = seller.answer(&buyer).expect("the buyer signs");
    let order = accepted.funding.order();
    let task = &buyer.posted.task;
    assert_eq!(order.buyer, buyer.keys.address());
    assert_eq!(order.seller, seller.keys.address());
    assert_eq!(order.amount, vault_amount(PRICE));
    assert_eq!(
        order.context,
        board::context(buyer.posted.id, task.buyer_key_binding)
    );
    assert!(order.fund_by <= task.fund_by && order.deliver_by <= task.deliver_by);
    assert_eq!(accepted.statement, STATEMENT);
    // The desk holds the same order, and the post is spent.
    let signed = buyer
        .desk
        .lock()
        .unwrap()
        .signed(&buyer.posted.id)
        .expect("signed");
    assert_eq!(signed.digest, accepted.funding.digest());
    assert!(!buyer.open());

    // A second seller with as good an offer is refused: first offer wins.
    let late = Seller::new();
    match late.answer(&buyer) {
        // The desk no longer serves the policy of a task that is not open.
        Err(Skip::Unreachable(why)) => assert!(why.contains("409"), "{why}"),
        other => panic!("a second seller was not refused: {other:?}"),
    }
    let reply = late.offer(&buyer, &late.order(&buyer, |_| {}));
    assert_eq!(reply.status, 409, "{}", text(&reply));
    assert!(reply.header(SIGNATURE_HEADER).is_none());
}

#[test]
fn an_offer_without_a_valid_fresh_proof_bound_to_the_sellers_node_is_refused() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    let transport = buyer.dial(&seller.keys);
    let path = board::path(&buyer.posted.id);
    let good_uri = format!("{}{path}", transport.base());
    let node = transport.node().unwrap();
    let send = |proof: Option<String>| -> Reply {
        let mut headers = BTreeMap::new();
        if let Some(proof) = proof {
            headers.insert("dpop".to_owned(), proof);
        }
        transport
            .send(&Request {
                method: "GET".into(),
                path: path.clone(),
                headers,
                body: vec![],
            })
            .unwrap()
    };
    let make = |method: &str, uri: &str, at: u64, nid: Option<&str>| {
        dpop_make(&seller.keys.possession, method, uri, at, nid).unwrap()
    };
    let refused = |reply: Reply, why: &str| {
        assert_eq!(reply.status, 401, "{}", text(&reply));
        assert!(text(&reply).contains(why), "{} lacks {why:?}", text(&reply));
    };

    refused(send(None), "missing");
    // A signature that does not verify.
    // (The first character of the signature part is changed: unlike the
    // last, every base64url character is valid there, so the proof still
    // decodes and it is the signature check that refuses it.)
    let good = make("GET", &good_uri, now(), Some(&node));
    let at = good.rfind('.').unwrap() + 1;
    let swapped = if good.as_bytes()[at] == b'A' {
        "B"
    } else {
        "A"
    };
    let forged = format!("{}{swapped}{}", &good[..at], &good[at + 1..]);
    refused(send(Some(forged)), "signature refused");
    // Another method, another path, another node's URI.
    refused(
        send(Some(make("POST", &good_uri, now(), Some(&node)))),
        "another method or URI",
    );
    let other_path = format!("{}/task/0x00", transport.base());
    refused(
        send(Some(make("GET", &other_path, now(), Some(&node)))),
        "another method or URI",
    );
    let other_node = format!("iroh://{node}{path}");
    refused(
        send(Some(make("GET", &other_node, now(), Some(&node)))),
        "another method or URI",
    );
    // Stale, and from the future.
    refused(
        send(Some(make("GET", &good_uri, now() - 1_000, Some(&node)))),
        "stale",
    );
    refused(
        send(Some(make("GET", &good_uri, now() + 1_000, Some(&node)))),
        "stale",
    );
    // Not bound to this connection's node: no node named, or another's.
    refused(send(Some(make("GET", &good_uri, now(), None))), "not bound");
    refused(
        send(Some(make("GET", &good_uri, now(), Some(&buyer.node)))),
        "not bound",
    );
    // A good proof works once and only once.
    let good = make("GET", &good_uri, now(), Some(&node));
    assert_eq!(send(Some(good.clone())).status, 200);
    refused(send(Some(good)), "replayed");

    // The same holds for the offer itself: a valid offer with no proof.
    let header = vault_wire::required_header(
        serde_json::json!({"url": "test"}),
        vault_wire::requirements(&deployment(), &domain(), &seller.order(&buyer, |_| {}), 60),
    )
    .unwrap();
    let bare = transport
        .send(&Request {
            method: "POST".into(),
            path: board::offer_path(&buyer.posted.id),
            headers: [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
            body: vec![],
        })
        .unwrap();
    refused(bare, "missing");
    assert!(buyer.open(), "nothing was signed for");
}

#[test]
fn an_offer_that_is_not_for_this_post_on_its_terms_is_refused() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    type Case = (fn(&mut vault::Order), &'static str);
    let cases: [Case; 10] = [
        // Another task's context: an order for some other post.
        (
            |o| o.context = board::context([0xee; 32], [0xdd; 32]),
            "another wallet, token, policy or context",
        ),
        (
            |o| o.buyer = [0x99; 20],
            "another wallet, token, policy or context",
        ),
        (
            |o| o.asset = [0x98; 20],
            "another wallet, token, policy or context",
        ),
        (
            |o| o.policy_hash = [0x97; 32],
            "another wallet, token, policy or context",
        ),
        (|o| o.verifier = [0x96; 20], "verifier or proof program"),
        (|o| o.program = [0x95; 32], "verifier or proof program"),
        (
            |o| o.amount[24..].copy_from_slice(&(CAP + 1).to_be_bytes()),
            "exceeds the buyer's limit",
        ),
        (|o| o.deliver_by += 2 * 3600, "deadlines fall outside"),
        (
            |o| o.fund_by += 1_000,
            "funding deadline is later than posted",
        ),
        // No time left to relay the funding.
        (|o| o.fund_by = now() + 10, "deadlines fall outside"),
    ];
    for (change, why) in cases {
        let reply = seller.offer(&buyer, &seller.order(&buyer, change));
        assert_eq!(reply.status, 422, "{why}: {}", text(&reply));
        assert!(text(&reply).contains(why), "{} lacks {why:?}", text(&reply));
        assert!(reply.header(SIGNATURE_HEADER).is_none());
        assert!(buyer.open(), "{why}: something was signed for");
    }
    // An offer for a task this desk never posted.
    let header = vault_wire::required_header(
        serde_json::json!({"url": "test"}),
        vault_wire::requirements(&deployment(), &domain(), &seller.order(&buyer, |_| {}), 60),
    )
    .unwrap();
    let elsewhere = ask(
        &buyer.dial(&seller.keys),
        &seller.keys,
        "POST",
        &board::offer_path(&[0xab; 32]),
        [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
        vec![],
    )
    .unwrap();
    assert_eq!(elsewhere.status, 404, "{}", text(&elsewhere));
    // No offer at all.
    let empty = ask(
        &buyer.dial(&seller.keys),
        &seller.keys,
        "POST",
        &board::offer_path(&buyer.posted.id),
        BTreeMap::new(),
        vec![],
    )
    .unwrap();
    assert_eq!(empty.status, 400, "{}", text(&empty));
    assert!(buyer.open());

    // The unchanged order, at the cap exactly, is signed for.
    let at_cap = seller.order(&buyer, |o| {
        o.amount[24..].copy_from_slice(&CAP.to_be_bytes())
    });
    let reply = seller.offer(&buyer, &at_cap);
    assert_eq!(reply.status, 200, "{}", text(&reply));
    let funding = vault_wire::admit_header(
        &deployment(),
        &domain(),
        reply.header(SIGNATURE_HEADER).unwrap(),
        60,
        now(),
    )
    .expect("the buyer's authorization is valid for the offered order");
    assert_eq!(funding.order(), &at_cap);
}

#[test]
fn a_seller_does_not_offer_for_a_statement_or_policy_other_than_the_posted_one() {
    // The buyer's node serves other bytes under the posted blob hash's place:
    // the post pins the fixture by SHA-256 but names another blob.
    let buyer = Buyer::with(b"not the pinned statement", |_| {});
    let seller = Seller::new();
    assert_eq!(
        seller.answer(&buyer).unwrap_err(),
        Skip::Declined(Declined::StatementNotPinned)
    );
    assert!(buyer.open());

    // A buyer whose node serves a different policy than the post commits to.
    struct OtherPolicy<'a>(IrohBuyer<'a>);
    impl BuyerLink for OtherPolicy<'_> {
        fn base(&self) -> String {
            self.0.base()
        }
        fn policy(&self, id: &[u8; 32]) -> nucleus_commerce_agents::chain::Res<Policy> {
            let mut policy = self.0.policy(id)?;
            policy.permitted_axioms.push("Classical.choice".into());
            Ok(policy)
        }
        fn statement(&self, blake3: &[u8; 32]) -> nucleus_commerce_agents::chain::Res<Vec<u8>> {
            self.0.statement(blake3)
        }
        fn offer(
            &self,
            id: &[u8; 32],
            header: String,
        ) -> nucleus_commerce_agents::chain::Res<Reply> {
            self.0.offer(id, header)
        }
    }
    let honest = Buyer::new();
    let link = OtherPolicy(IrohBuyer::new(&seller.keys, &honest.posted).unwrap());
    assert_eq!(
        answer(&seller.terms, &seller.prover, &honest.posted, &link, now).unwrap_err(),
        Skip::PolicyNotPosted
    );
    assert!(honest.open());

    // A prover whose artifact the checker refuses: no offer is made.
    let wrong = Seller::with_artifact(&format!("{FIXTURES}/task.ndjson"));
    match wrong.answer(&honest) {
        Err(Skip::Declined(Declined::NotAccepted(_))) => {}
        other => panic!("offered without a checked artifact: {other:?}"),
    }
    assert!(honest.open());
}

#[test]
fn a_seller_passes_over_posts_it_could_not_serve() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    assert_eq!(wanted(&seller.terms, &buyer.posted, now()), Ok(()));
    type Case = (fn(&mut PostedTask), Skip);
    let cases: [Case; 7] = [
        (|p| p.vault = [0x12; 20], Skip::OtherVault),
        (|p| p.task.asset = [0x34; 20], Skip::OtherAsset),
        (|p| p.task.verifier = [0x45; 20], Skip::OtherJudge),
        (|p| p.task.program = [0x56; 32], Skip::OtherJudge),
        (
            |p| p.task.maximum_amount = vault_amount(PRICE - 1),
            Skip::Price,
        ),
        (|p| p.task.fund_by = now() + 60, Skip::Deadline),
        (|p| p.task.deliver_by = now() + 600, Skip::Deadline),
    ];
    for (change, expected) in cases {
        let mut posted = buyer.posted.clone();
        change(&mut posted);
        assert_eq!(wanted(&seller.terms, &posted, now()), Err(expected));
    }
    // The price exactly at the cap is wanted.
    let mut at_cap = buyer.posted.clone();
    at_cap.task.maximum_amount = vault_amount(PRICE);
    assert_eq!(wanted(&seller.terms, &at_cap, now()), Ok(()));
}

#[test]
fn nothing_is_signed_for_an_offer_reviewed_against_another_post() {
    let (a, b) = (keys("a"), keys("b"));
    let seller = Seller::new();
    let make = |keys: &Keys, salt: u8| -> Posted {
        let policy = policy();
        let task = Task {
            statement_sha256: policy.statement_sha256,
            statement_blake3: [1; 32],
            policy_hash: policy.hash(),
            asset: TOKEN,
            maximum_amount: vault_amount(CAP),
            verifier: VERIFIER,
            program: PROGRAM,
            fund_by: now() + 1_800,
            deliver_by: now() + 4 * 3_600,
            buyer_node: [2; 32],
            buyer_key_binding: keys.binding(),
            salt: [salt; 32],
            buyer_address: "127.0.0.1:1".into(),
        };
        let id = reference::id(CHAIN, BOARD, keys.address(), &task);
        Posted::new(id, task, policy).unwrap()
    };
    let (first, second) = (make(&a, 1), make(&a, 2));
    let order = |posted: &Posted| vault::Order {
        buyer: a.address(),
        seller: seller.keys.address(),
        asset: TOKEN,
        amount: vault_amount(PRICE),
        verifier: VERIFIER,
        program: PROGRAM,
        policy_hash: posted.task().policy_hash,
        base: [0; 32],
        fund_by: now() + 900,
        deliver_by: now() + 3 * 3600,
        salt: [7; 32],
        context: board::context(posted.id(), posted.task().buyer_key_binding),
    };
    let header = |order: &vault::Order| {
        vault_wire::required_header(
            serde_json::json!({"url": "test"}),
            vault_wire::requirements(&deployment(), &domain(), order, 60),
        )
        .unwrap()
    };
    // An order for the first post does not pass review at the second.
    assert!(matches!(
        second.review(
            &deployment(),
            &domain(),
            a.address(),
            &header(&order(&first)),
            now(),
            &[]
        ),
        Err(Refused::Offer(vault_wire::OfferError::NotMyOrder))
    ));
    // An offer reviewed for the first post cannot be signed at the second.
    let offered = first
        .review(
            &deployment(),
            &domain(),
            a.address(),
            &header(&order(&first)),
            now(),
            &[],
        )
        .unwrap();
    assert!(
        second
            .clone()
            .sign(offered, &deployment(), &a.wallet)
            .is_err()
    );
    // A policy that is not the task's cannot be put on the desk at all.
    let mut other = policy();
    other.claim = "Nucleus.Other".into();
    assert!(Posted::new(first.id(), first.task().clone(), other).is_err());
    // And a task posted under another key's binding has another context.
    assert_ne!(
        board::context(first.id(), a.binding()),
        board::context(first.id(), b.binding())
    );

    // On a third-form vault an order may name a base library. A post's review
    // refuses one the buyer did not list, and passes it priced from the
    // listed registry entry.
    let third = vault::Deployment {
        rules: nucleus_proof_commerce::vault::Rules::Third {
            maximum_term: 30 * 24 * 3600,
            registry: [0x33; 20],
        },
        ..deployment()
    };
    let mut on_base = order(&first);
    on_base.base = [0x44; 32];
    let header3 = vault_wire::required_header(
        serde_json::json!({"url": "test"}),
        vault_wire::requirements(&third, &domain(), &on_base, 60),
    )
    .unwrap();
    assert!(matches!(
        first.review(&third, &domain(), a.address(), &header3, now(), &[]),
        Err(Refused::Offer(vault_wire::OfferError::UnsupportedBase))
    ));
    let listed = [(
        [0x44; 32],
        vault::Entry {
            payee: [0x55; 20],
            bps: 10,
        },
    )];
    assert!(
        first
            .review(&third, &domain(), a.address(), &header3, now(), &listed)
            .is_ok()
    );
}

/// The bounty's rule 3: a desk told to record signatures releases none it
/// could not record, and records each before the seller has it.
#[test]
fn a_signature_is_recorded_before_it_is_released_and_not_released_if_it_cannot_be() {
    // The record fails: no authorization leaves, and the post is closed.
    let buyer = Buyer::new();
    buyer
        .desk
        .lock()
        .unwrap()
        .record_signatures(Box::new(|_| Err("disk full".into())));
    let seller = Seller::new();
    let reply = seller.offer(&buyer, &seller.order(&buyer, |_| {}));
    assert_eq!(reply.status, 409, "{}", text(&reply));
    assert!(reply.header(SIGNATURE_HEADER).is_none());
    assert!(
        buyer
            .desk
            .lock()
            .unwrap()
            .signed(&buyer.posted.id)
            .is_none()
    );
    assert!(!buyer.open());

    // The record succeeds: it holds the order the seller is then given.
    let buyer = Buyer::new();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = recorded.clone();
    buyer
        .desk
        .lock()
        .unwrap()
        .record_signatures(Box::new(move |signed| {
            sink.lock()
                .unwrap()
                .push((signed.digest, signed.payment.clone()));
            Ok(())
        }));
    let order = seller.order(&buyer, |_| {});
    let reply = seller.offer(&buyer, &order);
    assert_eq!(reply.status, 200, "{}", text(&reply));
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, vault::digest(&deployment(), &order));
    assert_eq!(Some(recorded[0].1.as_str()), reply.header(SIGNATURE_HEADER));
}

// ---- After the independent read of 2026-11-13 (findings 3, 4 and 5 of
// docs/rfcs/proof-commerce-v3-review-2026-11-13.md). Each rule below was
// driven red once by deleting its check; the RFC has the table.

use alloy_primitives::U256;
use nucleus_commerce_agents::{
    iroh_net::Relay,
    job::{Accepted, Step},
    watch::peer_hint,
    worker::{ClearToProve, ClearToSettle, Limits, Sealer, Venue, work},
};

/// A vault that records what it is asked and answers from a script.
struct ScriptedVenue {
    booked: U256,
    /// Block times, one per question, the last repeated.
    times: Mutex<Vec<u64>>,
    log: Arc<Mutex<Vec<&'static str>>>,
}
impl Venue for ScriptedVenue {
    fn fund(
        &self,
        _order: &vault::Order,
        _signature: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.log.lock().unwrap().push("fund");
        Ok("0xfund".into())
    }
    fn booked_royalty(&self, _digest: [u8; 32]) -> Result<U256, Box<dyn std::error::Error>> {
        Ok(self.booked)
    }
    fn now(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let mut times = self.times.lock().unwrap();
        Ok(if times.len() > 1 {
            times.remove(0)
        } else {
            times[0]
        })
    }
    fn settle(
        &self,
        _clear: ClearToSettle,
        _order: &vault::Order,
        _artifact: &[u8],
        _seal: Vec<u8>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.log.lock().unwrap().push("settle");
        Ok("0xsettle".into())
    }
    fn collect(&self, _order: &vault::Order) {
        self.log.lock().unwrap().push("collect");
    }
}
struct RecordingSealer(Arc<Mutex<Vec<&'static str>>>);
impl Sealer for RecordingSealer {
    fn seal(
        &self,
        _clear: &ClearToProve,
        _id: &str,
        _accepted: &Accepted,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.0.lock().unwrap().push("seal");
        Ok(vec![0; 260])
    }
}
const LIMITS: Limits = Limits {
    settle_margin: 120,
    expected_proving: 900,
};
/// Run the seller's worker on an order a real buyer desk signed for, against
/// a scripted vault. Returns what the worker sent, in order, and how it ended.
fn worked(booked: u64, times: fn(u64) -> Vec<u64>) -> (Vec<&'static str>, Result<(), String>) {
    let buyer = Buyer::new();
    let seller = Seller::new();
    let accepted = seller.answer(&buyer).unwrap();
    let deliver_by = accepted.funding.order().deliver_by;
    let log = Arc::new(Mutex::new(vec![]));
    let venue = ScriptedVenue {
        booked: U256::from(booked),
        times: Mutex::new(times(deliver_by)),
        log: log.clone(),
    };
    let outcome = work(
        &venue,
        &RecordingSealer(log.clone()),
        &LIMITS,
        U256::ZERO,
        "job",
        &accepted,
        &|_: Step| {},
    )
    .map(|_| ())
    .map_err(|error| error.to_string());
    let sent = log.lock().unwrap().clone();
    (sent, outcome)
}

#[test]
fn a_funded_order_is_proved_settled_and_collected_when_terms_and_time_hold() {
    let (sent, outcome) = worked(0, |deliver_by| vec![deliver_by - 5_000, deliver_by - 4_000]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(sent, ["fund", "seal", "settle", "collect"]);
}

#[test]
fn a_seller_does_not_prove_an_order_the_vault_booked_a_larger_royalty_for_than_it_quoted() {
    // Quoted on no royalty; the vault booked one unit for a base registered
    // between the offer and `fund`.
    let (sent, outcome) = worked(1, |deliver_by| vec![deliver_by - 5_000]);
    assert_eq!(sent, ["fund"], "nothing is proved and nothing more is sent");
    let why = outcome.unwrap_err();
    assert!(why.contains("royalty of 1"), "{why}");
    assert!(why.contains("refundable to the buyer"), "{why}");
}

#[test]
fn a_seller_does_not_start_a_proof_it_could_not_settle_outside_the_margin() {
    // 1,019 s left; 900 to prove and 120 of margin are needed.
    let (sent, outcome) = worked(0, |deliver_by| vec![deliver_by - 1_019]);
    assert_eq!(sent, ["fund"]);
    assert!(outcome.unwrap_err().contains("too little time to prove"));
    // With exactly 1,020 s it starts.
    let (sent, outcome) = worked(0, |deliver_by| vec![deliver_by - 1_020, deliver_by - 500]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(sent.len(), 4);
}

#[test]
fn a_proof_that_is_ready_inside_the_margin_is_not_submitted() {
    // Proving overran: 119 s are left when the seal is ready.
    let (sent, outcome) = worked(0, |deliver_by| vec![deliver_by - 5_000, deliver_by - 119]);
    assert_eq!(
        sent,
        ["fund", "seal"],
        "the artifact is not put in calldata"
    );
    assert!(outcome.unwrap_err().contains("Not submitted"));
    // At exactly the margin it is submitted.
    let (sent, outcome) = worked(0, |deliver_by| vec![deliver_by - 5_000, deliver_by - 120]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(sent, ["fund", "seal", "settle", "collect"]);
}

fn log_json(emitter: [u8; 20], id: [u8; 32]) -> serde_json::Value {
    let hex = |bytes: &[u8]| {
        format!(
            "0x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    serde_json::json!({
        "address": hex(&emitter),
        "topics": [hex(&reference::withdrawn_topic()), hex(&id)],
        "data": "0x",
    })
}

#[test]
fn a_log_from_another_contract_is_not_a_notice_of_the_board() {
    let id = [0x77; 32];
    assert_eq!(
        board::notice_from_log(&BOARD, &log_json(BOARD, id)).unwrap(),
        reference::Notice::Withdrawn(id)
    );
    // The same event, emitted by some other contract.
    let refusal = board::notice_from_log(&BOARD, &log_json([0xee; 20], id)).unwrap_err();
    assert!(refusal.to_string().contains("was returned for the board"));
}

/// A buyer link that must never be used.
struct NoContact;
impl BuyerLink for NoContact {
    fn base(&self) -> String {
        panic!("the buyer was contacted")
    }
    fn policy(&self, _id: &[u8; 32]) -> Result<Policy, Box<dyn std::error::Error>> {
        panic!("the buyer was contacted")
    }
    fn statement(&self, _blake3: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        panic!("the buyer was contacted")
    }
    fn offer(&self, _id: &[u8; 32], _header: String) -> Result<Reply, Box<dyn std::error::Error>> {
        panic!("the buyer was contacted")
    }
}

#[test]
fn a_post_naming_another_vault_is_passed_over_before_the_buyer_is_contacted() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    let mut posted = buyer.posted.clone();
    posted.vault = [0x12; 20];
    assert_eq!(
        answer(&seller.terms, &seller.prover, &posted, &NoContact, now).unwrap_err(),
        Skip::OtherVault
    );
}

#[test]
fn an_address_hint_is_a_public_socket_address_or_the_post_is_passed_over() {
    let unsafe_for = |hint: &str, relay: &Relay| match peer_hint(hint, relay, false) {
        Err(Skip::UnsafeAddress(why)) => why,
        other => panic!("{hint}: {other:?}"),
    };
    // Public addresses are taken as they are.
    for hint in ["203.0.113.7:4450", "[2001:db8::7]:4450"] {
        assert_eq!(
            peer_hint(hint, &Relay::None, false).unwrap(),
            Some(hint.parse().unwrap())
        );
    }
    // Inside the seller's own machine or network.
    for hint in [
        "127.0.0.1:4450",
        "10.0.0.5:22",
        "172.16.3.4:80",
        "192.168.1.1:80",
        "169.254.169.254:80",
        "100.64.0.1:80",
        "0.0.0.0:80",
        "0.1.2.3:80",
        "224.0.0.1:80",
        "255.255.255.255:80",
        "[::1]:80",
        "[::]:80",
        "[fd00::1]:80",
        "[fe80::1]:80",
        "[ff02::1]:80",
        "[::ffff:127.0.0.1]:80",
        "[::ffff:10.0.0.5]:80",
    ] {
        assert!(
            unsafe_for(hint, &Relay::None).contains("loopback, private"),
            "{hint}"
        );
        // The one-machine switch takes them.
        assert!(peer_hint(hint, &Relay::None, true).unwrap().is_some());
    }
    // Not a socket address at all.
    for hint in [
        "example.com:80",
        "http://203.0.113.7:80",
        "203.0.113.7",
        "203.0.113.7:80/x",
    ] {
        assert_eq!(
            unsafe_for(hint, &Relay::None),
            "not a socket address",
            "{hint}"
        );
        assert!(peer_hint(hint, &Relay::None, true).is_err(), "{hint}");
    }
    assert_eq!(unsafe_for("203.0.113.7:0", &Relay::None), "port 0");
    // Longer than any socket address, whatever it says.
    let long = format!("203.0.113.7:80{}", " ".repeat(64));
    assert_eq!(
        unsafe_for(&long, &Relay::None),
        "longer than a socket address"
    );
    // No hint: the node ID alone, which needs a relay.
    assert_eq!(peer_hint("", &Relay::Default, false).unwrap(), None);
    assert!(unsafe_for("", &Relay::None).contains("no address"));

    // And through the link a watching seller builds: a post pointing at the
    // loopback interface is not dialled unless the switch is set.
    let buyer = Buyer::new();
    let seller = Seller::new();
    assert!(matches!(
        IrohBuyer::new_in(&seller.keys, &buyer.posted, &Relay::None, false),
        Err(Skip::UnsafeAddress(_))
    ));
    assert!(IrohBuyer::new_in(&seller.keys, &buyer.posted, &Relay::None, true).is_ok());
}

// ---- Review only: a seller's dry run -------------------------------------

/// A seller run with `quoteOnly` proves, has its artifact checked and its
/// offer reviewed by the buyer's desk, and nothing is signed: the post stays
/// open and another seller can still be signed for.
#[test]
fn a_review_says_whether_the_desk_would_sign_and_signs_nothing() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    let link = IrohBuyer::new(&seller.keys, &buyer.posted).unwrap();
    let reviewed = nucleus_commerce_agents::watch::review(
        &seller.terms,
        &seller.prover,
        &buyer.posted,
        &link,
        now,
    )
    .expect("the desk would sign");
    assert!(reviewed.reply.contains("\"review\":\"passes\""));
    assert!(
        reviewed
            .reply
            .contains(&nucleus_commerce_agents::chain::hex(&reviewed.order))
    );
    // Nothing was signed, and the post is still open.
    assert!(buyer.open());
    assert!(
        buyer
            .desk
            .lock()
            .unwrap()
            .signed(&buyer.posted.id)
            .is_none()
    );
    // The same seller can then trade for real.
    let accepted = seller.answer(&buyer).expect("the buyer signs");
    assert!(!buyer.open());
    assert_eq!(
        vault::digest(&deployment(), accepted.funding.order()).len(),
        32
    );
}

/// A review applies the same rules as an offer: what the desk would refuse
/// to sign, it refuses to pass, and a review of a spent post is refused.
#[test]
fn a_review_refuses_what_an_offer_would_refuse() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    let review = |order: &vault::Order| {
        let header = vault_wire::required_header(
            serde_json::json!({"url": "test"}),
            vault_wire::requirements(&deployment(), &domain(), order, 60),
        )
        .unwrap();
        ask(
            &buyer.dial(&seller.keys),
            &seller.keys,
            "POST",
            &board::review_path(&buyer.posted.id),
            [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
            vec![],
        )
        .unwrap()
    };
    // Over the cap.
    let dear = seller.order(&buyer, |o| o.amount = vault_amount(CAP + 1));
    assert_eq!(review(&dear).status, 422);
    // Another policy.
    let other = seller.order(&buyer, |o| o.policy_hash = [3; 32]);
    assert_eq!(review(&other).status, 422);
    // A good order passes review, carries no authorization, and leaves the
    // post open.
    let good = seller.order(&buyer, |_| {});
    let reply = review(&good);
    assert_eq!(reply.status, 200, "{}", text(&reply));
    assert!(reply.header(SIGNATURE_HEADER).is_none());
    assert!(buyer.open());
    // Once the post is signed for, a review of it is refused like an offer.
    assert_eq!(seller.offer(&buyer, &good).status, 200);
    assert_eq!(review(&good).status, 409);
}

/// A review is an authenticated request like any other: without a proof of
/// possession the desk answers nothing about the offer.
#[test]
fn a_review_without_a_proof_is_refused() {
    let buyer = Buyer::new();
    let seller = Seller::new();
    let good = seller.order(&buyer, |_| {});
    let header = vault_wire::required_header(
        serde_json::json!({"url": "test"}),
        vault_wire::requirements(&deployment(), &domain(), &good, 60),
    )
    .unwrap();
    let transport = buyer.dial(&seller.keys);
    let reply = transport
        .send(&nucleus_commerce_agents::message::Request {
            method: "POST".into(),
            path: board::review_path(&buyer.posted.id),
            headers: [(REQUIRED_HEADER.to_ascii_lowercase(), header)].into(),
            body: vec![],
        })
        .unwrap();
    assert_eq!(reply.status, 401, "{}", text(&reply));
    assert!(buyer.open());
}

/// A buyer that answers a review with a signed authorization is not doing
/// what was asked. A seller that asked only for a review does not take it.
#[test]
fn a_seller_asking_for_a_review_takes_no_authorization() {
    struct SignsAnyway<'a>(IrohBuyer<'a>);
    impl BuyerLink for SignsAnyway<'_> {
        fn base(&self) -> String {
            self.0.base()
        }
        fn policy(&self, id: &[u8; 32]) -> nucleus_commerce_agents::chain::Res<Policy> {
            self.0.policy(id)
        }
        fn statement(&self, blake3: &[u8; 32]) -> nucleus_commerce_agents::chain::Res<Vec<u8>> {
            self.0.statement(blake3)
        }
        fn offer(
            &self,
            id: &[u8; 32],
            header: String,
        ) -> nucleus_commerce_agents::chain::Res<Reply> {
            self.0.offer(id, header)
        }
        fn review(
            &self,
            id: &[u8; 32],
            header: String,
        ) -> nucleus_commerce_agents::chain::Res<Reply> {
            self.0.offer(id, header)
        }
    }
    let buyer = Buyer::new();
    let seller = Seller::new();
    let link = SignsAnyway(IrohBuyer::new(&seller.keys, &buyer.posted).unwrap());
    match nucleus_commerce_agents::watch::review(
        &seller.terms,
        &seller.prover,
        &buyer.posted,
        &link,
        now,
    ) {
        Err(Skip::BadPayment(_)) => {}
        other => panic!("expected the authorization to be refused, got {other:?}"),
    }
}

/// The blob path carries a statement of the size a real Nucleus obligation
/// over the Aeneas library exports to (5.4 MB), within the seller's 8 MiB
/// limit. Prints the fetch time; run with `--nocapture` to read it.
#[test]
fn a_five_megabyte_statement_is_served_and_fetched_whole() {
    let large: Vec<u8> = (0..5_400_000u32)
        .map(|i| {
            if i % 97 == 96 {
                b'\n'
            } else {
                b'a' + (i % 23) as u8
            }
        })
        .collect();
    let buyer = Buyer::with(&large, |_| {});
    let seller = Seller::new();
    let link = IrohBuyer::new(&seller.keys, &buyer.posted).unwrap();
    let started = std::time::Instant::now();
    let fetched = link
        .statement(&buyer.posted.task.statement_blake3)
        .expect("the blob is served");
    println!(
        "fetched {} bytes in {:.3} s",
        fetched.len(),
        started.elapsed().as_secs_f64()
    );
    assert_eq!(fetched.len(), large.len());
    assert!(fetched == large);
    assert!(fetched.len() < nucleus_commerce_agents::message::MAXIMUM_STATEMENT);
}
