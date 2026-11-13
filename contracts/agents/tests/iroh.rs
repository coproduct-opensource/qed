//! The seller behind the iroh adapter, driven by real iroh endpoints on the
//! loopback interface (no relay, no address lookup). The settler is a
//! recorder: nothing here touches a chain.
//!
//! Each refusal below was driven red once by deleting the check it tests;
//! docs/rfcs/proof-commerce-harness-and-iroh-2026-11-12.md has the table.
use base64::Engine;
use nucleus_commerce_agents::{
    buyer::ask,
    dpop::{dpop_binding_of, dpop_make},
    iroh_net::{self, IrohTransport},
    job::Accepted,
    message::{MAXIMUM_BODY, MAXIMUM_STATEMENT, Reply, Request, Transport},
    seller::{Jobs, Prover, Seller, Settler, Terms},
    support::{B64, Keys, policy_json},
    world::wall_clock,
};
use nucleus_proof_acceptance::Policy;
use nucleus_proof_commerce::{
    vault::{self, wire as vault_wire},
    x402::{
        TokenDomain,
        wire::{BUYER_HEADER, REQUIRED_HEADER, SIGNATURE_HEADER, declaration_header, request_hash},
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

/// Records what was accepted and leaves the job working.
#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<String>>>);
impl Settler for Recorder {
    fn start(&self, id: String, _accepted: Accepted, _jobs: Jobs) {
        self.0.lock().unwrap().push(id);
    }
}

fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "iroh-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
fn keys(name: &str) -> Keys {
    Keys::load_or_create(scratch(name).join("keys").to_str().unwrap()).unwrap()
}

struct World {
    _runtime: tokio::runtime::Runtime,
    _router: iroh::protocol::Router,
    /// `iroh:<node id>@<ip:port>`
    address: String,
    terms: Terms,
    accepted: Recorder,
}
impl World {
    /// `artifact` is what the fixture prover hands back for the fixture statement.
    fn with_artifact(artifact: &str) -> Self {
        let seller_keys = keys("seller");
        let terms = Terms {
            deployment: vault::Deployment {
                chain_id: 421614,
                vault: [0x11; 20],
                treasury: [0x22; 20],
                fee_bps: 25,
                maximum_fee_bps: 100,
                rules: nucleus_proof_commerce::vault::Rules::Second,
            },
            domain: TokenDomain {
                name: "USD Coin".into(),
                version: "2".into(),
            },
            token: [0x33; 20],
            verifier: [0x44; 20],
            program: [0x55; 32],
            seller: seller_keys.address(),
            price: 250_000,
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
        let accepted = Recorder::default();
        let seller = Arc::new(Mutex::new(Seller::new(
            terms.clone(),
            prover,
            Box::new(accepted.clone()),
        )));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime
            .block_on(async {
                iroh_net::endpoint(seller_keys.node, "127.0.0.1:0".parse().unwrap())
                    .await
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        let address = iroh_net::address_text(&endpoint).unwrap();
        let router = {
            let _guard = runtime.enter();
            iroh_net::serve(endpoint, seller)
        };
        Self {
            _runtime: runtime,
            _router: router,
            address,
            terms,
            accepted,
        }
    }
    fn new() -> Self {
        Self::with_artifact(&format!("{FIXTURES}/suffix.ndjson"))
    }
    fn dial(&self, keys: &Keys) -> IrohTransport {
        IrohTransport::new(keys.node, &self.address).unwrap()
    }
}

fn policy(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: Sha256::digest(statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
fn work_body(statement: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "policy": policy_json(&policy(statement)), "statement": B64.encode(statement),
    }))
    .unwrap()
}
fn declaration(keys: &Keys) -> BTreeMap<String, String> {
    [(
        BUYER_HEADER.to_ascii_lowercase(),
        declaration_header(keys.address(), keys.binding()).unwrap(),
    )]
    .into()
}
/// POST /work for the fixture statement; returns the job path.
fn request_work(transport: &IrohTransport, keys: &Keys, statement: &[u8]) -> Reply {
    ask(
        transport,
        keys,
        "POST",
        "/work",
        declaration(keys),
        work_body(statement),
    )
    .unwrap()
}
fn job_of(reply: &Reply) -> String {
    assert_eq!(
        reply.status,
        202,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    reply.header("location").unwrap().to_owned()
}
/// GET the job until it is no longer being quoted.
fn await_quote(transport: &IrohTransport, keys: &Keys, job: &str) -> Reply {
    for _ in 0..200 {
        let reply = ask(transport, keys, "GET", job, BTreeMap::new(), vec![]).unwrap();
        if reply.status != 202 {
            return reply;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no answer for {job}");
}
fn text(reply: &Reply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
}
/// A request with exactly this DPoP header value (or none).
fn raw(
    transport: &IrohTransport,
    method: &str,
    path: &str,
    proof: Option<String>,
    keys: &Keys,
    body: Vec<u8>,
) -> Reply {
    let mut headers = declaration(keys);
    if let Some(proof) = proof {
        headers.insert("dpop".into(), proof);
    }
    transport
        .send(&Request {
            method: method.into(),
            path: path.into(),
            headers,
            body,
        })
        .unwrap()
}
fn proof(keys: &Keys, transport: &IrohTransport, method: &str, path: &str) -> String {
    dpop_make(
        &keys.possession,
        method,
        &format!("{}{path}", transport.base()),
        wall_clock().unwrap(),
        transport.node().as_deref(),
    )
    .unwrap()
}

#[test]
fn a_buyer_is_quoted_only_after_the_prover_succeeds_and_pays_once() {
    let world = World::new();
    let buyer = keys("buyer");
    let transport = world.dial(&buyer);
    let body = work_body(STATEMENT);
    let job = job_of(&request_work(&transport, &buyer, STATEMENT));
    let offered = await_quote(&transport, &buyer, &job);
    assert_eq!(offered.status, 402, "{}", text(&offered));

    // The offer passes the buyer's own review: its wallet, its request, its limits.
    let now = wall_clock().unwrap();
    let uri = format!("{}/work", transport.base());
    let intent = vault_wire::Intent {
        wallet: buyer.address(),
        asset: world.terms.token,
        policy_hash: policy(STATEMENT).hash(),
        context: vault_wire::context(request_hash("POST", &uri, &body), buyer.binding()),
        maximum_amount: [&[0u8; 24][..], &250_000u64.to_be_bytes()]
            .concat()
            .try_into()
            .unwrap(),
        verifiers: vec![world.terms.verifier],
        programs: vec![world.terms.program],
        fund_no_earlier_than: now + 60,
        deliver_no_later_than: now + 8 * 3600,
        bases: vec![],
    };
    let reviewed = vault_wire::review_offer(
        &world.terms.deployment,
        &world.terms.domain,
        offered.header(REQUIRED_HEADER).unwrap(),
        &intent,
        now,
    )
    .unwrap();
    assert_eq!(reviewed.order().seller, world.terms.seller);
    let signature = nucleus_commerce_agents::sign(&buyer.wallet, reviewed.signing_digest());
    let payment =
        vault_wire::signature_header(&world.terms.deployment, reviewed, &signature).unwrap();
    let pay = |keys: &Keys, transport: &IrohTransport| {
        ask(
            transport,
            keys,
            "POST",
            &job,
            [(SIGNATURE_HEADER.to_ascii_lowercase(), payment.clone())].into(),
            vec![],
        )
        .unwrap()
    };

    // Another key cannot pay for, or even see, this job.
    let other = keys("other");
    let other_transport = world.dial(&other);
    assert_eq!(pay(&other, &other_transport).status, 403);
    assert!(world.accepted.0.lock().unwrap().is_empty());

    assert_eq!(pay(&buyer, &transport).status, 202);
    assert_eq!(world.accepted.0.lock().unwrap().len(), 1);
    // The quote was consumed: the same authorization starts nothing twice.
    let again = pay(&buyer, &transport);
    assert_eq!(
        (again.status, text(&again).as_str()),
        (409, "this job has no open quote")
    );
    assert_eq!(world.accepted.0.lock().unwrap().len(), 1);
    let working = ask(&transport, &buyer, "GET", &job, BTreeMap::new(), vec![]).unwrap();
    assert_eq!(
        (working.status, working.header("nucleus-job")),
        (202, Some("funding"))
    );
}

#[test]
fn no_offer_is_made_without_an_artifact_the_checker_accepts() {
    // The prover has no proof for this statement.
    let world = World::new();
    let buyer = keys("buyer");
    let transport = world.dial(&buyer);
    let mut other = STATEMENT.to_vec();
    other.extend_from_slice(b"\n");
    let job = job_of(&request_work(&transport, &buyer, &other));
    let answer = await_quote(&transport, &buyer, &job);
    assert_eq!(answer.status, 422, "{}", text(&answer));
    assert!(
        text(&answer).starts_with("no proof found"),
        "{}",
        text(&answer)
    );

    // The prover hands back bytes that are not a proof of the claim.
    let world = World::with_artifact(&format!("{FIXTURES}/task.ndjson"));
    let transport = world.dial(&buyer);
    let job = job_of(&request_work(&transport, &buyer, STATEMENT));
    let answer = await_quote(&transport, &buyer, &job);
    assert_eq!(answer.status, 422, "{}", text(&answer));
    assert!(
        text(&answer).starts_with("proof refused by the checker"),
        "{}",
        text(&answer)
    );
    assert!(world.accepted.0.lock().unwrap().is_empty());
}

#[test]
fn a_request_without_a_valid_fresh_proof_for_exactly_it_is_refused() {
    let world = World::new();
    let buyer = keys("buyer");
    let transport = world.dial(&buyer);
    let body = || work_body(STATEMENT);
    let refused = |reply: Reply, why: &str| {
        assert_eq!((reply.status, text(&reply).as_str()), (401, why));
    };

    refused(
        raw(&transport, "POST", "/work", None, &buyer, body()),
        "DPoP proof missing",
    );

    // Signed by one key, presenting another.
    let stranger = keys("stranger");
    let mine = proof(&buyer, &transport, "POST", "/work");
    let theirs = proof(&stranger, &transport, "POST", "/work");
    let part = |proof: &str, n: usize| proof.split('.').nth(n).unwrap().to_owned();
    let spliced = format!("{}.{}.{}", part(&theirs, 0), part(&mine, 1), part(&mine, 2));
    refused(
        raw(&transport, "POST", "/work", Some(spliced), &buyer, body()),
        "DPoP signature refused",
    );
    // A good proof by a key other than the one the request declares.
    refused(
        raw(&transport, "POST", "/work", Some(theirs), &buyer, body()),
        "the declared key is not the key that proved possession",
    );

    // Another method, another path, another node.
    refused(
        raw(
            &transport,
            "POST",
            "/work",
            Some(proof(&buyer, &transport, "GET", "/work")),
            &buyer,
            body(),
        ),
        "DPoP proof is for another method or URI",
    );
    refused(
        raw(
            &transport,
            "POST",
            "/work",
            Some(proof(&buyer, &transport, "POST", "/work/x")),
            &buyer,
            body(),
        ),
        "DPoP proof is for another method or URI",
    );
    let elsewhere = dpop_make(
        &buyer.possession,
        "POST",
        &format!("iroh://{}/work", "ab".repeat(32)),
        wall_clock().unwrap(),
        transport.node().as_deref(),
    )
    .unwrap();
    refused(
        raw(&transport, "POST", "/work", Some(elsewhere), &buyer, body()),
        "DPoP proof is for another method or URI",
    );

    // Too old, and from the future.
    for skew in [-1000i64, 1000] {
        let at = wall_clock().unwrap().checked_add_signed(skew).unwrap();
        let stale = dpop_make(
            &buyer.possession,
            "POST",
            &format!("{}/work", transport.base()),
            at,
            transport.node().as_deref(),
        )
        .unwrap();
        refused(
            raw(&transport, "POST", "/work", Some(stale), &buyer, body()),
            "DPoP proof is stale",
        );
    }

    // The same proof twice.
    let once = proof(&buyer, &transport, "POST", "/work");
    assert_eq!(
        raw(
            &transport,
            "POST",
            "/work",
            Some(once.clone()),
            &buyer,
            body()
        )
        .status,
        202
    );
    refused(
        raw(&transport, "POST", "/work", Some(once), &buyer, body()),
        "DPoP proof replayed",
    );
}

#[test]
fn a_proof_is_bound_to_the_node_that_iroh_authenticated() {
    let world = World::new();
    let buyer = keys("buyer");
    let transport = world.dial(&buyer);
    let not_bound = "DPoP proof is not bound to this connection's node";
    let uri = format!("{}/work", transport.base());
    let now = wall_clock().unwrap();

    // No node claim at all.
    let bare = dpop_make(&buyer.possession, "POST", &uri, now, None).unwrap();
    let reply = raw(
        &transport,
        "POST",
        "/work",
        Some(bare),
        &buyer,
        work_body(STATEMENT),
    );
    assert_eq!((reply.status, text(&reply).as_str()), (401, not_bound));

    // A claim naming some other node.
    let other_node = "cd".repeat(32);
    let wrong = dpop_make(&buyer.possession, "POST", &uri, now, Some(&other_node)).unwrap();
    let reply = raw(
        &transport,
        "POST",
        "/work",
        Some(wrong),
        &buyer,
        work_body(STATEMENT),
    );
    assert_eq!((reply.status, text(&reply).as_str()), (401, not_bound));

    // A proof the buyer made for its own node, presented from a thief's node.
    let lifted = proof(&buyer, &transport, "POST", "/work");
    let thief = keys("thief");
    let thief_transport = world.dial(&thief);
    assert_ne!(thief_transport.node(), transport.node());
    let reply = raw(
        &thief_transport,
        "POST",
        "/work",
        Some(lifted),
        &buyer,
        work_body(STATEMENT),
    );
    assert_eq!((reply.status, text(&reply).as_str()), (401, not_bound));
    assert_eq!(dpop_binding_of(&buyer.possession), buyer.binding());
}

#[test]
fn a_job_answers_only_to_the_key_that_made_it() {
    let world = World::new();
    let buyer = keys("buyer");
    let transport = world.dial(&buyer);
    let job = job_of(&request_work(&transport, &buyer, STATEMENT));
    assert_eq!(await_quote(&transport, &buyer, &job).status, 402);

    let other = keys("other");
    let other_transport = world.dial(&other);
    let reply = ask(
        &other_transport,
        &other,
        "GET",
        &job,
        BTreeMap::new(),
        vec![],
    )
    .unwrap();
    assert_eq!(
        (reply.status, text(&reply).as_str()),
        (403, "this job belongs to another key")
    );
    // And a job that does not exist is not found, for anyone.
    let reply = ask(
        &transport,
        &buyer,
        "GET",
        "/work/0xdead",
        BTreeMap::new(),
        vec![],
    )
    .unwrap();
    assert_eq!(reply.status, 404);
}

#[test]
fn oversize_and_unpinned_statements_are_refused() {
    let world = World::new();
    let buyer = keys("buyer");
    let transport = world.dial(&buyer);

    // A statement over the limit, in a frame that itself fits.
    let big = vec![b'x'; MAXIMUM_STATEMENT + 1];
    let reply = request_work(&transport, &buyer, &big);
    assert_eq!(
        (reply.status, text(&reply).as_str()),
        (413, "statement too large")
    );

    // A statement that is not the one the policy pins.
    let body = serde_json::to_vec(&serde_json::json!({
        "policy": policy_json(&policy(STATEMENT)), "statement": B64.encode(b"something else"),
    }))
    .unwrap();
    let reply = ask(
        &transport,
        &buyer,
        "POST",
        "/work",
        declaration(&buyer),
        body,
    )
    .unwrap();
    assert_eq!(
        (reply.status, text(&reply).as_str()),
        (422, "statement is not the one the policy pins")
    );

    // A frame that announces a body over the limit is refused before the body is read.
    let head = br#"{"method":"POST","path":"/work","headers":{}}"#;
    let mut frame = (head.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(head);
    frame.extend_from_slice(&(MAXIMUM_BODY as u32 + 1).to_be_bytes());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let reply = runtime
        .block_on(async {
            let endpoint = iroh_net::endpoint(buyer.node, "127.0.0.1:0".parse().unwrap())
                .await
                .map_err(|e| e.to_string())?;
            let seller = iroh_net::parse_address(&world.address).map_err(|e| e.to_string())?;
            iroh_net::exchange(&endpoint, &seller, frame)
                .await
                .map_err(|e| e.to_string())
        })
        .unwrap();
    assert_eq!(
        (reply.status, text(&reply).as_str()),
        (413, "message too large")
    );
}
