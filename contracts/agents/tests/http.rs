//! The optional HTTP adapter serves the same handler: a request is quoted
//! after the prover succeeds, and one without a proof is refused. Plain HTTP
//! authenticates no node, so the proof carries no node claim here.
use base64::Engine;
use nucleus_commerce_agents::{
    buyer::ask,
    http::{self, HttpTransport},
    job::Accepted,
    message::{Request, Transport},
    seller::{Jobs, Prover, Seller, Settler, Terms},
    support::{B64, Keys, policy_json},
};
use nucleus_proof_acceptance::Policy;
use nucleus_proof_commerce::{
    vault,
    x402::{
        TokenDomain,
        wire::{BUYER_HEADER, REQUIRED_HEADER, declaration_header},
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const STATEMENT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/task.ndjson");
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proof-acceptance/core/tests/fixtures"
);

struct Nothing;
impl Settler for Nothing {
    fn start(&self, _id: String, _accepted: Accepted, _jobs: Jobs) {}
}

#[test]
fn the_http_adapter_quotes_after_the_prover_and_refuses_a_request_without_a_proof() {
    let scratch =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("http-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let key_file = |name: &str| Keys::load_or_create(scratch.join(name).to_str().unwrap()).unwrap();
    let (seller_keys, buyer) = (key_file("seller.keys"), key_file("buyer.keys"));
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
            format!("{FIXTURES}/suffix.ndjson"),
        ],
        timeout: Duration::from_secs(30),
        work: scratch.join("jobs"),
    };
    let seller = Arc::new(Mutex::new(Seller::new(terms, prover, Box::new(Nothing))));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let transport = HttpTransport::new(&format!("http://{}", listener.local_addr().unwrap()));
    std::thread::spawn(move || http::serve(listener, seller));

    let policy = Policy {
        statement_sha256: Sha256::digest(STATEMENT).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    };
    let body = serde_json::to_vec(&serde_json::json!({
        "policy": policy_json(&policy), "statement": B64.encode(STATEMENT),
    }))
    .unwrap();
    let declaration: BTreeMap<String, String> = [(
        BUYER_HEADER.to_ascii_lowercase(),
        declaration_header(buyer.address(), buyer.binding()).unwrap(),
    )]
    .into();

    let bare = transport
        .send(&Request {
            method: "POST".into(),
            path: "/work".into(),
            headers: declaration.clone(),
            body: body.clone(),
        })
        .unwrap();
    assert_eq!(
        (bare.status, bare.body.as_slice()),
        (401, &b"DPoP proof missing"[..])
    );

    let taken = ask(&transport, &buyer, "POST", "/work", declaration, body).unwrap();
    assert_eq!(
        taken.status,
        202,
        "{}",
        String::from_utf8_lossy(&taken.body)
    );
    let job = taken.header("location").unwrap().to_owned();
    for _ in 0..200 {
        let reply = ask(&transport, &buyer, "GET", &job, BTreeMap::new(), vec![]).unwrap();
        if reply.status != 202 {
            assert_eq!(
                reply.status,
                402,
                "{}",
                String::from_utf8_lossy(&reply.body)
            );
            assert!(reply.header(REQUIRED_HEADER).is_some());
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no offer over HTTP");
}
