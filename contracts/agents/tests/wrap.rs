//! The Groth16 wrap service and the seller's check of its answers.
//!
//! The service's admission rules run against a stand-in backend, so they are
//! exercised without the prover. The seller's check runs the real prover host
//! (`NUCLEUS_ACCEPTANCE_HOST`) on a real receipt from a settled order; those
//! tests say so and stop when the host is not given.
use nucleus_commerce_agents::{
    chain::{Res, hex, unhex},
    dpop::{DPOP_TYP, proof_make},
    message::Request,
    wrap::{Answer, Backend, Policy, Service, WrapKey, accept_answer},
};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
};

const BASE: &str = "http://127.0.0.1:4460";
const SUCCINCT: &[u8] = include_bytes!("fixtures/wrap/order2.succinct.receipt");
const GROTH16: &[u8] = include_bytes!("fixtures/wrap/order2.groth16.receipt");
const SEAL: &str = include_str!("fixtures/wrap/order2.seal.hex");
/// The fixture's journal: Arbitrum Sepolia, the format-2 vault, one order.
const JOURNAL: &str = "f18a89db86c3eb4ba4761e0e656ba7d08cb463ddd5b2f73eaec94d197bbee4b60000000000000000000000000000000000000000000000000000000000066eee0000000000000000000000004a0d2359f5ba363e7a2d97207b72a91dd41ff426088812156c68b0fc7368046fdf88cdaa035f5f53fb018b1ce496e7c7f5ed0d71ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8";
const VAULT: &str = "4a0d2359f5ba363e7a2d97207b72a91dd41ff426";

/// Answers with the fixture's journal for the fixture's receipt, refuses any
/// other receipt, and can be held inside `wrap` to fill the queue.
struct Stand {
    hold: Mutex<Option<mpsc::Receiver<()>>>,
    entered: Mutex<Option<mpsc::Sender<()>>>,
}
impl Stand {
    fn plain() -> Arc<Self> {
        Arc::new(Self {
            hold: Mutex::new(None),
            entered: Mutex::new(None),
        })
    }
}
impl Backend for Stand {
    fn journal(&self, _prefix: &str, receipt: &[u8]) -> Res<Vec<u8>> {
        if receipt == SUCCINCT {
            unhex(JOURNAL)
        } else {
            Err("does not verify".into())
        }
    }
    fn wrap(&self, _prefix: &str, _receipt: &[u8]) -> Res<(Vec<u8>, String)> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        if let Some(hold) = self.hold.lock().unwrap().take() {
            let _ = hold.recv();
        }
        Ok((GROTH16.to_vec(), SEAL.trim().to_owned()))
    }
}

fn policy() -> Policy {
    let vault: [u8; 20] = unhex(VAULT).unwrap().try_into().unwrap();
    Policy {
        allowed: vec![(421614, vault)],
        maximum_receipt: 1 << 20,
        per_key_per_hour: 3,
        per_address_per_hour: 100,
        queue: 2,
    }
}
fn service(policy: Policy, backend: Arc<dyn Backend>) -> Service {
    Service::new(policy, BASE, backend)
}
fn key(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn now() -> u64 {
    1_800_000_000
}
fn peer() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
/// A request for `prefix` with `body`, proved by `key` for `method`/`url`
/// at `at`, naming `named` as the body.
fn signed(
    prefix: &str,
    body: &[u8],
    key: &p256::ecdsa::SigningKey,
    url: &str,
    at: u64,
    named: &[u8],
) -> Request {
    let proof = proof_make(key, DPOP_TYP, "POST", url, at, None, Some(named)).unwrap();
    let mut headers = BTreeMap::new();
    headers.insert("dpop".to_owned(), proof);
    Request {
        method: "POST".into(),
        path: format!("/wrap/{prefix}"),
        headers,
        body: body.to_vec(),
    }
}
fn good(seed: u8) -> Request {
    signed(
        "order2",
        SUCCINCT,
        &key(seed),
        &format!("{BASE}/wrap/order2"),
        now(),
        SUCCINCT,
    )
}

#[test]
fn a_receipt_for_an_allowed_vault_is_wrapped() {
    let reply = service(policy(), Stand::plain()).handle(peer(), &good(1), now());
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let value: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(
        value["journal"].as_str().unwrap().trim_start_matches("0x"),
        JOURNAL
    );
    assert_eq!(value["seal"], SEAL.trim());
}

#[test]
fn a_request_without_a_valid_fresh_proof_for_this_receipt_is_refused() {
    let s = service(policy(), Stand::plain());
    let url = format!("{BASE}/wrap/order2");
    let mut missing = good(1);
    missing.headers.clear();
    assert_eq!(s.handle(peer(), &missing, now()).status, 401);
    // Another URL, another method's worth of target, another time, another body.
    let cases = [
        signed(
            "order2",
            SUCCINCT,
            &key(2),
            "http://elsewhere/wrap/order2",
            now(),
            SUCCINCT,
        ),
        signed("order2", SUCCINCT, &key(3), &url, now() - 600, SUCCINCT),
        signed("order2", SUCCINCT, &key(4), &url, now() + 600, SUCCINCT),
        signed("order2", SUCCINCT, &key(5), &url, now(), b"another receipt"),
    ];
    for case in cases {
        assert_eq!(s.handle(peer(), &case, now()).status, 401);
    }
    // A forged signature: the proof's last character changed.
    let mut forged = good(6);
    let proof = forged.headers.get_mut("dpop").unwrap();
    let last = proof.pop().unwrap();
    proof.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(s.handle(peer(), &forged, now()).status, 401);
    // The same proof twice.
    let once = good(7);
    assert_eq!(s.handle(peer(), &once, now()).status, 200);
    assert_eq!(s.handle(peer(), &once, now()).status, 401);
}

#[test]
fn unknown_programs_unverifiable_receipts_and_other_vaults_are_refused() {
    let s = service(policy(), Stand::plain());
    let unknown = signed(
        "base2",
        SUCCINCT,
        &key(1),
        &format!("{BASE}/wrap/base2"),
        now(),
        SUCCINCT,
    );
    assert_eq!(s.handle(peer(), &unknown, now()).status, 422);
    let url = format!("{BASE}/wrap/order2");
    let unverifiable = signed("order2", b"junk", &key(2), &url, now(), b"junk");
    assert_eq!(s.handle(peer(), &unverifiable, now()).status, 422);
    let mut elsewhere = policy();
    elsewhere.allowed = vec![(421614, [0x11; 20])];
    let s = service(elsewhere, Stand::plain());
    assert_eq!(s.handle(peer(), &good(3), now()).status, 403);
    let mut small = policy();
    small.maximum_receipt = 1000;
    let s = service(small, Stand::plain());
    assert_eq!(s.handle(peer(), &good(4), now()).status, 413);
}

/// Verifies every receipt and reports a journal of the right length for an
/// allowed vault whose first word is not the order tag (a base program's,
/// say).
struct NotAnOrder;
impl Backend for NotAnOrder {
    fn journal(&self, _prefix: &str, _receipt: &[u8]) -> Res<Vec<u8>> {
        let mut journal = unhex(JOURNAL)?;
        journal[0] ^= 1;
        Ok(journal)
    }
    fn wrap(&self, _prefix: &str, _receipt: &[u8]) -> Res<(Vec<u8>, String)> {
        Ok((GROTH16.to_vec(), SEAL.trim().to_owned()))
    }
}

#[test]
fn a_journal_that_is_not_an_order_journal_is_refused() {
    let s = service(policy(), Arc::new(NotAnOrder));
    assert_eq!(s.handle(peer(), &good(30), now()).status, 403);
}

#[test]
fn one_key_and_one_address_are_limited_per_hour() {
    let s = service(policy(), Stand::plain());
    for _ in 0..3 {
        assert_eq!(s.handle(peer(), &good(9), now()).status, 200);
    }
    assert_eq!(s.handle(peer(), &good(9), now()).status, 429);
    // An hour later the key may ask again.
    let later = signed(
        "order2",
        SUCCINCT,
        &key(9),
        &format!("{BASE}/wrap/order2"),
        now() + 3600,
        SUCCINCT,
    );
    assert_eq!(s.handle(peer(), &later, now() + 3600).status, 200);
    let mut by_address = policy();
    by_address.per_address_per_hour = 2;
    let s = service(by_address, Stand::plain());
    assert_eq!(s.handle(peer(), &good(10), now()).status, 200);
    assert_eq!(s.handle(peer(), &good(11), now()).status, 200);
    assert_eq!(s.handle(peer(), &good(12), now()).status, 429);
}

#[test]
fn a_full_queue_is_refused_while_a_wrap_runs() {
    let (release, hold) = mpsc::channel();
    let (entered, inside) = mpsc::channel();
    let stand = Arc::new(Stand {
        hold: Mutex::new(Some(hold)),
        entered: Mutex::new(Some(entered)),
    });
    let mut one = policy();
    one.queue = 1;
    let s = Arc::new(service(one, stand));
    let running = {
        let s = s.clone();
        std::thread::spawn(move || s.handle(peer(), &good(20), now()).status)
    };
    inside.recv().unwrap();
    assert_eq!(s.handle(peer(), &good(21), now()).status, 503);
    release.send(()).unwrap();
    assert_eq!(running.join().unwrap(), 200);
    // The slot is free again.
    assert_eq!(s.handle(peer(), &good(22), now()).status, 200);
}

/// The real prover host, or `None` with a note when it is not given.
fn host() -> Option<String> {
    match std::env::var("NUCLEUS_ACCEPTANCE_HOST") {
        Ok(host) => Some(host),
        Err(_) => {
            eprintln!("NUCLEUS_ACCEPTANCE_HOST is not set: the seller-side checks did not run");
            None
        }
    }
}
fn work(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qed-wrap-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}
fn answer(receipt: &[u8], seal: &str, journal: &str) -> Answer {
    Answer {
        journal: unhex(journal).unwrap(),
        seal: seal.trim().to_owned(),
        receipt: receipt.to_vec(),
    }
}

#[test]
fn the_seller_derives_the_seal_from_a_verified_answer() {
    let Some(host) = host() else { return };
    let seal = accept_answer(
        &host,
        "order2",
        &unhex(JOURNAL).unwrap(),
        &answer(GROTH16, SEAL, JOURNAL),
        &work("good"),
    )
    .expect("a good answer is accepted");
    assert_eq!(hex(&seal).trim_start_matches("0x"), SEAL.trim());
}

#[test]
fn the_seller_refuses_a_bad_answer() {
    let Some(host) = host() else { return };
    let own = unhex(JOURNAL).unwrap();
    // A Groth16 receipt with one byte of its proof changed.
    let mut tampered = GROTH16.to_vec();
    let at = tampered.len() / 2;
    tampered[at] ^= 1;
    assert!(
        accept_answer(
            &host,
            "order2",
            &own,
            &answer(&tampered, SEAL, JOURNAL),
            &work("tampered")
        )
        .is_err()
    );
    // The succinct receipt handed back instead of a Groth16 one.
    assert!(
        accept_answer(
            &host,
            "order2",
            &own,
            &answer(SUCCINCT, SEAL, JOURNAL),
            &work("succinct")
        )
        .is_err()
    );
    // A good receipt, but a seal that is not its own.
    let mut other = SEAL.trim().to_owned();
    other.replace_range(other.len() - 2.., "00");
    assert!(
        accept_answer(
            &host,
            "order2",
            &own,
            &answer(GROTH16, &other, JOURNAL),
            &work("seal")
        )
        .is_err()
    );
    // A good answer for an order that is not the seller's.
    let mut elsewhere = own.clone();
    elsewhere[100] ^= 1;
    assert!(
        accept_answer(
            &host,
            "order2",
            &elsewhere,
            &answer(GROTH16, SEAL, JOURNAL),
            &work("journal")
        )
        .is_err()
    );
    // The right receipt checked as another program's.
    assert!(
        accept_answer(
            &host,
            "vault3",
            &own,
            &answer(GROTH16, SEAL, JOURNAL),
            &work("program")
        )
        .is_err()
    );
}

#[test]
fn a_wrap_key_never_prints() {
    let key = WrapKey::from_secret([7; 32]).unwrap();
    assert_eq!(format!("{key:?}"), "WrapKey(redacted)");
}
