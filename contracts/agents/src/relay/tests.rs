//! The relayer's rules (docs/rfcs/qed-relayer-2026-11-13.md) against a
//! scripted chain (`chain/fault.rs`) that records every transaction it is
//! sent. Each test names the rule it falsifies; the red runs are in the RFC.
use super::*;
use crate::chain::fault::{Endpoint, QUICK, Reply as Rpc, serve};
use crate::world::{fund_data, settle_data};
use std::collections::BTreeMap;

const CHAIN: u64 = 421_614;
const VAULT: Address = [0x4a; 20];
const OTHER_VAULT: Address = [0x8c; 20];
const TOKEN: Address = [0x75; 20];
const SELLER: Address = [2; 20];
const BASE_URL: &str = "http://127.0.0.1:4461";
/// 0.1 gwei, Arbitrum Sepolia's usual base fee.
const BASE_FEE: u128 = 100_000_000;

/// What the scripted chain knows and what it was sent.
struct Ledger {
    balance: u128,
    estimate: u128,
    reverts: bool,
    raw: Vec<Vec<u8>>,
    mined: HashSet<String>,
    transactions: HashMap<String, Value>,
}
impl Default for Ledger {
    fn default() -> Self {
        Self {
            balance: 10u128.pow(17),
            estimate: 150_000,
            reverts: false,
            raw: vec![],
            mined: HashSet::new(),
            transactions: HashMap::new(),
        }
    }
}
type Shared = Arc<Mutex<Ledger>>;

fn chain_with(ledger: &Shared) -> (Endpoint, Chain) {
    let ledger = ledger.clone();
    let endpoint = serve(Box::new(move |method, params, _| {
        let mut l = ledger.lock().unwrap();
        let first = params[0].as_str().unwrap_or_default().to_owned();
        match method {
            "eth_chainId" => Rpc::result(json!(format!("{CHAIN:#x}"))),
            "eth_call" if l.reverts => Rpc::error(200, 3, "execution reverted: NothingOwed"),
            "eth_call" => Rpc::result(json!("0x")),
            "eth_estimateGas" if l.reverts => Rpc::error(200, 3, "execution reverted"),
            "eth_estimateGas" => Rpc::result(json!(format!("{:#x}", l.estimate))),
            "eth_getBlockByNumber" => Rpc::result(
                json!({"baseFeePerGas": format!("{BASE_FEE:#x}"), "timestamp": "0x6a000000"}),
            ),
            "eth_maxPriorityFeePerGas" => Rpc::result(json!("0x0")),
            "eth_getBalance" => Rpc::result(json!(format!("{:#x}", l.balance))),
            // The chain's pending count never moves: only the lane's own
            // bookkeeping can give two requests different nonces.
            "eth_getTransactionCount" => Rpc::result(json!("0x7")),
            "eth_sendRawTransaction" => {
                let raw = unhex(&first).unwrap();
                let hash = hex(&keccak(&raw));
                l.raw.push(raw);
                Rpc::result(json!(hash))
            }
            "eth_getTransactionReceipt" if l.mined.contains(&first) => {
                Rpc::result(json!({"status": "0x1", "gasUsed": "0x20000"}))
            }
            "eth_getTransactionReceipt" => Rpc::result(Value::Null),
            "eth_getTransactionByHash" => {
                Rpc::result(l.transactions.get(&first).cloned().unwrap_or(Value::Null))
            }
            _ => Rpc::error(200, -32601, "method not found"),
        }
    }));
    let chain = Chain::connect_any(std::slice::from_ref(&endpoint.url), QUICK).unwrap();
    (endpoint, chain)
}

fn order() -> vault::Order {
    vault::Order {
        buyer: [1; 20],
        seller: SELLER,
        asset: TOKEN,
        amount: U256::from(100_000u64).to_be_bytes(),
        verifier: [6; 20],
        program: [7; 32],
        policy_hash: [9; 32],
        base: [0; 32],
        fund_by: 1000,
        deliver_by: 2000,
        salt: [10; 32],
        context: [11; 32],
    }
}
fn fund() -> Vec<u8> {
    fund_data(vault::Form::Third, &order(), &[7; 65])
}
fn settle() -> Vec<u8> {
    settle_data(vault::Form::Third, &order(), b"artifact", vec![1; 260])
}
fn claim() -> Vec<u8> {
    third::claimCall {
        payee: A::from(SELLER),
        asset: A::from(TOKEN),
    }
    .abi_encode()
}

fn relayer_key() -> SigningKey {
    SigningKey::from_slice(&[9; 32]).unwrap()
}
fn relay_with(ledger: &Shared, limits: Limits, budget: u128) -> (Endpoint, Relay) {
    let (endpoint, chain) = chain_with(ledger);
    let lane = Lane::new(
        chain,
        LaneConfig {
            vaults: vec![VAULT],
            maximum_fee_per_gas: 10 * BASE_FEE,
            budget,
            floor: 10u128.pow(15),
        },
    );
    let relay = Relay::new(BASE_URL, relayer_key(), limits, vec![lane]).unwrap();
    (endpoint, relay)
}
fn relay(ledger: &Shared) -> (Endpoint, Relay) {
    relay_with(ledger, Limits::default(), 10u128.pow(17))
}
fn now() -> u64 {
    1_800_000_000
}
fn peer() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn possession(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
}
/// `POST /relay` for (`to`, `value`, `data`), proved by key `seed`.
fn post(seed: u8, to: Address, value: &str, data: &[u8]) -> Request {
    let body = json!({"chainId": CHAIN, "to": hex(&to), "value": value, "data": hex(data)})
        .to_string()
        .into_bytes();
    let proof = proof_make(
        &possession(seed),
        DPOP_TYP,
        "POST",
        &format!("{BASE_URL}/relay"),
        now(),
        None,
        Some(&body),
    )
    .unwrap();
    Request {
        method: "POST".into(),
        path: "/relay".into(),
        headers: BTreeMap::from([("dpop".to_owned(), proof)]),
        body,
    }
}
fn get(seed: u8, hash: &str) -> Request {
    let path = format!("/relay/{hash}");
    let proof = proof_make(
        &possession(seed),
        DPOP_TYP,
        "GET",
        &format!("{BASE_URL}{path}"),
        now(),
        None,
        None,
    )
    .unwrap();
    Request {
        method: "GET".into(),
        path,
        headers: BTreeMap::from([("dpop".to_owned(), proof)]),
        body: vec![],
    }
}
fn body(reply: &crate::message::Reply) -> Value {
    serde_json::from_slice(&reply.body)
        .unwrap_or_else(|_| json!(String::from_utf8_lossy(&reply.body)))
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// S-1 to S-4: each of the three calls is relayed as a type-2 transaction
/// to the vault, carrying exactly the calldata asked for.
#[test]
fn a_good_fund_settle_and_claim_are_relayed() {
    let ledger = Shared::default();
    let (endpoint, relay) = relay(&ledger);
    for (seed, data) in [(1, fund()), (2, settle()), (3, claim())] {
        let reply = relay.handle(peer(), &post(seed, VAULT, "0", &data), now());
        assert_eq!(reply.status, 202, "{}", body(&reply));
        let answer = body(&reply);
        let raw = ledger.lock().unwrap().raw.last().unwrap().clone();
        assert_eq!(answer["transaction"], hex(&keccak(&raw)));
        assert_eq!(answer["relayer"], hex(&relay.address()));
        assert_eq!(raw[0], 2, "an EIP-1559 transaction");
        assert!(contains(&raw, &VAULT) && contains(&raw, &data));
    }
    assert_eq!(endpoint.count("eth_sendRawTransaction"), 3);
    // Each send was simulated and estimated first (A-3).
    assert_eq!(endpoint.count("eth_call"), 3);
    assert_eq!(endpoint.count("eth_estimateGas"), 3);
}

/// S-1, S-2, S-3: refused before anything is simulated or sent.
#[test]
fn calls_outside_the_three_or_off_the_allow_list_are_refused() {
    let ledger = Shared::default();
    let (endpoint, relay) = relay(&ledger);
    let transfer = crate::ops::token_transfer_call(SELLER, U256::from(1u64));
    let refund = crate::world::refund_data(vault::Form::Third, &order());
    let mut padded = fund();
    padded.extend_from_slice(&[0; 32]);
    let cases: [(&str, Request, u16); 6] = [
        (
            "vault not on the allow-list",
            post(1, OTHER_VAULT, "0", &fund()),
            403,
        ),
        ("another contract", post(2, TOKEN, "0", &transfer), 403),
        ("non-zero value", post(3, VAULT, "1", &fund()), 403),
        ("unknown function", post(4, VAULT, "0", &refund), 422),
        ("not the vault's call", post(5, VAULT, "0", &transfer), 422),
        ("not canonical", post(6, VAULT, "0", &padded), 422),
    ];
    for (name, request, status) in cases {
        let reply = relay.handle(peer(), &request, now());
        assert_eq!(reply.status, status, "{name}: {}", body(&reply));
    }
    assert_eq!(endpoint.count("eth_call"), 0);
    assert!(ledger.lock().unwrap().raw.is_empty());
}

/// A-3: a call whose simulation reverts is refused and nothing is sent.
#[test]
fn a_call_whose_simulation_reverts_is_refused() {
    let ledger = Shared::default();
    ledger.lock().unwrap().reverts = true;
    let (_endpoint, relay) = relay(&ledger);
    let reply = relay.handle(peer(), &post(1, VAULT, "0", &claim()), now());
    assert_eq!(reply.status, 422, "{}", body(&reply));
    assert!(body(&reply).to_string().contains("NothingOwed"));
    assert!(ledger.lock().unwrap().raw.is_empty());
}

/// A-4: over the per-call gas cap.
#[test]
fn a_call_over_the_gas_cap_is_refused() {
    let ledger = Shared::default();
    ledger.lock().unwrap().estimate = 600_000;
    let (_endpoint, relay) = relay(&ledger);
    let reply = relay.handle(peer(), &post(1, VAULT, "0", &settle()), now());
    assert_eq!(reply.status, 422, "{}", body(&reply));
    assert!(ledger.lock().unwrap().raw.is_empty());
}

/// A-5: the budget, and the balance floor, are never crossed.
#[test]
fn a_call_over_budget_or_below_the_floor_is_refused() {
    let ledger = Shared::default();
    // 150,000 × 1.2 gas at up to 2 × 0.1 gwei is 36,000 gwei; allow one.
    let (_endpoint, relay) = relay_with(&ledger, Limits::default(), 50_000 * 10u128.pow(9));
    let first = relay.handle(peer(), &post(1, VAULT, "0", &fund()), now());
    assert_eq!(first.status, 202, "{}", body(&first));
    let second = relay.handle(peer(), &post(2, VAULT, "0", &settle()), now());
    assert_eq!(second.status, 503, "{}", body(&second));
    assert!(body(&second).to_string().contains("budget"));

    let poor = Shared::default();
    poor.lock().unwrap().balance = 10u128.pow(15);
    let (_endpoint, poor_relay) = relay_with(&poor, Limits::default(), 10u128.pow(17));
    let reply = poor_relay.handle(peer(), &post(1, VAULT, "0", &fund()), now());
    assert_eq!(reply.status, 503, "{}", body(&reply));
    assert!(body(&reply).to_string().contains("floor"));
    assert!(poor.lock().unwrap().raw.is_empty());
}

/// A-2: per key, and per named seller per day.
#[test]
fn a_rate_limited_caller_is_refused() {
    let ledger = Shared::default();
    let limits = Limits {
        per_key_per_hour: 1,
        per_seller_per_day: 2,
        ..Limits::default()
    };
    let (_endpoint, relay) = relay_with(&ledger, limits, 10u128.pow(17));
    assert_eq!(
        relay
            .handle(peer(), &post(1, VAULT, "0", &fund()), now())
            .status,
        202
    );
    let again = relay.handle(peer(), &post(1, VAULT, "0", &settle()), now());
    assert_eq!(again.status, 429, "{}", body(&again));
    // A fresh key does not escape the cap on the seller the calls serve.
    assert_eq!(
        relay
            .handle(peer(), &post(2, VAULT, "0", &settle()), now())
            .status,
        202
    );
    let third = relay.handle(peer(), &post(3, VAULT, "0", &claim()), now());
    assert_eq!(third.status, 429, "{}", body(&third));
    assert!(body(&third).to_string().contains("seller"));
    assert_eq!(ledger.lock().unwrap().raw.len(), 2);
}

/// A-1: no proof, a replayed proof, a proof for another body.
#[test]
fn a_missing_or_replayed_proof_is_refused() {
    let ledger = Shared::default();
    let (_endpoint, relay) = relay(&ledger);
    let mut missing = post(1, VAULT, "0", &fund());
    missing.headers.clear();
    assert_eq!(relay.handle(peer(), &missing, now()).status, 401);

    let once = post(2, VAULT, "0", &fund());
    assert_eq!(relay.handle(peer(), &once, now()).status, 202);
    let replayed = relay.handle(peer(), &once, now());
    assert_eq!(replayed.status, 401);
    assert!(body(&replayed).to_string().contains("replayed"));

    let mut rebodied = post(3, VAULT, "0", &fund());
    rebodied.body = post(3, VAULT, "0", &settle()).body;
    assert_eq!(relay.handle(peer(), &rebodied, now()).status, 401);
    let mut status = get(4, "0x00");
    status.headers.clear();
    assert_eq!(relay.handle(peer(), &status, now()).status, 401);
    assert_eq!(ledger.lock().unwrap().raw.len(), 1);
}

/// A-7: two requests at once get two consecutive nonces, though the chain's
/// pending count says 7 both times.
#[test]
fn concurrent_requests_get_distinct_nonces() {
    let ledger = Shared::default();
    let (_endpoint, relay) = relay(&ledger);
    let relay = Arc::new(relay);
    let threads: Vec<_> = [(1, fund()), (2, settle())]
        .into_iter()
        .map(|(seed, data)| {
            let relay = relay.clone();
            std::thread::spawn(move || relay.handle(peer(), &post(seed, VAULT, "0", &data), now()))
        })
        .collect();
    let mut nonces: Vec<u64> = threads
        .into_iter()
        .map(|thread| {
            let reply = thread.join().unwrap();
            assert_eq!(reply.status, 202, "{}", body(&reply));
            body(&reply)["nonce"].as_u64().unwrap()
        })
        .collect();
    nonces.sort_unstable();
    assert_eq!(nonces, vec![7, 8]);
}

/// A-8: a stuck transaction is replaced with the same nonce and call at a
/// higher fee, at most `maximum_replacements` times, and every hash is listed.
#[test]
fn a_stuck_transaction_is_replaced_a_bounded_number_of_times() {
    let ledger = Shared::default();
    let limits = Limits {
        replace_after: Duration::ZERO,
        maximum_replacements: 2,
        ..Limits::default()
    };
    let (_endpoint, relay) = relay_with(&ledger, limits, 10u128.pow(17));
    let reply = relay.handle(peer(), &post(1, VAULT, "0", &fund()), now());
    let first = body(&reply)["transaction"].as_str().unwrap().to_owned();
    for _ in 0..4 {
        relay.tend();
    }
    let raw = ledger.lock().unwrap().raw.clone();
    assert_eq!(raw.len(), 3, "the first and two replacements");
    for replacement in &raw[1..] {
        assert!(contains(replacement, &fund()));
    }
    let listed = body(&relay.handle(peer(), &get(2, &first), now()));
    let hashes: Vec<String> = raw.iter().map(|r| hex(&keccak(r))).collect();
    assert_eq!(listed["transactions"], json!(hashes));
    // Once one is mined the lane forgets it and replaces nothing more.
    ledger.lock().unwrap().mined.insert(hashes[2].clone());
    relay.tend();
    assert_eq!(ledger.lock().unwrap().raw.len(), 3);
}

/// A-6: the max fee is capped, and a price above the cap is refused.
#[test]
fn fees_stay_under_the_cap() {
    assert_eq!(max_fee(100, 5, 1_000), Ok((5, 205)));
    assert_eq!(max_fee(100, 5, 150), Ok((5, 150)));
    assert_eq!(max_fee(100, 5, 104).unwrap_err().0, 503);
}

// ------------------------------------------------------------ seller side

/// A relayer that answers with a fixed hash and lists only it.
struct Says(String);
impl RelayApi for Says {
    fn submit(&self, _chain_id: u64, _to: Address, _data: &[u8]) -> Res<String> {
        Ok(self.0.clone())
    }
    fn hashes(&self, _first: &str) -> Res<Vec<String>> {
        Ok(vec![self.0.clone()])
    }
}
fn submission<'a>(chain: &'a Chain, relayer: &'a dyn RelayApi, data: &'a [u8]) -> Submission<'a> {
    Submission {
        chain,
        relayer: Some(relayer),
        vault: VAULT,
        data,
        wait: Duration::from_millis(300),
        until: None,
        poll: Duration::from_millis(20),
        label: "fund",
    }
}
fn own_receipt() -> crate::chain::Receipt {
    crate::chain::Receipt {
        success: true,
        contract: None,
        gas_used: 131_311,
        transaction: "0xown".into(),
    }
}
fn on_chain(to: Address, input: &[u8]) -> Value {
    json!({"to": hex(&to), "value": "0x0", "input": hex(input)})
}

/// R-3: the relayed transaction is believed only once the chain shows it
/// is the call asked for, mined and successful.
#[test]
fn a_relayed_call_that_landed_as_asked_is_accepted() {
    let ledger = Shared::default();
    let hash = hex(&[0xaa; 32]);
    {
        let mut l = ledger.lock().unwrap();
        l.transactions
            .insert(hash.clone(), on_chain(VAULT, &fund()));
        l.mined.insert(hash.clone());
    }
    let (_endpoint, chain) = chain_with(&ledger);
    let sends = Mutex::new(0);
    let data = fund();
    let delivered = submission(&chain, &Says(hash.clone()), &data)
        .run(&|| Ok(false), &|| {
            *sends.lock().unwrap() += 1;
            Ok(own_receipt())
        })
        .unwrap();
    assert_eq!(
        delivered,
        Delivered::Relayed {
            transaction: hash,
            gas: 0x20000
        }
    );
    assert_eq!(*sends.lock().unwrap(), 0);
}

/// R-2, R-4: a relayed transaction that never lands is sent by the seller.
#[test]
fn a_relayed_call_that_never_lands_is_sent_with_own_gas() {
    let ledger = Shared::default();
    let (_endpoint, chain) = chain_with(&ledger);
    let sends = Mutex::new(0);
    let data = fund();
    let delivered = submission(&chain, &Says(hex(&[0xbb; 32])), &data)
        .run(&|| Ok(false), &|| {
            *sends.lock().unwrap() += 1;
            Ok(own_receipt())
        })
        .unwrap();
    assert_eq!(
        delivered,
        Delivered::OwnGas {
            transaction: "0xown".into(),
            gas: 131_311
        }
    );
    assert_eq!(*sends.lock().unwrap(), 1);
    // If the effect is already on chain, nothing is sent.
    let delivered = submission(&chain, &Says(hex(&[0xbb; 32])), &data)
        .run(&|| Ok(true), &|| panic!("must not send"))
        .unwrap();
    assert_eq!(delivered, Delivered::AlreadyDone);
}

/// R-3: a hash for a transaction with other calldata is refused even though
/// it was mined and succeeded; the seller falls back.
#[test]
fn a_hash_for_other_calldata_is_refused() {
    let ledger = Shared::default();
    let hash = hex(&[0xcc; 32]);
    {
        let mut l = ledger.lock().unwrap();
        // The same vault, a different order: another seller's fund.
        let mut other = order();
        other.salt = [12; 32];
        l.transactions.insert(
            hash.clone(),
            on_chain(VAULT, &fund_data(vault::Form::Third, &other, &[7; 65])),
        );
        l.mined.insert(hash.clone());
    }
    let (_endpoint, chain) = chain_with(&ledger);
    let data = fund();
    assert_eq!(judge(&chain, &hash, VAULT, &data).unwrap(), Seen::OtherCall);
    let delivered = submission(&chain, &Says(hash), &data)
        .run(&|| Ok(false), &|| Ok(own_receipt()))
        .unwrap();
    assert!(
        matches!(delivered, Delivered::OwnGas { .. }),
        "{delivered:?}"
    );
}
