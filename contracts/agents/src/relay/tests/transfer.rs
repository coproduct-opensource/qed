//! T-1 to T-9 (RFC qed-relayer §15) against a scripted chain that knows one
//! claim, the token's outgoing transfers and which nonces are used. Each test
//! names the rule it falsifies; the red runs are in the RFC.
use super::*;
use crate::relay::transfer::{
    self, Authorization, TransferConfig, authorizationStateCall, bound, claimed_topic,
    domain_separator, transfer_topic,
};

/// Base mainnet USDC, for the vectors read from the chain.
const USDC: Address = [
    0x83, 0x35, 0x89, 0xfc, 0xd6, 0xed, 0xb6, 0xe0, 0x8f, 0x4c, 0x7c, 0x32, 0xd4, 0xf7, 0x1b, 0x54,
    0xbd, 0xa0, 0x29, 0x13,
];
/// The latest block's timestamp the scripted chain reports (0x6a000000).
const CHAIN_NOW: u64 = 0x6a00_0000;
const CLAIM: &str = "0x00000000000000000000000000000000000000000000000000000000000c1a10";
const OTHER_CLAIM: &str = "0x00000000000000000000000000000000000000000000000000000000000c1a11";
const PAID: u128 = 997_500;
const PAYEE: Address = [0x83; 20];

fn wallet() -> SigningKey {
    SigningKey::from_slice(&[5; 32]).unwrap()
}
fn seller() -> Address {
    address_of(&wallet())
}
fn domain() -> [u8; 32] {
    domain_separator("USD Coin", "2", CHAIN, TOKEN)
}
fn word(address: Address) -> String {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&address);
    hex(&w)
}
fn amount(value: u128) -> String {
    hex(&U256::from(value).to_be_bytes::<32>())
}

/// What the scripted chain knows about the token and the vault.
struct Book {
    /// Claim receipts by hash.
    receipts: HashMap<String, Value>,
    /// The token's `Transfer` logs out of the seller.
    out: Vec<Value>,
    used: HashSet<[u8; 32]>,
    raw: Vec<Vec<u8>>,
    mined: HashSet<String>,
}
fn claim_receipt(emitter: Address, payee: Address, asset: Address, value: u128) -> Value {
    json!({"status": "0x1", "blockNumber": "0x3000", "gasUsed": "0x1", "logs": [{
        "address": hex(&emitter),
        "topics": [hex(&claimed_topic()), word(payee), word(asset)],
        "data": amount(value)}]})
}
impl Default for Book {
    fn default() -> Self {
        let mut receipts = HashMap::new();
        receipts.insert(
            CLAIM.to_owned(),
            claim_receipt(VAULT, seller(), TOKEN, PAID),
        );
        Self {
            receipts,
            out: vec![],
            used: HashSet::new(),
            raw: vec![],
            mined: HashSet::new(),
        }
    }
}
type Books = Arc<Mutex<Book>>;

fn token_chain(book: &Books) -> (Endpoint, Chain) {
    let book = book.clone();
    let endpoint = serve(Box::new(move |method, params, _| {
        let mut b = book.lock().unwrap();
        let first = params[0].as_str().unwrap_or_default().to_owned();
        match method {
            "eth_chainId" => Rpc::result(json!(format!("{CHAIN:#x}"))),
            "eth_call" => {
                let data = unhex(params[0]["data"].as_str().unwrap()).unwrap();
                if data[..4] == authorizationStateCall::SELECTOR {
                    let call = authorizationStateCall::abi_decode(&data).unwrap();
                    let used = b.used.contains(&call.nonce.0);
                    Rpc::result(json!(amount(u128::from(used))))
                } else {
                    Rpc::result(json!(amount(1)))
                }
            }
            "eth_estimateGas" => Rpc::result(json!("0x13880")),
            "eth_blockNumber" => Rpc::result(json!("0x4000")),
            "eth_getBlockByNumber" => Rpc::result(
                json!({"baseFeePerGas": format!("{BASE_FEE:#x}"), "timestamp": format!("{CHAIN_NOW:#x}")}),
            ),
            "eth_getLogs" => Rpc::result(json!(b.out.clone())),
            "eth_maxPriorityFeePerGas" => Rpc::result(json!("0x0")),
            "eth_getBalance" => Rpc::result(json!(format!("{:#x}", 10u128.pow(17)))),
            "eth_getTransactionCount" => Rpc::result(json!("0x0")),
            "eth_sendRawTransaction" => {
                let raw = unhex(&first).unwrap();
                let hash = hex(&keccak(&raw));
                b.raw.push(raw);
                Rpc::result(json!(hash))
            }
            "eth_getTransactionReceipt" => match b.receipts.get(&first) {
                Some(receipt) => Rpc::result(receipt.clone()),
                None if b.mined.contains(&first) => {
                    Rpc::result(json!({"status": "0x1", "gasUsed": "0x10000"}))
                }
                None => Rpc::result(Value::Null),
            },
            _ => Rpc::error(200, -32601, "method not found"),
        }
    }));
    let chain = Chain::connect_any(std::slice::from_ref(&endpoint.url), QUICK).unwrap();
    (endpoint, chain)
}

fn config() -> TransferConfig {
    TransferConfig {
        token: TOKEN,
        domain: domain(),
        per_address_per_day: 5,
        per_day: 100,
    }
}
fn transfer_relay(book: &Books, transfer: Option<TransferConfig>) -> (Endpoint, Relay) {
    let (endpoint, chain) = token_chain(book);
    let lane = Lane::new(
        chain,
        LaneConfig {
            vaults: vec![VAULT],
            maximum_fee_per_gas: 10 * BASE_FEE,
            budget: 10u128.pow(17),
            floor: 10u128.pow(15),
            transfer,
        },
    );
    let relay = Relay::new(BASE_URL, relayer_key(), Limits::default(), vec![lane]).unwrap();
    (endpoint, relay)
}

fn authorization(value: u128, nonce: u8) -> Authorization {
    Authorization {
        from: seller(),
        to: PAYEE,
        value,
        valid_after: 0,
        valid_before: CHAIN_NOW + 900,
        nonce: [nonce; 32],
    }
}
fn signed(a: &Authorization) -> Vec<u8> {
    a.sign(&wallet(), &domain()).calldata()
}
/// `POST /relay` for a transfer to `to` naming `claims`, proved by key `seed`.
fn post_transfer(seed: u8, to: Address, data: &[u8], claims: &[&str]) -> Request {
    post_valued(seed, to, "0", data, claims)
}
fn post_valued(seed: u8, to: Address, value: &str, data: &[u8], claims: &[&str]) -> Request {
    let body = json!({"chainId": CHAIN, "to": hex(&to), "value": value, "data": hex(data),
                      "claims": claims})
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

/// The token's interface as read from Base mainnet on 2026-11-14 (§15): the
/// domain separator, the type hash and the selector are vectors, not
/// restatements of the code.
#[test]
fn the_domain_and_selector_are_base_usdcs() {
    assert_eq!(
        hex(&domain_separator("USD Coin", "2", 8453, USDC)),
        "0x02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f"
    );
    assert_eq!(
        hex(&keccak(x402::TRANSFER_TYPE.as_bytes())),
        "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267"
    );
    assert_eq!(
        transfer::transferWithAuthorizationCall::SELECTOR,
        [0xe3, 0xee, 0x16, 0x0e]
    );
    assert_eq!(authorizationStateCall::SELECTOR, [0xe9, 0x4a, 0x01, 0x02]);
    // The signed call round-trips and recovers to its signer.
    let a = authorization(PAID, 1);
    let parsed = transfer::parse(&signed(&a)).unwrap();
    assert_eq!(parsed.authorization, a);
    assert_eq!(parsed.signer(&domain()), Some(seller()));
}

/// The positive witness: a transfer within the bound is relayed to the
/// token, value 0, with exactly the calldata signed, then held in flight.
#[test]
fn a_paid_sellers_transfer_within_the_bound_is_relayed() {
    let book = Books::default();
    let (endpoint, relay) = transfer_relay(&book, Some(config()));
    let data = signed(&authorization(PAID, 1));
    let reply = relay.handle(peer(), &post_transfer(1, TOKEN, &data, &[CLAIM]), now());
    assert_eq!(reply.status, 202, "{}", body(&reply));
    let raw = book.lock().unwrap().raw.last().unwrap().clone();
    assert_eq!(raw[0], 2);
    assert!(contains(&raw, &TOKEN) && contains(&raw, &data));
    assert_eq!(body(&reply)["transaction"], hex(&keccak(&raw)));
    assert_eq!(endpoint.count("eth_sendRawTransaction"), 1);
}

/// T-1, T-2: the wrong token, the wrong function, trailing calldata, a
/// non-zero value; refused before anything is simulated or sent.
#[test]
fn the_wrong_token_function_or_encoding_is_refused() {
    let book = Books::default();
    let (endpoint, relay) = transfer_relay(&book, Some(config()));
    let data = signed(&authorization(PAID, 1));
    let mut trailing = data.clone();
    trailing.extend_from_slice(&[0; 32]);
    let plain = crate::ops::token_transfer_call(PAYEE, U256::from(PAID));
    // The v2.2 overload with `bytes signature`: same fields, other selector.
    let mut overload = data.clone();
    overload[..4].copy_from_slice(&[0xcf, 0x09, 0x29, 0x95]);
    let cases: [(&str, Request, u16); 6] = [
        (
            "wrong token",
            post_transfer(1, OTHER_VAULT, &data, &[CLAIM]),
            403,
        ),
        (
            "wrong function: transfer",
            post_transfer(2, TOKEN, &plain, &[CLAIM]),
            422,
        ),
        (
            "wrong function: the bytes overload",
            post_transfer(3, TOKEN, &overload, &[CLAIM]),
            422,
        ),
        (
            "extra trailing calldata",
            post_transfer(4, TOKEN, &trailing, &[CLAIM]),
            422,
        ),
        (
            "a vault call to the token",
            post_transfer(5, TOKEN, &claim(), &[CLAIM]),
            422,
        ),
        (
            "non-zero value",
            post_valued(9, TOKEN, "1", &data, &[CLAIM]),
            403,
        ),
    ];
    for (name, request, status) in cases {
        let reply = relay.handle(peer(), &request, now());
        assert_eq!(reply.status, status, "{name}: {}", body(&reply));
    }
    // A lane with no `transfer` entry relays none (T-1).
    let (_e, plain_relay) = transfer_relay(&book, None);
    let reply = plain_relay.handle(peer(), &post_transfer(6, TOKEN, &data, &[CLAIM]), now());
    assert_eq!(reply.status, 403, "{}", body(&reply));
    assert_eq!(endpoint.count("eth_call"), 0);
    assert!(book.lock().unwrap().raw.is_empty());
}

/// T-3: `to` changed after signing no longer recovers to `from`; a
/// signature by another key, or a high-s one, is refused too.
#[test]
fn a_tampered_to_or_a_foreign_signature_is_refused() {
    let book = Books::default();
    let (_endpoint, relay) = transfer_relay(&book, Some(config()));
    let a = authorization(PAID, 1);
    let good = a.sign(&wallet(), &domain());
    let mut tampered = good.clone();
    tampered.authorization.to = [0x66; 20];
    let foreign = a.sign(&SigningKey::from_slice(&[6; 32]).unwrap(), &domain());
    let mut high_s = good.clone();
    high_s.s = [0xff; 32];
    let mut to_self = authorization(PAID, 2);
    to_self.to = seller();
    for (name, data) in [
        ("tampered to", tampered.calldata()),
        ("another key", foreign.calldata()),
        ("high s", high_s.calldata()),
        ("to is from", signed(&to_self)),
        ("zero value", signed(&authorization(0, 3))),
    ] {
        let reply = relay.handle(peer(), &post_transfer(1, TOKEN, &data, &[CLAIM]), now());
        assert_eq!(reply.status, 422, "{name}: {}", body(&reply));
    }
    assert!(book.lock().unwrap().raw.is_empty());
}

/// T-4: expired, expiring within the margin, or not yet valid.
#[test]
fn an_expired_or_not_yet_valid_authorization_is_refused() {
    let book = Books::default();
    let (_endpoint, relay) = transfer_relay(&book, Some(config()));
    let mut expired = authorization(PAID, 1);
    expired.valid_before = CHAIN_NOW - 1;
    let mut expiring = authorization(PAID, 2);
    expiring.valid_before = CHAIN_NOW + transfer::LANDING_MARGIN - 1;
    let mut early = authorization(PAID, 3);
    early.valid_after = CHAIN_NOW;
    for (seed, (name, a)) in [
        ("expired", expired),
        ("expiring", expiring),
        ("early", early),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = relay.handle(
            peer(),
            &post_transfer(seed as u8 + 1, TOKEN, &signed(&a), &[CLAIM]),
            now(),
        );
        assert_eq!(reply.status, 422, "{name}: {}", body(&reply));
        assert!(
            body(&reply).to_string().contains("valid")
                || body(&reply).to_string().contains("expires"),
            "{name}"
        );
    }
    assert!(book.lock().unwrap().raw.is_empty());
}

/// T-5: a nonce the token has already used.
#[test]
fn a_replayed_nonce_is_refused() {
    let book = Books::default();
    book.lock().unwrap().used.insert([1; 32]);
    let (_endpoint, relay) = transfer_relay(&book, Some(config()));
    let reply = relay.handle(
        peer(),
        &post_transfer(1, TOKEN, &signed(&authorization(PAID, 1)), &[CLAIM]),
        now(),
    );
    assert_eq!(reply.status, 422, "{}", body(&reply));
    assert!(body(&reply).to_string().contains("nonce"));
    assert!(book.lock().unwrap().raw.is_empty());
}

/// T-6: `from` never paid (no claim named, a claim to someone else, a claim
/// from a vault off the allow-list, in another token, or not on chain).
#[test]
fn a_from_never_paid_is_refused() {
    let book = Books::default();
    {
        let mut b = book.lock().unwrap();
        b.receipts.insert(
            OTHER_CLAIM.to_owned(),
            claim_receipt(VAULT, PAYEE, TOKEN, PAID),
        );
        b.receipts.insert(
            "0x00000000000000000000000000000000000000000000000000000000000c1a12".into(),
            claim_receipt(OTHER_VAULT, seller(), TOKEN, PAID),
        );
        b.receipts.insert(
            "0x00000000000000000000000000000000000000000000000000000000000c1a13".into(),
            claim_receipt(VAULT, seller(), [0x99; 20], PAID),
        );
    }
    let (_endpoint, relay) = transfer_relay(&book, Some(config()));
    let data = signed(&authorization(1, 1));
    let cases: [(&str, &[&str], u16); 5] = [
        ("no claim named", &[], 400),
        ("a claim paying someone else", &[OTHER_CLAIM], 403),
        (
            "a vault off the allow-list",
            &["0x00000000000000000000000000000000000000000000000000000000000c1a12"],
            403,
        ),
        (
            "another token",
            &["0x00000000000000000000000000000000000000000000000000000000000c1a13"],
            403,
        ),
        (
            "not on chain",
            &["0x00000000000000000000000000000000000000000000000000000000000c1aff"],
            403,
        ),
    ];
    for (seed, (name, claims, status)) in cases.into_iter().enumerate() {
        let reply = relay.handle(
            peer(),
            &post_transfer(seed as u8 + 1, TOKEN, &data, claims),
            now(),
        );
        assert_eq!(reply.status, status, "{name}: {}", body(&reply));
    }
    assert!(book.lock().unwrap().raw.is_empty());
}

/// T-6: above C − O, where O counts what already left `from`.
#[test]
fn a_value_above_the_bound_is_refused() {
    let book = Books::default();
    let (_endpoint, relay) = transfer_relay(&book, Some(config()));
    let reply = relay.handle(
        peer(),
        &post_transfer(1, TOKEN, &signed(&authorization(PAID + 1, 1)), &[CLAIM]),
        now(),
    );
    assert_eq!(reply.status, 422, "{}", body(&reply));
    assert!(body(&reply).to_string().contains("above the bound"));
    // 400,000 already moved out: 597,500 is the most, and 597,501 is refused.
    book.lock().unwrap().out.push(json!({
        "address": hex(&TOKEN),
        "topics": [hex(&transfer_topic()), word(seller()), word(PAYEE)],
        "data": amount(400_000)}));
    let over = relay.handle(
        peer(),
        &post_transfer(2, TOKEN, &signed(&authorization(597_501, 2)), &[CLAIM]),
        now(),
    );
    assert_eq!(over.status, 422, "{}", body(&over));
    let within = relay.handle(
        peer(),
        &post_transfer(3, TOKEN, &signed(&authorization(597_500, 3)), &[CLAIM]),
        now(),
    );
    assert_eq!(within.status, 202, "{}", body(&within));
    assert_eq!(book.lock().unwrap().raw.len(), 1);
}

/// T-7, T-8: one transfer in flight per `from`; the per-address daily count.
#[test]
fn one_transfer_in_flight_per_address_and_a_daily_count() {
    let book = Books::default();
    let (_endpoint, relay) = transfer_relay(
        &book,
        Some(TransferConfig {
            per_address_per_day: 3,
            ..config()
        }),
    );
    let first = relay.handle(
        peer(),
        &post_transfer(1, TOKEN, &signed(&authorization(1, 1)), &[CLAIM]),
        now(),
    );
    assert_eq!(first.status, 202, "{}", body(&first));
    let second = relay.handle(
        peer(),
        &post_transfer(2, TOKEN, &signed(&authorization(1, 2)), &[CLAIM]),
        now(),
    );
    assert_eq!(second.status, 409, "{}", body(&second));
    // Mined: the next one may go, and then the daily count is spent.
    let hash = body(&first)["transaction"].as_str().unwrap().to_owned();
    book.lock().unwrap().mined.insert(hash);
    relay.tend();
    let third = relay.handle(
        peer(),
        &post_transfer(3, TOKEN, &signed(&authorization(1, 3)), &[CLAIM]),
        now(),
    );
    assert_eq!(third.status, 202, "{}", body(&third));
    let hash = body(&third)["transaction"].as_str().unwrap().to_owned();
    book.lock().unwrap().mined.insert(hash);
    relay.tend();
    let fourth = relay.handle(
        peer(),
        &post_transfer(4, TOKEN, &signed(&authorization(1, 4)), &[CLAIM]),
        now(),
    );
    assert_eq!(fourth.status, 429, "{}", body(&fourth));
    assert_eq!(book.lock().unwrap().raw.len(), 2);
}

/// T-6's soundness argument (§15) on random histories: an adversary that
/// names whatever claims it likes and always asks for the full bound is
/// never subsidised for more than the vaults paid it.
#[test]
fn relayed_transfers_never_exceed_what_was_claimed() {
    let mut seed: u64 = 0x5eed;
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for _ in 0..2000 {
        // (block, amount) of each claim, and of each relayed transfer.
        let mut claims: Vec<(u64, u128)> = vec![];
        let mut relayed: Vec<(u64, u128)> = vec![];
        for block in 0..40u64 {
            match next(3) {
                0 => claims.push((block, u128::from(next(100) + 1) * 10)),
                1 if !claims.is_empty() => {
                    // Name any non-empty subset of the claims so far.
                    let named: Vec<(u64, u128)> =
                        claims.iter().copied().filter(|_| next(2) == 0).collect();
                    let Some(since) = named.iter().map(|(b, _)| *b).min() else {
                        continue;
                    };
                    let c: u128 = named.iter().map(|(_, a)| a).sum();
                    let o: u128 = relayed
                        .iter()
                        .filter(|(b, _)| *b >= since)
                        .map(|(_, a)| a)
                        .sum();
                    let value = bound(c, o);
                    if value > 0 {
                        relayed.push((block, value));
                    }
                }
                _ => {}
            }
        }
        let paid: u128 = claims.iter().map(|(_, a)| a).sum();
        let total: u128 = relayed.iter().map(|(_, a)| a).sum();
        assert!(
            total <= paid,
            "relayed {total} > paid {paid}: {claims:?} {relayed:?}"
        );
    }
}
