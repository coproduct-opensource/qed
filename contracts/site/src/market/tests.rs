#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use alloy_primitives::{Address, B256, U256};
use std::collections::BTreeMap;

fn w(n: u8) -> Word {
    [n; 32]
}
fn post(id: u8, kb: u8, policy: u8, statement: u8, fund_by: u64) -> ModelPost {
    ModelPost {
        id: w(id),
        key_binding: w(kb),
        policy: w(policy),
        statement: w(statement),
        fund_by,
        poster: "p".into(),
        block: 0,
    }
}
fn funded(d: u8, p: &ModelPost, policy: u8, payee: u8, amount: u128) -> ModelEvent {
    ModelEvent::Funded {
        digest: w(d),
        context: context(&p.id, &p.key_binding),
        policy: w(policy),
        payee: w(payee),
        amount,
    }
}

/// The context agrees with the agents' derivation on one recorded post:
/// Base post 0xafa53fb0…, whose order 0xe8c1e899… carried this context.
#[test]
fn context_is_the_agents_derivation() {
    let id = word("0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727");
    let kb = word("0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8");
    assert_eq!(
        hx(&context(&id, &kb)),
        "0xa1c0369fd35a3f2efc5cce7182544495e07615e47a576f5568958e8de7dc3bd3"
    );
}

// ---- The Lean mutants, mirrored (proofs/commerce/Market.lean, Mutants) ----

/// M1: the latest joined order's phase moves a post back; the model does not.
#[test]
fn m1_state_never_moves_back() {
    let p = post(1, 7, 50, 90, 100);
    let mut m = Market::replay(&[
        ModelEvent::Posted(p.clone()),
        funded(11, &p, 50, 3, 10),
        ModelEvent::Refunded(w(11)),
    ]);
    let before = m.state(&p);
    let latest = |m: &Market| m.joined(&p).last().map(|o| o.phase.rank()).unwrap_or(0);
    let latest_before = latest(&m);
    m.apply(&funded(12, &p, 50, 3, 10));
    assert_eq!(before, State::Refunded);
    assert!(m.state(&p).rank() >= before.rank());
    // Red: the mutant reads funded (3) after refunded (4).
    assert!(latest(&m) < latest_before);
}

/// M2: joining on the context alone settles a post with another policy's order.
#[test]
fn m2_settled_only_by_a_joined_order() {
    let p = post(1, 7, 50, 90, 100);
    let m = Market::replay(&[
        ModelEvent::Posted(p.clone()),
        funded(21, &p, 51, 3, 10),
        ModelEvent::Settled(w(21)),
    ]);
    assert!(m.state(&p).rank() < 5);
    let mutant = m
        .orders
        .iter()
        .filter(|o| o.context == context(&p.id, &p.key_binding))
        .map(|o| o.phase.rank())
        .max();
    assert_eq!(mutant, Some(5));
}

/// M3: a context that ignores the post ID joins one order to two posts.
#[test]
fn m3_one_order_one_post() {
    let (a, b) = (post(1, 7, 50, 90, 100), post(2, 7, 50, 90, 100));
    let o = ModelOrder {
        digest: w(31),
        context: context(&a.id, &a.key_binding),
        policy: w(50),
        payee: w(3),
        amount: 10,
        phase: Phase::Funded,
    };
    assert!(Market::joins(&a, &o) && !Market::joins(&b, &o));
    let flat = |p: &ModelPost, o: &ModelOrder| o.context == keccak256(p.key_binding).0;
    let o2 = ModelOrder {
        context: keccak256(w(7)).0,
        ..o
    };
    assert!(flat(&a, &o2) && flat(&b, &o2));
}

/// M4: remaining without refunds overspends a round that refunded.
#[test]
fn m4_remaining_counts_refunds() {
    let p = post(1, 7, 50, 90, 100);
    let m = Market::replay(&[
        ModelEvent::Posted(p.clone()),
        funded(41, &p, 50, 3, 10),
        ModelEvent::Refunded(w(41)),
        funded(42, &p, 50, 3, 10),
        ModelEvent::Tick(200),
    ]);
    let member = |q: &ModelPost| q.id == w(1);
    let r = Round {
        budget: 15,
        tasks: 2,
        member: &member,
    };
    assert_eq!((m.remaining(&r), m.remaining_tasks(&r)), (Some(5), Some(1)));
    // Red: 15 − 20 has no value; the mutant's truncated 0 plus 20 is not 15.
    assert_eq!(r.budget.checked_sub(m.funded_amount(&r)), None);
}

/// M5: taken once funded; the model takes a statement only once settled.
#[test]
fn m5_taken_only_when_settled() {
    let p = post(1, 7, 50, 90, 100);
    let mut m = Market::replay(&[ModelEvent::Posted(p.clone()), funded(51, &p, 50, 3, 10)]);
    assert!(!m.taken(&w(90)));
    assert!(m.rank_of(&p) >= 3, "the mutant's rule would take it");
    m.apply(&ModelEvent::Settled(w(51)));
    assert!(m.taken(&w(90)));
}

/// M6: a claim marks only settled orders of its payee.
#[test]
fn m6_claim_needs_a_settlement() {
    let p = post(1, 7, 50, 90, 100);
    let mut m = Market::replay(&[ModelEvent::Posted(p.clone()), funded(61, &p, 50, 3, 10)]);
    m.apply(&ModelEvent::Claimed(w(3)));
    assert_eq!(m.state(&p), State::Funded);
    m.apply(&ModelEvent::Settled(w(61)));
    m.apply(&ModelEvent::Claimed(w(4)));
    assert_eq!(m.state(&p), State::Settled);
    m.apply(&ModelEvent::Claimed(w(3)));
    assert_eq!(m.state(&p), State::Claimed);
}

#[test]
fn listed_expired_withdrawn() {
    let p = post(1, 7, 50, 90, 100);
    let mut m = Market::replay(&[ModelEvent::Posted(p.clone()), ModelEvent::Tick(100)]);
    assert_eq!(m.state(&p), State::Listed);
    m.apply(&ModelEvent::Tick(101));
    assert_eq!(m.state(&p), State::Expired);
    m.apply(&ModelEvent::Withdrawn(w(1)));
    assert_eq!(m.state(&p), State::Withdrawn);
    m.apply(&ModelEvent::Tick(50));
    assert_eq!(m.state(&p), State::Withdrawn, "time does not go back");
}

// ---- Decoding and scanning ------------------------------------------------

const BOARD: &str = "0x1000000000000000000000000000000000000001";
const VAULT: &str = "0x2000000000000000000000000000000000000002";
const SELLER: &str = "0x3000000000000000000000000000000000000003";
const ASSET: &str = "0x4000000000000000000000000000000000000004";
const BUYER: &str = "0x5000000000000000000000000000000000000005";
const RELAYER: &str = "0x6000000000000000000000000000000000000006";

fn a20(s: &str) -> [u8; 20] {
    unhex(s).unwrap().try_into().unwrap()
}
fn pad(a: &str) -> String {
    format!("0x{:0>64}", a.trim_start_matches("0x"))
}

/// A synthetic chain: one post (the first test vector, re-addressed to
/// BOARD), its order funded at block 15, settled at 25, claimed at 26.
struct Fake {
    logs: Vec<Value>,
    txs: BTreeMap<String, Value>,
    hashes: BTreeMap<u64, String>,
    calls: u64,
}

fn fake() -> (Fake, ModelPost) {
    let input = crate::Input::read(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/input/arbitrum-sepolia.json"
    )))
    .unwrap();
    let vectors = crate::vectors(&input).unwrap();
    let v = &vectors[0];
    let e = &v["expect"];
    let p = ModelPost {
        id: word(e["id"].as_str().unwrap()),
        key_binding: word(e["buyerKeyBinding"].as_str().unwrap()),
        policy: word(e["policyHash"].as_str().unwrap()),
        statement: word(e["statementSha256"].as_str().unwrap()),
        fund_by: e["fundBy"].as_str().unwrap().parse().unwrap(),
        poster: e["poster"].as_str().unwrap().into(),
        block: 5,
    };
    let order = v3::Order {
        buyer: Address::from(a20(BUYER)),
        seller: Address::from(a20(SELLER)),
        asset: Address::from(a20(ASSET)),
        amount: U256::from(1_000_000u64),
        verifier: Address::from([0x77; 20]),
        program: B256::from([0x44; 32]),
        policyHash: B256::from(p.policy),
        base: B256::ZERO,
        fundBy: 1_794_000_001,
        deliverBy: 1_796_000_001,
        salt: B256::from([0x55; 32]),
        context: B256::from(context(&p.id, &p.key_binding)),
    };
    let digest = digest3(8453, &a20(VAULT), &order);
    let fund = v3::fundCall {
        o: order.clone(),
        authorization: vec![1u8; 65].into(),
    }
    .abi_encode();
    let settle = v3::settleCall {
        o: order,
        artifact: vec![9u8; 8].into(),
        seal: vec![].into(),
    }
    .abi_encode();
    let log = |block: u64, i: u64, address: &str, topics: Vec<String>, data: String, tx: &str| {
        json!({"address": address, "topics": topics, "data": data,
               "blockNumber": format!("0x{block:x}"), "logIndex": format!("0x{i:x}"),
               "transactionHash": tx})
    };
    let words = |ws: &[String]| {
        format!(
            "0x{}",
            ws.iter()
                .map(|w| w.trim_start_matches("0x"))
                .collect::<String>()
        )
    };
    let num = |n: u128| format!("0x{n:064x}");
    let t = |s: &str| hx(&topic(s));
    let logs = vec![
        log(
            5,
            0,
            BOARD,
            v["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect(),
            v["data"].as_str().unwrap().into(),
            "0xa1",
        ),
        log(
            15,
            3,
            VAULT,
            vec![
                t("Funded(bytes32,address,address,address,uint256)"),
                hx(&digest),
                pad(BUYER),
                pad(SELLER),
            ],
            words(&[pad(ASSET), num(1_000_000)]),
            "0xa2",
        ),
        log(
            25,
            1,
            VAULT,
            vec![
                t("Settled(bytes32,bytes32,uint256,uint256,address,uint256)"),
                hx(&digest),
            ],
            words(&[
                hx(&keccak256([9u8; 8]).0),
                num(997_500),
                num(2_500),
                pad("0x0"),
                num(0),
            ]),
            "0xa3",
        ),
        log(
            26,
            0,
            VAULT,
            vec![
                t("Claimed(address,address,uint256)"),
                pad(SELLER),
                pad(ASSET),
            ],
            words(&[num(997_500)]),
            "0xa4",
        ),
    ];
    let mut txs = BTreeMap::new();
    txs.insert(
        "0xa2".into(),
        json!({"from": RELAYER, "to": VAULT, "input": hx(&fund)}),
    );
    txs.insert(
        "0xa3".into(),
        json!({"from": RELAYER, "to": VAULT, "input": hx(&settle)}),
    );
    txs.insert(
        "0xa4".into(),
        json!({"from": RELAYER, "to": VAULT, "input": "0x"}),
    );
    let hashes = (0..=40).map(|n| (n, format!("0x{n:064x}"))).collect();
    (
        Fake {
            logs,
            txs,
            hashes,
            calls: 0,
        },
        p,
    )
}

impl Fake {
    fn rpc(&mut self, method: &str, params: Value) -> Res<Value> {
        self.calls += 1;
        let q = |v: &Value| {
            u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        match method {
            "eth_getLogs" => {
                let f = &params[0];
                let (from, to) = (q(&f["fromBlock"]), q(&f["toBlock"]));
                Ok(Value::Array(
                    self.logs
                        .iter()
                        .filter(|l| (from..=to).contains(&q(&l["blockNumber"])))
                        .cloned()
                        .collect(),
                ))
            }
            "eth_getTransactionByHash" => Ok(self.txs[params[0].as_str().unwrap()].clone()),
            "eth_getBlockByNumber" => Ok(json!({"hash": self.hashes[&q(&params[0])]})),
            other => Err(format!("unexpected {other}").into()),
        }
    }
}

fn chain() -> Chain {
    Chain {
        chain_id: 8453,
        board: BOARD.into(),
        board_from: 1,
        vaults: vec![(VAULT.into(), 1)],
        range: 10,
    }
}

#[test]
fn a_fund_call_is_decoded_only_when_its_digest_matches() {
    let (f, p) = fake();
    let input = unhex(f.txs["0xa2"]["input"].as_str().unwrap()).unwrap();
    let digest = word(f.logs[1]["topics"][1].as_str().unwrap());
    let terms = terms_from_call(8453, &a20(VAULT), &input, &digest).unwrap();
    assert_eq!(terms.from, "fund");
    assert_eq!(word(&terms.context), context(&p.id, &p.key_binding));
    // Red: another vault, another chain, another digest.
    assert!(terms_from_call(8453, &a20(BOARD), &input, &digest).is_none());
    assert!(terms_from_call(1, &a20(VAULT), &input, &digest).is_none());
    assert!(terms_from_call(8453, &a20(VAULT), &input, &w(1)).is_none());
}

#[test]
fn an_incremental_scan_equals_a_full_one_and_a_reorg_rescans() {
    let (mut f, p) = fake();
    let c = chain();
    let (full, _) = scan(&mut |m, x| f.rpc(m, x), &c, None, 30, &hash(30), 900).unwrap();
    assert_eq!(full.scan.kind, "full");
    assert_eq!(full.events.len(), 4);
    let (half, _) = scan(&mut |m, x| f.rpc(m, x), &c, None, 18, &hash(18), 800).unwrap();
    assert_eq!(half.events.len(), 2);
    let before = f.calls;
    let (resumed, _) = scan(&mut |m, x| f.rpc(m, x), &c, Some(&half), 30, &hash(30), 900).unwrap();
    assert_eq!(resumed.scan.kind, "incremental");
    assert_eq!(resumed.events, full.events);
    // One hash check, two log ranges (19–28, 29–30), two transactions.
    assert_eq!(f.calls - before, 5);
    let m = Market::replay(&model_events(&resumed, 900));
    assert_eq!(m.state(&m.posts[0]), State::Claimed);
    assert_eq!(m.posts[0].id, p.id);
    // Red: block 18 now has another hash, so the scan starts over.
    f.hashes.insert(18, "0xdead".into());
    let (again, _) = scan(&mut |m, x| f.rpc(m, x), &c, Some(&half), 30, &hash(30), 900).unwrap();
    assert_eq!(again.scan.kind, "full");
    assert_eq!(
        again.scan.why.as_deref(),
        Some("block 18 has another hash now")
    );
    assert_eq!(again.events, full.events);
    // A filtered index is never resumed.
    let names = Names::default();
    let (filtered_again, _) = scan(
        &mut |m, x| f.rpc(m, x),
        &c,
        Some(&filtered(&half, &names)),
        30,
        &hash(30),
        900,
    )
    .unwrap();
    assert_eq!(filtered_again.scan.kind, "full");
}

#[test]
fn an_order_not_funded_directly_takes_its_terms_from_settle() {
    let (mut f, _) = fake();
    // The fund went through some other contract.
    f.txs.insert(
        "0xa2".into(),
        json!({"from": RELAYER, "to": BOARD, "input": "0x"}),
    );
    let (index, _) = scan(&mut |m, x| f.rpc(m, x), &chain(), None, 30, &hash(30), 900).unwrap();
    let Event::Funded { terms: Some(t), .. } = &index.events[1].event else {
        panic!("no terms: {:?}", index.events[1]);
    };
    assert_eq!(t.from, "settle");
}

#[test]
fn publication_shows_outside_posters_only_with_the_authors_list() {
    let (mut f, _) = fake();
    let (index, _) = scan(&mut |m, x| f.rpc(m, x), &chain(), None, 30, &hash(30), 900).unwrap();
    let poster = match &index.events[0].event {
        Event::Posted { poster, .. } => poster.clone(),
        _ => panic!(),
    };
    let published = vec![RELAYER.to_owned()];
    let without = filtered(
        &index,
        &Names {
            published: published.clone(),
            authors: None,
        },
    );
    assert!(shown_posters(&without).is_empty());
    let outside = filtered(
        &index,
        &Names {
            published: published.clone(),
            authors: Some(BTreeSet::from([SELLER.to_owned()])),
        },
    );
    assert_eq!(
        shown_posters(&outside),
        BTreeSet::from([poster.trim_start_matches("0x").to_owned()])
    );
    let theirs = filtered(
        &index,
        &Names {
            published,
            authors: Some(BTreeSet::from([poster.clone()])),
        },
    );
    assert!(
        shown_posters(&theirs).is_empty(),
        "an author's wallet stays elided"
    );
    // Sellers, buyers and payees are never shown; the relayer is.
    let text = serde_json::to_string(&outside).unwrap();
    for a in [SELLER, BUYER] {
        assert!(!text.contains(&a[2..]), "{a}");
    }
    assert!(text.contains(&RELAYER[2..]));
    // Claims still match on the payee key after filtering.
    let m = Market::replay(&model_events(&outside, 900));
    assert_eq!(m.state(&m.posts[0]), State::Claimed);
}

fn hash(n: u64) -> String {
    format!("0x{n:064x}")
}

#[test]
fn the_authors_list_reads_bare_hex_and_never_echoes_a_bad_line() {
    let dir = std::env::temp_dir().join(format!("qed-authors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("a.txt");
    let bare = "00000000000000000000000000000000000000aa";
    std::fs::write(
        &p,
        format!("{bare}\n0x00000000000000000000000000000000000000BB # x\n\n"),
    )
    .unwrap();
    let set = Names::read_authors(&p).unwrap().unwrap();
    assert!(set.contains(&format!("0x{bare}")));
    assert!(set.contains("0x00000000000000000000000000000000000000bb"));
    std::fs::write(&p, "secretish-not-hex\n").unwrap();
    let e = Names::read_authors(&p).unwrap_err().to_string();
    assert!(e.contains("line 1") && !e.contains("secretish"), "{e}");
    assert!(Names::read_authors(&dir.join("absent")).unwrap().is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}
