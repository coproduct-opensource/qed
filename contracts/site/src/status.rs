//! The status page: the main-network bounty, the vault's books and the gas
//! relayer, every number read from the chain at one block and printed with
//! the JSON-RPC query that reproduces it.
//!
//! `nucleus-site snapshot-status INPUT NOW` is the only part that touches a
//! network, and only to read (plus one unauthenticated POST to the relayer,
//! which a relayer answers 401 when it is up). It writes
//! `input/status.snapshot.json`. The build reads that file and never the
//! network; the page's script can re-read the balances live and says which
//! it shows.
//!
//! `nucleus-site refresh-status` (`refresh`) runs the same snapshot on the
//! web host every 10 minutes and rewrites only this page, rendered by the
//! same `page_from` (docs/rfcs/qed-status-refresh-2026-11-17.md).
//!
//! Addresses other than the contracts, the bounty buyer, the relayer and
//! the ladder buyer (when the input names one) are not written to the snapshot: they are stored as "elided". The queries
//! return them to anyone who runs them.
use crate::doc::{Block, Doc, Line, code, code_link, h2, link, p, para, strong, t};
use crate::html::{self, Html};
use crate::ledger::rpc;
use crate::pages::{date, short};
use crate::{Input, Mainnet, Res, StatusInput, amount, hex, unhex};
use alloy_primitives::keccak256;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

pub const SNAPSHOT_PATH: &str = "contracts/site/input/status.snapshot.json";
/// The page's path on the site (`doc`), which the host's reader rewrites.
pub const STATUS_PATH: &str = "status";
pub const ELIDED: &str = "elided";

/// How often the host's reader runs (its timer), and the oldest a served
/// page's block may be before `check-live` reports it: three periods.
pub const REFRESH_SECONDS: u64 = 600;
pub const MAX_AGE_SECONDS: u64 = 1_800;
/// How far a page's read time may be ahead of the checker's clock.
pub const CLOCK_SKEW_SECONDS: u64 = 300;

/// Where the values on the page come from. The page says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The snapshot the release was built from; never refreshed.
    Build,
    /// The host's reader. `failed_at`: the time of a read that failed after
    /// this snapshot, which the page then names with the values' age.
    Refreshed { failed_at: Option<u64> },
}

fn topic(signature: &str) -> String {
    format!("0x{}", hex(keccak256(signature.as_bytes()).as_slice()))
}
fn funded_topic() -> String {
    topic("Funded(bytes32,address,address,address,uint256)")
}
fn refunded_topic() -> String {
    topic("Refunded(bytes32,address,uint256)")
}
fn settled_topic() -> String {
    topic("Settled(bytes32,bytes32,uint256,uint256,address,uint256)")
}
fn claimed_topic() -> String {
    topic("Claimed(address,address,uint256)")
}
const BALANCE_OF: &str = "0x70a08231";

fn word_address(word: &str) -> String {
    format!("0x{}", &word.trim_start_matches("0x")[24..])
}
fn padded(address: &str) -> String {
    format!("{:0>64}", address.trim_start_matches("0x"))
}
fn quantity(v: &Value) -> Res<u64> {
    let s = v.as_str().ok_or("quantity is not a string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}
/// A 32-byte word as an integer; amounts here fit in 128 bits.
fn word_u128(word: &str) -> Res<u128> {
    let w = word.trim_start_matches("0x");
    let w = w.trim_start_matches('0');
    if w.is_empty() {
        return Ok(0);
    }
    if w.len() > 32 {
        return Err(format!("word {word} does not fit in 128 bits").into());
    }
    Ok(u128::from_str_radix(w, 16)?)
}
fn data_words(data: &str) -> Vec<String> {
    let d = data.trim_start_matches("0x");
    (0..d.len() / 64)
        .map(|i| format!("0x{}", &d[i * 64..(i + 1) * 64]))
        .collect()
}

struct Reader<'a> {
    url: &'a str,
    reads: Vec<Value>,
}

impl Reader<'_> {
    /// One JSON-RPC call, recorded with its query so the page can print it.
    fn read(&mut self, id: &str, what: &str, method: &str, params: Value) -> Res<Value> {
        let result = rpc(self.url, method, params.clone())?;
        self.reads.push(json!({
            "id": id, "what": what, "method": method, "params": params,
            // Logs are summarised, not stored: they carry addresses.
            "result": match method {
                "eth_getLogs" => json!(format!("{} logs", result.as_array().map_or(0, Vec::len))),
                "eth_getBlockByNumber" => json!({"number": result["number"], "timestamp": result["timestamp"]}),
                _ => result.clone(),
            },
        }));
        Ok(result)
    }
    /// `eth_getLogs` over [from, to] in ranges of at most `range` blocks.
    fn logs(
        &mut self,
        id: &str,
        what: &str,
        address: &str,
        from: u64,
        to: u64,
        range: u64,
    ) -> Res<Vec<Value>> {
        let mut out = Vec::new();
        let mut start = from;
        let mut part = 0;
        while start <= to {
            let end = to.min(start + range - 1);
            let filter = json!([{"address": address, "fromBlock": format!("0x{start:x}"), "toBlock": format!("0x{end:x}")}]);
            let got = self.read(&format!("{id}-{part}"), what, "eth_getLogs", filter)?;
            out.extend(got.as_array().cloned().unwrap_or_default());
            start = end + 1;
            part += 1;
        }
        Ok(out)
    }
}

fn published(address: &str, st: &StatusInput) -> String {
    let a = address.to_ascii_lowercase();
    if a == st.buyer || a == st.relayer || st.ladder_buyer.as_deref() == Some(a.as_str()) {
        a
    } else {
        ELIDED.into()
    }
}

/// Read the main network's bounty, vaults and relayer at the latest block.
/// `deliveries` is the buyer's signed summary of delivery attempts as
/// `nucleus-buyer deliveries-fetch` wrote it beside the input, if it did; it
/// is stored as fetched and checked when the page is built.
pub fn snapshot(input: &Input, now: u64, deliveries: Option<&str>) -> Res<Value> {
    let m = input
        .mainnet
        .as_ref()
        .ok_or("the input has no main network")?;
    let st = m
        .status
        .as_ref()
        .ok_or("the input's main network has no status block")?;
    let url = m.network.rpc.as_str();
    let range = m.network.log_range.unwrap_or(10_000);
    let mut r = Reader {
        url,
        reads: Vec::new(),
    };
    let chain = quantity(&r.read("chain", "chain ID", "eth_chainId", json!([]))?)?;
    if chain != m.network.chain_id {
        return Err(format!("{url} answers chain {chain}, not {}", m.network.chain_id).into());
    }
    let block = quantity(&r.read(
        "block",
        "the block every value below is read at",
        "eth_blockNumber",
        json!([]),
    )?)?;
    let tag = format!("0x{block:x}");
    let header = r.read(
        "block-header",
        "that block's timestamp",
        "eth_getBlockByNumber",
        json!([tag, false]),
    )?;
    let timestamp = quantity(&header["timestamp"])?;

    // The board: every post and withdrawal since it was deployed.
    let board_logs = r.logs(
        "board-logs",
        "the board's Posted and Withdrawn events",
        &m.board.address,
        m.board.deploy_block.ok_or("board deploy block")?,
        block,
        range,
    )?;
    let mut posts: Vec<Value> = Vec::new();
    let mut withdrawn: Vec<(String, String)> = Vec::new();
    for log in &board_logs {
        let topics: Vec<[u8; 32]> = log["topics"]
            .as_array()
            .ok_or("log topics")?
            .iter()
            .map(|t| {
                let b = unhex(t.as_str().unwrap_or(""))?;
                b.try_into().map_err(|_| "topic length".into())
            })
            .collect::<Res<_>>()?;
        let data = unhex(log["data"].as_str().unwrap_or("0x"))?;
        let tx = log["transactionHash"].as_str().unwrap_or("").to_string();
        match nucleus_board_reference::decode_log(&topics, &data) {
            Ok(nucleus_board_reference::Notice::Posted(p)) => posts.push(json!({
                "id": format!("0x{}", hex(&p.id)),
                "poster": published(&format!("0x{}", hex(&p.poster)), st),
                "vault": format!("0x{}", hex(&p.vault)),
                "maximumAmount": word_u128(&hex(&p.task.maximum_amount))?.to_string(),
                "program": hex(&p.task.program),
                "statementSha256": hex(&p.task.statement_sha256),
                "fundBy": p.task.fund_by,
                "deliverBy": p.task.deliver_by,
                "transaction": tx,
                "block": quantity(&log["blockNumber"])?,
            })),
            Ok(nucleus_board_reference::Notice::Withdrawn(id)) => {
                withdrawn.push((format!("0x{}", hex(&id)), tx));
            }
            Err(e) => return Err(format!("board log in {tx}: {e:?}").into()),
        }
    }
    for post in &mut posts {
        if let Some((_, tx)) = withdrawn.iter().find(|(id, _)| post["id"] == id.as_str()) {
            post["withdrawnIn"] = json!(tx);
        }
    }

    // Each vault the relayer serves: its events, who sent each one's
    // transaction, and the USDC it holds.
    let mut vaults = Vec::new();
    // Each payee a vault paid, and the block of its first claim: where to
    // look for its sweeps.
    let mut payees: Vec<(String, u64)> = Vec::new();
    for (index, v) in st.vaults.iter().enumerate() {
        let logs = r.logs(
            &format!("vault{index}-logs"),
            "the vault's Funded, Settled, Refunded and Claimed events",
            &v.address,
            v.deploy_block,
            block,
            range,
        )?;
        let mut events = Vec::new();
        for log in &logs {
            let topics: Vec<String> = log["topics"]
                .as_array()
                .ok_or("topics")?
                .iter()
                .map(|t| t.as_str().unwrap_or("").to_ascii_lowercase())
                .collect();
            let words = data_words(log["data"].as_str().unwrap_or("0x"));
            let tx = log["transactionHash"].as_str().unwrap_or("").to_string();
            let sent = rpc(url, "eth_getTransactionByHash", json!([tx]))?;
            let from = sent["from"].as_str().unwrap_or("").to_ascii_lowercase();
            let kind = topics.first().cloned().unwrap_or_default();
            let mut e = json!({
                "transaction": tx,
                "block": quantity(&log["blockNumber"])?,
                "sentBy": published(&from, st),
            });
            if kind == funded_topic() && topics.len() == 4 && words.len() == 2 {
                e["event"] = json!("Funded");
                e["digest"] = json!(topics[1]);
                e["buyer"] = json!(published(&word_address(&topics[2]), st));
                e["seller"] = json!(published(&word_address(&topics[3]), st));
                e["amount"] = json!(word_u128(&words[1])?.to_string());
            } else if kind == refunded_topic() && topics.len() == 3 && words.len() == 1 {
                e["event"] = json!("Refunded");
                e["digest"] = json!(topics[1]);
                e["buyer"] = json!(published(&word_address(&topics[2]), st));
                e["amount"] = json!(word_u128(&words[0])?.to_string());
            } else if kind == settled_topic() && topics.len() == 2 && words.len() == 5 {
                e["event"] = json!("Settled");
                e["digest"] = json!(topics[1]);
                e["sellerOwed"] = json!(word_u128(&words[1])?.to_string());
                e["feeOwed"] = json!(word_u128(&words[2])?.to_string());
                e["royaltyOwed"] = json!(word_u128(&words[4])?.to_string());
            } else if kind == claimed_topic() && topics.len() == 3 && words.len() == 1 {
                e["event"] = json!("Claimed");
                let payee = word_address(&topics[1]).to_ascii_lowercase();
                let at = quantity(&log["blockNumber"])?;
                match payees.iter_mut().find(|(p, _)| *p == payee) {
                    Some((_, first)) => *first = (*first).min(at),
                    None => payees.push((payee.clone(), at)),
                }
                e["payee"] = json!(published(&payee, st));
                e["asset"] = json!(word_address(&topics[2]));
                e["amount"] = json!(word_u128(&words[0])?.to_string());
            } else {
                return Err(format!("unknown vault log in {tx}").into());
            }
            events.push(e);
        }
        let held = r.read(
            &format!("vault{index}-usdc"),
            "USDC the vault holds",
            "eth_call",
            json!([{"to": m.token.address, "data": format!("{BALANCE_OF}{}", padded(&v.address))}, tag]),
        )?;
        vaults.push(json!({
            "address": v.address,
            "deployBlock": v.deploy_block,
            "usdcHeld": word_u128(held.as_str().unwrap_or("0x"))?.to_string(),
            "events": events,
        }));
    }

    // Sweeps: USDC Transfer events out of each payee since its first claim,
    // in transactions the relayer sent (a relayed transferWithAuthorization).
    // The payee is not written to the snapshot: the recorded query names it
    // as PAYEE, and the page says where to read it.
    let transfer = topic("Transfer(address,address,uint256)");
    let mut sweeps = Vec::new();
    for (k, (payee, first)) in payees.iter().enumerate() {
        let mut start = *first;
        let mut part = 0;
        while start <= block {
            let end = block.min(start + range - 1);
            let filter = |who: &str| {
                json!([{"address": m.token.address, "topics": [transfer, format!("0x{}", padded(who))],
                        "fromBlock": format!("0x{start:x}"), "toBlock": format!("0x{end:x}")}])
            };
            let logs = rpc(url, "eth_getLogs", filter(payee))?;
            r.reads.push(json!({
                "id": format!("sweeps{k}-{part}"),
                "what": "USDC Transfer events out of a payee (PAYEE: the payee of a Claimed event above)",
                "method": "eth_getLogs",
                "params": filter("PAYEE"),
                "result": format!("{} logs", logs.as_array().map_or(0, Vec::len)),
            }));
            for log in logs.as_array().cloned().unwrap_or_default() {
                let tx = log["transactionHash"].as_str().unwrap_or("").to_string();
                let sent = rpc(url, "eth_getTransactionByHash", json!([tx]))?;
                let from = sent["from"].as_str().unwrap_or("").to_ascii_lowercase();
                if from == st.relayer {
                    sweeps.push(json!({
                        "event": "Transfer (sweep)",
                        "transaction": tx,
                        "block": quantity(&log["blockNumber"])?,
                        "sentBy": published(&from, st),
                        "amount": word_u128(log["data"].as_str().unwrap_or("0x"))?.to_string(),
                    }));
                }
            }
            start = end + 1;
            part += 1;
        }
    }
    let relayer_nonce = r.read(
        "relayer-nonce",
        "transactions the relayer's wallet has sent",
        "eth_getTransactionCount",
        json!([st.relayer, tag]),
    )?;
    let buyer_usdc = r.read(
        "buyer-usdc",
        "USDC the bounty buyer holds",
        "eth_call",
        json!([{"to": m.token.address, "data": format!("{BALANCE_OF}{}", padded(&st.buyer))}, tag]),
    )?;
    let relayer_eth = r.read(
        "relayer-eth",
        "ETH the relayer holds, in wei",
        "eth_getBalance",
        json!([st.relayer, tag]),
    )?;

    // Reachability: a POST without a proof. 401 means the relayer answered.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .http_status_as_error(false)
        .build()
        .into();
    let relay = format!("{}/relay", st.relayer_url.trim_end_matches('/'));
    let reach = match agent
        .post(&relay)
        .header("content-type", "application/json")
        .send("{}")
    {
        Ok(mut response) => json!({
            "status": response.status().as_u16(),
            "body": response.body_mut().read_to_string().unwrap_or_default().chars().take(80).collect::<String>(),
        }),
        Err(e) => json!({"status": null, "error": e.to_string()}),
    };

    Ok(json!({
        "schema": "qed-status-snapshot/1",
        "takenAt": now,
        "rpc": url,
        "chainId": chain,
        "block": block,
        "blockTimestamp": timestamp,
        "posts": posts,
        "vaults": vaults,
        "buyerUsdc": word_u128(buyer_usdc.as_str().unwrap_or("0x"))?.to_string(),
        "relayerWei": word_u128(relayer_eth.as_str().unwrap_or("0x"))?.to_string(),
        "relayerNonce": quantity(&relayer_nonce)?,
        "sweeps": sweeps,
        "relayerReach": { "url": relay, "checkedAt": now, "answer": reach },
        "deliveries": { "jws": deliveries.map(str::trim), "readAt": now },
        "reads": r.reads,
    }))
}

// ---- Delivery attempts --------------------------------------------------------

/// The file `nucleus-buyer deliveries-fetch` writes beside the input, which
/// `snapshot-status` stores in the snapshot.
pub const DELIVERIES_FILE: &str = "deliveries.jws";

/// What the page can say about the buyer's record of delivery attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deliveries {
    /// A summary signed by the buyer's key, for the bounty buyer.
    Read(Box<qed_deliveries::Summary>),
    /// Anything else. Shown as "could not read", never as a count of zero.
    CouldNotRead(String),
}

/// Read the snapshot's signed summary against the input's key binding.
pub fn deliveries(st: &StatusInput, snap: &Value) -> Deliveries {
    let could_not = |why: &str| Deliveries::CouldNotRead(why.to_owned());
    let Some(d) = st.deliveries.as_ref() else {
        return could_not("the input names no key for the buyer's record");
    };
    let binding: Option<qed_deliveries::Hash> =
        unhex(&d.key_binding).ok().and_then(|b| b.try_into().ok());
    let Some(binding) = binding else {
        return could_not("the input's key binding is not 32 bytes");
    };
    let Some(jws) = snap["deliveries"]["jws"].as_str() else {
        return could_not("the snapshot holds no signed summary");
    };
    match qed_deliveries::verify(jws, &binding) {
        Ok(s) if s.buyer.eq_ignore_ascii_case(&st.buyer) => Deliveries::Read(Box::new(s)),
        Ok(_) => could_not("the summary is for another buyer"),
        Err(why) => Deliveries::CouldNotRead(why.to_string()),
    }
}

/// The section's blocks, and the line for the compact summary. A refreshed
/// page carries the build's record and says so: the host's reader reads the
/// chain only (docs/rfcs/qed-status-refresh-2026-11-17.md §8).
fn deliveries_section(st: &StatusInput, snap: &Value, source: Source) -> (Vec<Block>, Line) {
    let mut blocks = vec![h2("deliveries", "Delivery attempts")];
    // The reread covers the chain only; this record is the build's.
    let as_of = match (source, snap["deliveries"]["readAt"].as_u64()) {
        (Source::Build, _) => String::new(),
        (Source::Refreshed { .. }, Some(at)) => format!(" As of the build ({}).", date(at)),
        (Source::Refreshed { .. }, None) => " Not reread.".into(),
    };
    let as_of_line = match source {
        Source::Build => "",
        Source::Refreshed { .. } => " As of the build.",
    };
    let s = match deliveries(st, snap) {
        Deliveries::CouldNotRead(why) => {
            blocks.push(para(&format!(
                "Could not read the bounty buyer's record of delivery attempts: {why}.{as_of}"
            )));
            return (
                blocks,
                vec![
                    strong("Delivery attempts:"),
                    t(format!(" could not read.{as_of_line}")),
                ],
            );
        }
        Deliveries::Read(s) => s,
    };
    // Bounded by the signature's date: the record says nothing of what came
    // after it (2026-11-25, when a seller settled four tasks on chain after a
    // record that still read as current).
    blocks.push(p(vec![
        t(format!(
            "Off-chain offers, signed by the bounty buyer, {}.{as_of} The record says nothing of later attempts; settlements are on chain, in the ",
            date(s.signed_at)
        )),
        link("/transactions", "ledger"),
        t("."),
    ]));
    let line = vec![
        strong("Delivery attempts:"),
        t(format!(
            " {}, signed {}.{as_of_line}",
            s.records,
            date(s.signed_at)
        )),
    ];
    if s.records == 0 && s.unreadable == 0 && s.unrecorded == 0 {
        // Not "since": the record ends when it was signed.
        blocks.push(para(&format!(
            "No delivery attempt was recorded from {} to {}.",
            date(s.opened),
            date(s.signed_at)
        )));
    } else {
        let count = |what: String, n: u64| vec![vec![t(what)], vec![t(n.to_string())]];
        let mut rows = vec![
            count("Attempts".into(), s.records),
            count("Accepted (authorization signed)".into(), s.accepted),
            count("Reviewed (nothing signed)".into(), s.reviewed),
        ];
        for (reason, n) in &s.refused {
            rows.push(count(format!("Refused: {}", reason.describe()), *n));
        }
        for (what, at) in [("First", s.first), ("Last", s.last)] {
            if let Some(at) = at {
                rows.push(vec![vec![t(what)], vec![t(date(at))]]);
            }
        }
        rows.push(count("Sellers, by key".into(), s.sellers.distinct));
        rows.push(count(
            "Sellers not in the authors' wallet list".into(),
            s.sellers.unknown,
        ));
        if s.unreadable > 0 {
            rows.push(count("Records that could not be read".into(), s.unreadable));
        }
        if s.unrecorded > 0 {
            rows.push(count(
                "Attempts that could not be recorded".into(),
                s.unrecorded,
            ));
        }
        blocks.push(Block::Table {
            caption: "Delivery attempts, from the bounty buyer's signed record".into(),
            head: ["Count", "Value"].map(String::from).to_vec(),
            rows,
        });
    }
    if let Some(d) = st.deliveries.as_ref() {
        for note in &d.notes {
            blocks.push(para(&format!("Authors' note: {note}")));
        }
        blocks.push(Block::Details {
            summary: "Check".into(),
            blocks: query(
                "q-deliveries",
                format!(
                    "nucleus-buyer deliveries-fetch {} deliveries.jws {}",
                    d.node, d.key_binding
                ),
            ),
        });
    }
    (blocks, line)
}

// ---- The page ---------------------------------------------------------------

fn n(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// What the page derives from the vault's events, for one vault.
struct Books {
    funded: u128,
    settled_deposits: u128,
    refunded: u128,
    booked: u128,
    claimed: u128,
}

fn books(vault: &Value, token: &str) -> Books {
    let events = vault["events"].as_array().cloned().unwrap_or_default();
    let of = |name: &'static str| events.iter().filter(move |e| e["event"] == name);
    let funded: u128 = of("Funded").map(|e| n(&e["amount"])).sum();
    let refunded: u128 = of("Refunded").map(|e| n(&e["amount"])).sum();
    let settled_deposits: u128 = of("Settled")
        .filter_map(|s| of("Funded").find(|f| f["digest"] == s["digest"]))
        .map(|f| n(&f["amount"]))
        .sum();
    let booked: u128 = of("Settled")
        .map(|e| n(&e["sellerOwed"]) + n(&e["feeOwed"]) + n(&e["royaltyOwed"]))
        .sum::<u128>()
        + refunded;
    let claimed: u128 = of("Claimed")
        .filter(|e| {
            e["asset"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(token))
        })
        .map(|e| n(&e["amount"]))
        .sum();
    Books {
        funded,
        settled_deposits,
        refunded,
        booked,
        claimed,
    }
}

/// The curl that reproduces one recorded read, with the two wallets
/// replaced by placeholders when they are not published.
fn curl(rpc: &str, read: &Value, st: &StatusInput) -> String {
    let body =
        json!({"jsonrpc": "2.0", "id": 1, "method": read["method"], "params": read["params"]});
    let mut text = body.to_string();
    if !st.publish_wallets {
        for (address, name) in [
            (&st.buyer, "BUYER_ADDRESS"),
            (&st.relayer, "RELAYER_ADDRESS"),
        ] {
            text = text.replace(address.trim_start_matches("0x"), name);
        }
    }
    format!("curl -s {rpc} -H 'content-type: application/json' \\\n  -d '{text}'")
}

/// A query as the page offers it: with a copy control when it runs as it
/// is, and otherwise as a template under a line saying what to replace,
/// without one (`crate::commands`).
fn query(id: &str, text: String) -> Vec<Block> {
    let missing = crate::commands::placeholders(&text);
    if missing.is_empty() {
        vec![Block::Pre {
            id: id.into(),
            text,
            copy: Some("Copy".into()),
        }]
    } else {
        vec![
            para(&format!(
                "Template, not runnable as it is: replace {}.",
                missing.join(", ")
            )),
            Block::Pre {
                id: id.into(),
                text,
                copy: None,
            },
        ]
    }
}

fn wallet(address: &str, st: &StatusInput, role: &str) -> Vec<crate::doc::Inline> {
    if st.publish_wallets {
        vec![code(address.to_owned())]
    } else {
        vec![t(format!("the {role} (not listed here)"))]
    }
}

fn tx_link(m: &Mainnet, tx: &str) -> crate::doc::Inline {
    code_link(format!("{}/tx/{tx}", m.network.explorer), short(tx))
}

/// The page as the build writes it, from the build-time snapshot.
pub fn page(input: &Input, snap: Option<&Value>) -> Option<Doc> {
    page_from(input, snap, Source::Build)
}

/// The sentence that says which values the page shows, with their block,
/// that block's time and the time they were read.
fn source_sentence(m: &Mainnet, s: &Value, source: Source) -> String {
    let block = s["block"].as_u64().unwrap_or(0);
    let made = date(s["blockTimestamp"].as_u64().unwrap_or(0));
    let read = s["takenAt"].as_u64().unwrap_or(0);
    let rpc_url = s["rpc"].as_str().unwrap_or("");
    // Short on purpose: the site's prose limit counts these words, and the
    // refreshed page must fit it as the built one does.
    let block = format!(
        "block {block} on {} (chain {}), made {made}",
        m.network.name, m.network.chain_id
    );
    let read = date(read);
    match source {
        Source::Build => {
            format!("Read at {read} from {rpc_url} by the build: {block}. Not refreshed.")
        }
        Source::Refreshed { failed_at: None } => format!(
            "Read at {read} from {rpc_url}: {block}. Reread every {} minutes; stale after {} minutes.",
            REFRESH_SECONDS / 60,
            MAX_AGE_SECONDS / 60
        ),
        Source::Refreshed {
            failed_at: Some(failed),
        } => format!(
            "Read at {read} from {rpc_url}: {block}. Reread failed at {}, {} minutes later.",
            date(failed),
            failed.saturating_sub(s["takenAt"].as_u64().unwrap_or(0)) / 60,
        ),
    }
}

/// The page, from a snapshot taken by the build or by the host's reader.
/// The one renderer of the status page: `refresh` calls it too.
pub fn page_from(input: &Input, snap: Option<&Value>, source: Source) -> Option<Doc> {
    let m = input.mainnet.as_ref()?;
    let st = m.status.as_ref()?;
    let usdc = |units: u128| {
        format!(
            "{} {}",
            amount(units as u64, m.token.decimals),
            m.token.name
        )
    };
    let eth = |wei: u128| {
        const ONE: u128 = 1_000_000_000_000_000_000;
        let frac = format!("{:018}", wei % ONE);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() {
            format!("{} ETH", wei / ONE)
        } else {
            format!("{}.{frac} ETH", wei / ONE)
        }
    };
    let mut blocks = vec![para("Each value comes with the call that reproduces it.")];
    let Some(s) = snap else {
        blocks.push(para(
            "This build was made without a status snapshot, so no values are shown.",
        ));
        return Some(doc(blocks, None));
    };
    let block = s["block"].as_u64().unwrap_or(0);
    let now = s["blockTimestamp"].as_u64().unwrap_or(0);
    let rpc_url = s["rpc"].as_str().unwrap_or("");
    let reads: Vec<Value> = s["reads"].as_array().cloned().unwrap_or_default();
    let read = |id: &str| {
        reads
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap_or(Value::Null)
    };
    let pre = |id: &str, text: String| query(&format!("q-{id}"), text);
    let log_reads = |prefix: &str| -> Vec<Value> {
        reads
            .iter()
            .filter(|r| r["id"].as_str().is_some_and(|i| i.starts_with(prefix)))
            .cloned()
            .collect()
    };

    // Which values the reader is looking at, and how old they are.
    let source_kind = source;
    let source = source_sentence(m, s, source_kind);
    let stamp = [
        block.to_string(),
        now.to_string(),
        s["takenAt"].as_u64().unwrap_or(0).to_string(),
    ];
    let live_rows = [
        (
            "buyer-usdc",
            "Bounty buyer's USDC (funding)",
            usdc(n(&s["buyerUsdc"])),
        ),
        ("relayer-eth", "Relayer's ETH", eth(n(&s["relayerWei"]))),
        (
            "vault0-usdc",
            "USDC the bounty's vault holds",
            usdc(n(&s["vaults"][0]["usdcHeld"])),
        ),
    ];
    let table = html::el(
        "table",
        &[],
        [
            html::tx("caption", &[], "Balances"),
            html::el(
                "thead",
                &[],
                [html::el(
                    "tr",
                    &[],
                    ["Value", "Read"].map(|h| html::tx("th", &[("scope", "col")], h)),
                )],
            ),
            html::el(
                "tbody",
                &[],
                live_rows.iter().map(|(id, what, value)| {
                    html::el(
                        "tr",
                        &[],
                        [
                            html::tx("td", &[], what),
                            html::tx("td", &[("data-read", id)], value),
                        ],
                    )
                }),
            ),
        ],
    );
    blocks.push(h2("source", "Snapshot"));
    blocks.push(Block::Rendered {
        html: Html::join([
            html::tx(
                "p",
                &[
                    ("id", "status-source"),
                    ("aria-live", "polite"),
                    ("data-block", &stamp[0]),
                    ("data-block-time", &stamp[1]),
                    ("data-read-at", &stamp[2]),
                ],
                &source,
            ),
            html::el("div", &[("class", "scroll")], [table]),
            html::el(
                "form",
                &[("id", "status-form"), ("hidden", "")],
                [
                    html::tx("label", &[("for", "status-rpc")], "Base RPC endpoint"),
                    html::void(
                        "input",
                        &[
                            ("id", "status-rpc"),
                            ("type", "url"),
                            ("value", &m.network.rpc),
                            ("required", "required"),
                        ],
                    ),
                    html::tx("button", &[("type", "submit")], "Read the balances live"),
                ],
            ),
        ]),
        markdown: format!(
            "{source}\n\n| Value | Read |\n|---|---|\n{}",
            live_rows
                .iter()
                .map(|(_, w, v)| format!("| {w} | {v} |\n"))
                .collect::<String>()
        ),
    });
    // The compact summary goes here, under the balances; the sections
    // below fill it, and keep their raw queries in disclosures.
    let summary_at = blocks.len();
    let mut summary: Vec<Line> = Vec::new();
    let queries = |blocks: Vec<Block>| Block::Details {
        summary: "Queries".into(),
        blocks,
    };
    blocks.push(queries(pre("block", curl(rpc_url, &read("block"), st))));

    // The bounty.
    let b = &m.bounty;
    let books0 = books(&s["vaults"][0], &m.token.address);
    let vault0 = &s["vaults"][0];
    let events0: Vec<Value> = vault0["events"].as_array().cloned().unwrap_or_default();
    let buyer_funded: Vec<&Value> = events0
        .iter()
        .filter(|e| e["event"] == "Funded" && e["buyer"] == st.buyer.as_str())
        .collect();
    let buyer_refunded: Vec<&Value> = events0
        .iter()
        .filter(|e| e["event"] == "Refunded" && e["buyer"] == st.buyer.as_str())
        .collect();
    let spent: u128 = buyer_funded.iter().map(|e| n(&e["amount"])).sum::<u128>()
        - buyer_refunded.iter().map(|e| n(&e["amount"])).sum::<u128>();
    let used = buyer_funded.len() - buyer_refunded.len().min(buyer_funded.len());
    let remaining_tasks = (b.tasks as usize).saturating_sub(used);
    blocks.push(h2("bounty", "The bounty"));
    let mut line = vec![t("The bounty buyer, ")];
    line.extend(wallet(&st.buyer, st, "bounty buyer"));
    line.push(t(format!(
        ", posts on the board {} (vault {}); ",
        m.board.address, m.vault.address
    )));
    line.push(link("/bounty", "terms"));
    line.push(t("."));
    if let (true, Some(ladder)) = (st.publish_wallets, st.ladder_buyer.as_deref()) {
        line.push(t(" The ladder buyer, "));
        line.push(code(ladder.to_owned()));
        line.push(t(", posts Nucleus's open statements on the same board."));
    }
    blocks.push(p(line));
    let posts: Vec<Value> = s["posts"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<Line>> = posts
        .iter()
        .rev()
        .map(|p| {
            let state = if p["withdrawnIn"].is_string() {
                "withdrawn".to_string()
            } else if p["fundBy"].as_u64().unwrap_or(0) >= now {
                "open".into()
            } else {
                "funding deadline passed".into()
            };
            let poster = if p["poster"] == st.buyer.as_str() {
                "the bounty buyer"
            } else if st.publish_wallets
                && st.ladder_buyer.as_deref().is_some_and(|l| p["poster"] == l)
            {
                "the ladder buyer"
            } else {
                "another poster (not listed here)"
            };
            vec![
                vec![code(short(p["id"].as_str().unwrap_or("")))],
                vec![t(state)],
                vec![t(usdc(n(&p["maximumAmount"])))],
                vec![t(date(p["fundBy"].as_u64().unwrap_or(0)))],
                vec![t(date(p["deliverBy"].as_u64().unwrap_or(0)))],
                vec![t(poster)],
                vec![tx_link(m, p["transaction"].as_str().unwrap_or(""))],
            ]
        })
        .collect();
    let open = posts
        .iter()
        .filter(|p| !p["withdrawnIn"].is_string() && p["fundBy"].as_u64().unwrap_or(0) >= now)
        .count();
    summary.push(vec![strong(format!(
        "{} posts on the board, {open} open at block {block}.",
        posts.len()
    ))]);
    blocks.push(Block::Table {
        caption: "Posts on the board, from its Posted and Withdrawn events".into(),
        head: [
            "Task",
            "State",
            "Price cap",
            "Fund by",
            "Deliver by",
            "Posted by",
            "Post",
        ]
        .map(String::from)
        .to_vec(),
        rows,
    });
    let mut bounty_queries = Vec::new();
    for r in log_reads("board-logs") {
        bounty_queries.extend(pre(
            r["id"].as_str().unwrap_or("board"),
            curl(rpc_url, &r, st),
        ));
    }
    summary.push(vec![
        strong(format!(
            "Remaining: {remaining_tasks} of {} tasks, {} of {}.",
            b.tasks,
            usdc(u128::from(b.budget).saturating_sub(spent)),
            usdc(u128::from(b.budget))
        )),
        t(format!(
            " From the buyer's Funded less Refunded events ({} and {}).",
            buyer_funded.len(),
            buyer_refunded.len(),
        )),
    ]);
    let mut fund = vec![
        strong(format!("Funding: {}", usdc(n(&s["buyerUsdc"])))),
        t(" held by the bounty buyer."),
    ];
    if n(&s["buyerUsdc"]) < u128::from(b.price) {
        fund.push(t(
            " Less than one task's price: the buyer cannot fund an order.",
        ));
    }
    summary.push(fund);
    bounty_queries.extend(pre("buyer-usdc", curl(rpc_url, &read("buyer-usdc"), st)));
    blocks.push(queries(bounty_queries));

    // Delivery attempts: what the chain does not show.
    let (delivery_blocks, delivery_line) = deliveries_section(st, s, source_kind);
    blocks.extend(delivery_blocks);
    summary.push(delivery_line);

    // Payouts and the vault's books.
    blocks.push(h2("payouts", "Payouts and what the vault owes"));
    let payout_rows: Vec<Vec<Line>> = events0
        .iter()
        .filter(|e| e["event"] == "Settled" || e["event"] == "Claimed")
        .map(|e| {
            let what = if e["event"] == "Settled" {
                format!(
                    "Settled: seller {}, fee {}, royalty {}",
                    usdc(n(&e["sellerOwed"])),
                    usdc(n(&e["feeOwed"])),
                    usdc(n(&e["royaltyOwed"]))
                )
            } else {
                format!("Claimed: {}", usdc(n(&e["amount"])))
            };
            vec![
                vec![t(what)],
                vec![t(e["block"].to_string())],
                vec![tx_link(m, e["transaction"].as_str().unwrap_or(""))],
            ]
        })
        .collect();
    if payout_rows.is_empty() {
        blocks.push(para(&format!("No Settled or Claimed event on the vault {} up to block {block}: nothing has been paid out through it.", m.vault.address)));
    } else {
        blocks.push(Block::Table {
            caption: "Settled and Claimed events on the bounty's vault".into(),
            head: ["Event", "Block", "Transaction"].map(String::from).to_vec(),
            rows: payout_rows,
        });
    }
    let held_deposits = books0
        .funded
        .saturating_sub(books0.settled_deposits + books0.refunded);
    let owed = books0.booked.saturating_sub(books0.claimed);
    let holds = n(&vault0["usdcHeld"]);
    summary.push(vec![
        strong(format!("The vault holds {}:", usdc(holds))),
        t(if holds == held_deposits + owed {
            format!(
                " open deposits {} plus booked, unclaimed {}.",
                usdc(held_deposits),
                usdc(owed)
            )
        } else {
            format!(
                " not open deposits {} plus booked, unclaimed {}: a transfer outside fund, or an event this page does not read.",
                usdc(held_deposits),
                usdc(owed)
            )
        }),
    ]);
    let mut vault_queries = Vec::new();
    for r in log_reads("vault0-logs") {
        vault_queries.extend(pre(
            r["id"].as_str().unwrap_or("vault"),
            curl(rpc_url, &r, st),
        ));
    }
    vault_queries.extend(pre("vault0-usdc", curl(rpc_url, &read("vault0-usdc"), st)));
    blocks.push(queries(vault_queries));

    // The relayer.
    blocks.push(h2("relayer", "The gas relayer"));
    let wei = n(&s["relayerWei"]);
    let floor: u128 = st.relayer_floor_wei.parse().unwrap_or(0);
    let mut line = vec![
        t("The relayer "),
        code(st.relayer_url.clone()),
        t(" sends from "),
    ];
    line.extend(wallet(&st.relayer, st, "relayer's wallet"));
    line.push(t(format!(
        ". Its floor is {}, set as {}. {}",
        eth(floor),
        st.relayer_floor_source,
        if wei > floor {
            format!("It can spend {} before it refuses.", eth(wei - floor))
        } else {
            "At or below its floor it refuses every call.".into()
        }
    )));
    blocks.push(p(line));
    let mut relayer_queries = pre("relayer-eth", curl(rpc_url, &read("relayer-eth"), st));
    let reach = &s["relayerReach"];
    let up = match reach["answer"]["status"].as_u64() {
        Some(401) => "Up: 401 to a request without a proof.".to_string(),
        Some(code) => format!(
            "Answered {code} to a request without a proof (401 is what a running relayer answers)."
        ),
        None => "No answer to a request without a proof.".to_string(),
    };
    summary.push(vec![
        strong("Relayer."),
        t(format!(
            " {up} Checked {}. It holds {}.",
            date(reach["checkedAt"].as_u64().unwrap_or(0)),
            eth(wei)
        )),
    ]);
    relayer_queries.extend(pre(
        "relay-reach",
        format!("curl -s -o /dev/null -w '%{{http_code}}\\n' -X POST {} -H 'content-type: application/json' -d '{{}}'", reach["url"].as_str().unwrap_or("")),
    ));
    let mut relayed_rows = Vec::new();
    for (i, v) in s["vaults"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        for e in v["events"].as_array().cloned().unwrap_or_default() {
            if e["sentBy"] == st.relayer.as_str() {
                relayed_rows.push(vec![
                    vec![t(e["event"].as_str().unwrap_or("").to_string())],
                    vec![code(short(v["address"].as_str().unwrap_or("")))],
                    vec![t(e["block"].to_string())],
                    vec![tx_link(m, e["transaction"].as_str().unwrap_or(""))],
                ]);
            }
        }
        let _ = i;
    }
    let vault_events = relayed_rows.len();
    let sweeps: Vec<Value> = s["sweeps"].as_array().cloned().unwrap_or_default();
    for e in &sweeps {
        relayed_rows.push(vec![
            vec![t(format!(
                "USDC transfer out of a paid seller (a sweep), {}",
                usdc(n(&e["amount"]))
            ))],
            vec![code(short(&m.token.address))],
            vec![t(e["block"].to_string())],
            vec![tx_link(m, e["transaction"].as_str().unwrap_or(""))],
        ]);
    }
    // One relayed transaction can carry one vault event (fund, settle,
    // claim); a sweep carries one transfer.
    let found: std::collections::BTreeSet<String> = relayed_rows
        .iter()
        .filter_map(|row| match row.get(3).and_then(|c| c.first()) {
            Some(crate::doc::Inline::CodeLink { href, .. }) => Some(href.clone()),
            _ => None,
        })
        .collect();
    let sent = s["relayerNonce"].as_u64().unwrap_or(0);
    blocks.push(p(vec![t(format!(
        "The relayer's wallet sent {} transactions: {vault_events} events on the vaults {} and {} sweep(s) out of addresses a vault paid. Its transaction count at block {block} is {sent}{}.",
        found.len(),
        st.vaults.iter().map(|v| v.address.as_str()).collect::<Vec<_>>().join(", "),
        sweeps.len(),
        if sent as usize == found.len() {
            ", so every one is listed".to_string()
        } else {
            format!("; {} are not identified here", (sent as usize).saturating_sub(found.len()))
        }
    ))]));
    relayer_queries.extend(pre(
        "relayer-nonce",
        curl(rpc_url, &read("relayer-nonce"), st),
    ));
    // Each sweep found, by its own transaction: the receipt's Transfer log
    // names the payee and its sender is the relayer. Runs as it is.
    for (k, e) in sweeps.iter().enumerate() {
        let tx = e["transaction"].as_str().unwrap_or("");
        relayer_queries.extend(pre(
            &format!("sweep{k}-receipt"),
            format!(
                "curl -s {rpc_url} -H 'content-type: application/json' \\\n  -d '{}'",
                json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx]})
            ),
        ));
    }
    // The search that found them names a payee the page does not publish, so
    // it is shown as a template, without a copy control.
    let sweep_reads = log_reads("sweeps");
    if !sweep_reads.is_empty() {
        relayer_queries.push(para(
            "Search templates (PAYEE: topic 1 of a Claimed event, padded to 64 hex digits):",
        ));
        for r in sweep_reads {
            relayer_queries.push(Block::Pre {
                id: format!("q-{}", r["id"].as_str().unwrap_or("sweeps")),
                text: curl(rpc_url, &r, st),
                copy: None,
            });
        }
    }
    if !relayed_rows.is_empty() {
        blocks.push(Block::Table {
            caption: "Transactions the relayer sent: vault events and sweeps".into(),
            head: ["Event", "Vault", "Block", "Transaction"]
                .map(String::from)
                .to_vec(),
            rows: relayed_rows,
        });
    }
    blocks.push(queries(relayer_queries));
    for (index, v) in s["vaults"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .skip(1)
    {
        let address = v["address"].as_str().unwrap_or("");
        let mut queries = vec![para(&format!(
            "The earlier vault {address} holds {} unclaimed at block {block}.",
            usdc(n(&v["usdcHeld"])),
        ))];
        for r in log_reads(&format!("vault{index}-logs")) {
            queries.extend(pre(
                r["id"].as_str().unwrap_or("vault"),
                curl(rpc_url, &r, st),
            ));
        }
        queries.extend(pre(
            &format!("vault{index}-usdc"),
            curl(rpc_url, &read(&format!("vault{index}-usdc")), st),
        ));
        blocks.push(Block::Details {
            summary: format!("Queries for the earlier vault {}", short(address)),
            blocks: queries,
        });
    }
    blocks.push(para(
        "Not shown: the relayer's gas budget, in memory, not on chain.",
    ));
    blocks.insert(summary_at, Block::Ul(summary));
    let data = json!({
        "status": {
            "rpc": m.network.rpc,
            "chainId": m.network.chain_id,
            "token": m.token.address,
            "decimals": m.token.decimals,
            "buyer": if st.publish_wallets { json!(st.buyer) } else { Value::Null },
            "relayer": if st.publish_wallets { json!(st.relayer) } else { Value::Null },
            "vault": m.vault.address,
        }
    });
    Some(doc(blocks, Some(data)))
}

fn doc(blocks: Vec<Block>, data: Option<Value>) -> Doc {
    Doc {
        path: STATUS_PATH.into(),
        title: "Status — QED".into(),
        description: "The bounty, the vault's books and the gas relayer on Base, each number read from the chain at one block with the query that reproduces it.".into(),
        heading: "Status".into(),
        blocks,
        script: data.is_some(),
        data: data.map(|d| ("site-data".into(), d.to_string())),
    }
}

// ---- What a served page must keep -------------------------------------------

/// Element ids every status page carries: its sections and the reads that
/// reproduce its values. `check-live` requires each on the served page.
pub const REQUIRED_IDS: [&str; 13] = [
    "status-source",
    "source",
    "bounty",
    "deliveries",
    "payouts",
    "relayer",
    "q-block",
    "q-board-logs-0",
    "q-buyer-usdc",
    "q-vault0-usdc",
    "q-relayer-eth",
    "q-relayer-nonce",
    "q-relay-reach",
];
/// The balance cells (`data-read`), which the page's script also fills.
pub const REQUIRED_CELLS: [&str; 3] = ["buyer-usdc", "relayer-eth", "vault0-usdc"];

/// Every address in a text, lower case without `0x`: a run of exactly 40
/// hex digits, or a 32-byte word (in a run of words, after a 4-byte
/// selector or not) whose first 12 bytes are zero, which is how calldata
/// and log topics carry one.
pub fn addresses(text: &str) -> BTreeSet<String> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let run = &lower[start..i];
        if run.len() == 40 {
            out.insert(run.to_owned());
            continue;
        }
        let words = match run.len() % 64 {
            _ if run.len() < 64 => continue,
            0 => run,
            8 => &run[8..],
            _ => continue,
        };
        for k in 0..words.len() / 64 {
            let word = &words[k * 64..(k + 1) * 64];
            let (zeros, tail) = word.split_at(24);
            if zeros.bytes().all(|b| b == b'0') && !tail.bytes().all(|b| b == b'0') {
                out.insert(tail.to_owned());
            }
        }
    }
    out
}

/// The addresses a status page may name: the main network's contracts, and
/// the bounty buyer and the relayer when the input publishes them (owner
/// decision, 2026-11-14: "publish buyer and relayer only").
pub fn allowed_addresses(input: &Input) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(m) = input.mainnet.as_ref() else {
        return out;
    };
    let mut add = |a: &str| {
        out.insert(a.trim_start_matches("0x").to_ascii_lowercase());
    };
    for a in [
        &m.board.address,
        &m.vault.address,
        &m.registry.address,
        &m.verifier.address,
        &m.token.address,
    ] {
        add(a);
    }
    if let Some(st) = m.status.as_ref() {
        for v in &st.vaults {
            add(&v.address);
        }
        if st.publish_wallets {
            add(&st.buyer);
            add(&st.relayer);
            if let Some(ladder) = &st.ladder_buyer {
                add(ladder);
            }
        }
    }
    out
}

/// Addresses in `text` that a status page may not name.
pub fn foreign_addresses(input: &Input, text: &str) -> Vec<String> {
    let allowed = allowed_addresses(input);
    addresses(text)
        .into_iter()
        .filter(|a| !allowed.contains(a))
        .collect()
}

const MAIN_OPEN: &str = "<main id=\"main\">";
const MAIN_CLOSE: &str = "</main>";

/// (before `<main>`, inside, from `</main>`), when the page has one main.
fn html_frame(page: &str) -> Option<(&str, &str, &str)> {
    let open = page.find(MAIN_OPEN)? + MAIN_OPEN.len();
    let close = page.rfind(MAIN_CLOSE)?;
    (open <= close && page.matches(MAIN_OPEN).count() == 1)
        .then(|| (&page[..open], &page[open..close], &page[close..]))
}

/// (heading and description, body, closing index line) of a document's
/// Markdown (`doc::markdown`).
fn markdown_frame(md: &str) -> Option<(&str, &str, &str)> {
    let mut paragraphs = md.match_indices("\n\n");
    paragraphs.next()?;
    let head = paragraphs.next()?.0 + 2;
    let foot = md.rfind("\n---\n\n")?;
    (head <= foot).then(|| (&md[..head], &md[head..foot], &md[foot..]))
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// The stamp a page carries: (block, block time, read time, sentence).
pub fn stamp(html: &str) -> Option<(u64, u64, u64, String)> {
    let at = html.find("id=\"status-source\"")?;
    let tag_start = html[..at].rfind('<')?;
    let tag_end = at + html[at..].find('>')?;
    let tag = &html[tag_start..tag_end];
    let attr = |name: &str| -> Option<u64> {
        let key = format!(" {name}=\"");
        let from = tag.find(&key)? + key.len();
        tag[from..].split('"').next()?.parse().ok()
    };
    let text_end = tag_end + 1 + html[tag_end + 1..].find("</p>")?;
    Some((
        attr("data-block")?,
        attr("data-block-time")?,
        attr("data-read-at")?,
        unescape(&html[tag_end + 1..text_end]),
    ))
}

/// What is wrong with a served status page (HTML and Markdown) against the
/// release's built one, at `now`: the frame must be the build's byte for
/// byte, every required section and read present, the values at most
/// `MAX_AGE_SECONDS` old, and no address the built page does not name.
/// The values themselves are not compared: each carries its query
/// (docs/rfcs/qed-status-refresh-2026-11-17.md §7).
pub fn check_served(
    built_html: &str,
    built_md: &str,
    served_html: &str,
    served_md: &str,
    now: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    let main = match (html_frame(built_html), html_frame(served_html)) {
        (Some((bp, _, bs)), Some((sp, sm, ss))) => {
            if bp != sp {
                out.push("the head or masthead is not the release's".into());
            }
            if bs != ss {
                out.push("the footer or data block is not the release's".into());
            }
            sm
        }
        (None, _) => {
            out.push("the built page has no single <main>".into());
            served_html
        }
        (_, None) => {
            out.push("the served page has no single <main id=\"main\">".into());
            served_html
        }
    };
    match (markdown_frame(built_md), markdown_frame(served_md)) {
        (Some((bh, _, bf)), Some((sh, _, sf))) => {
            if bh != sh {
                out.push("the Markdown heading or description is not the release's".into());
            }
            if bf != sf {
                out.push("the Markdown index line is not the release's".into());
            }
        }
        _ => out.push("the Markdown has no heading, description and index line".into()),
    }
    for id in REQUIRED_IDS {
        if !main.contains(&format!("id=\"{id}\"")) {
            out.push(format!("no element with id {id}"));
        }
    }
    for cell in REQUIRED_CELLS {
        if !main.contains(&format!("data-read=\"{cell}\"")) {
            out.push(format!("no balance cell {cell}"));
        }
    }
    match stamp(main) {
        None => out.push("no stamp (data-block, data-block-time, data-read-at)".into()),
        Some((block, made, read, sentence)) => {
            if made + MAX_AGE_SECONDS < now {
                out.push(format!(
                    "the values are from block {block}, {} minutes old; the limit is {}",
                    (now - made) / 60,
                    MAX_AGE_SECONDS / 60
                ));
            }
            if read > now + CLOCK_SKEW_SECONDS {
                out.push(format!("read time {read} is in the future"));
            }
            if !served_md.contains(&sentence) {
                out.push("the Markdown does not carry the HTML's stamp sentence".into());
            }
        }
    }
    let built: BTreeSet<String> = addresses(built_html)
        .union(&addresses(built_md))
        .cloned()
        .collect();
    for a in addresses(served_html).union(&addresses(served_md)) {
        if !built.contains(a) {
            out.push(format!(
                "an address the built page does not name: 0x{}…",
                &a[..8]
            ));
        }
    }
    out
}

// ---- The host's reader --------------------------------------------------------

/// The snapshot `refresh` keeps beside the pages, and the pages it writes,
/// relative to its state directory.
pub const LAST_GOOD: &str = "status.snapshot.json";
pub const SERVED_MD: &str = "site/status/index.md";
pub const SERVED_HTML: &str = "site/status/index.html";

/// What one pass decided.
#[derive(Debug)]
pub struct Pass {
    /// The new snapshot to keep, after a successful read.
    pub snapshot: Option<Value>,
    /// (Markdown, HTML) to serve; none when there is nothing good to show.
    pub pages: Option<(String, String)>,
    /// The read's error, when it failed.
    pub failure: Option<String>,
}

fn render(input: &Input, snap: &Value, source: Source, site_url: &str) -> Res<(String, String)> {
    let d = page_from(input, Some(snap), source).ok_or("the input has no status page")?;
    let site = site_url.trim_end_matches('/');
    let html = crate::doc::page(&d, Some(site), &crate::pages::footer());
    let md = crate::doc::markdown(&d, Some(site));
    let foreign = foreign_addresses(input, &format!("{md}\n{html}"));
    if !foreign.is_empty() {
        return Err(format!(
            "refused: the page would name {} address(es) the input does not publish",
            foreign.len()
        )
        .into());
    }
    Ok((md, html))
}

/// One pass of the reader, without effects: `read` is `snapshot`'s result.
/// A good read is rendered and kept; a failed one re-renders the last good
/// snapshot saying the read failed and how old the values were; with
/// neither, nothing is served (Caddy falls back to the release's page). The
/// build's signed delivery record is carried with its own read time.
pub fn pass(
    input: &Input,
    site_url: &str,
    build: Option<&Value>,
    last_good: Option<&Value>,
    read: Res<Value>,
    now: u64,
) -> Res<Pass> {
    match read {
        Ok(mut snap) => {
            snap["deliveries"] = build
                .map(|b| b["deliveries"].clone())
                .filter(|d| d.is_object())
                .unwrap_or_else(|| json!({"jws": null, "readAt": null}));
            let pages = render(
                input,
                &snap,
                Source::Refreshed { failed_at: None },
                site_url,
            )?;
            Ok(Pass {
                snapshot: Some(snap),
                pages: Some(pages),
                failure: None,
            })
        }
        Err(e) => {
            let pages = last_good
                .map(|s| {
                    render(
                        input,
                        s,
                        Source::Refreshed {
                            failed_at: Some(now),
                        },
                        site_url,
                    )
                })
                .transpose()?;
            Ok(Pass {
                snapshot: None,
                pages,
                failure: Some(e.to_string()),
            })
        }
    }
}

/// Write `bytes` to `path` by a synced temporary file in the same directory
/// and a rename, so a reader sees the old file or the new one.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Res<()> {
    use std::io::Write;
    let dir = path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(&tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json(path: &Path) -> Res<Option<Value>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display()).into()),
    }
}

/// `nucleus-site refresh-status INPUT STATE_DIR SITE_URL`: read the chain
/// now, and write `STATE_DIR/status.snapshot.json` (0600) and the page's
/// Markdown, then HTML, under `STATE_DIR/site/status/` (0644). The build's
/// snapshot beside INPUT supplies only the delivery record. Returns the
/// read's failure, if any, after writing what `pass` decided.
pub fn refresh(input_path: &Path, state: &Path, site_url: &str, now: u64) -> Res<Pass> {
    if !site_url.starts_with("https://") {
        return Err("SITE_URL must be an https URL".into());
    }
    let input = Input::read(input_path)?;
    let build = read_json(
        &input_path
            .parent()
            .ok_or("input path")?
            .join("status.snapshot.json"),
    )?;
    let last_good = read_json(&state.join(LAST_GOOD))?;
    let read = snapshot(&input, now, None);
    let decided = pass(
        &input,
        site_url,
        build.as_ref(),
        last_good.as_ref(),
        read,
        now,
    )?;
    if let Some(snap) = &decided.snapshot {
        write_atomic(
            &state.join(LAST_GOOD),
            (serde_json::to_string_pretty(snap)? + "\n").as_bytes(),
            0o600,
        )?;
    }
    if let Some((md, html)) = &decided.pages {
        write_atomic(&state.join(SERVED_MD), md.as_bytes(), 0o644)?;
        write_atomic(&state.join(SERVED_HTML), html.as_bytes(), 0o644)?;
    }
    Ok(decided)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input::read(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/input/arbitrum-sepolia.json"
        )))
        .unwrap()
    }
    fn committed() -> Value {
        serde_json::from_str(include_str!("../input/status.snapshot.json")).unwrap()
    }
    const SITE: &str = "https://qed.example.test";
    const OTHER: [&str; 4] = [
        "0xd15c105ed0d15c105ed0d15c105ed0d15c105ed0",
        "0x5e11e50000000000000000000000000000000abc",
        "0x0123456789abcdef0123456789abcdef01234567",
        "0xfeedfacefeedfacefeedfacefeedfacefeedface",
    ];

    /// The committed snapshot with every elided wallet replaced by another
    /// wallet, as if `published` had not run: posters, post vaults,
    /// senders, buyers, sellers and payees.
    fn unelided() -> Value {
        let text = serde_json::to_string(&committed())
            .unwrap()
            .replace(&format!("\"{ELIDED}\""), &format!("\"{}\"", OTHER[0]));
        let mut s: Value = serde_json::from_str(&text).unwrap();
        for p in s["posts"].as_array_mut().unwrap() {
            p["vault"] = json!(OTHER[1]);
        }
        for v in s["vaults"].as_array_mut().unwrap() {
            for e in v["events"].as_array_mut().unwrap() {
                e["sentBy"] = json!(OTHER[2]);
                if e["event"] == "Claimed" {
                    e["payee"] = json!(OTHER[3]);
                }
            }
        }
        s
    }

    #[test]
    fn addresses_are_found_bare_and_in_words() {
        let a = "d15c105ed0d15c105ed0d15c105ed0d15c105ed0";
        assert!(addresses(&format!("x 0x{a} y")).contains(a));
        assert!(addresses(&format!("\"0x70a08231{:0>64}\"", a)).contains(a));
        assert!(addresses(&format!("[\"0x{:0>64}\"]", a.to_uppercase())).contains(a));
        // A transaction hash and a short form are not addresses.
        assert!(addresses(&format!("0x{a}{a}abcdefabcdefabcdefabcdef")).is_empty());
        assert!(addresses("0x952c31aa20…6fa39a6b").is_empty());
    }

    /// Owner decision 2026-11-14 holds on every refresh: a snapshot naming
    /// other wallets everywhere it can renders none of them.
    #[test]
    fn a_snapshot_naming_other_wallets_renders_none_of_them() {
        let i = input();
        let snap = unelided();
        assert!(
            serde_json::to_string(&snap)
                .unwrap()
                .contains(&OTHER[3][2..])
        );
        for source in [
            Source::Build,
            Source::Refreshed { failed_at: None },
            Source::Refreshed {
                failed_at: Some(snap["takenAt"].as_u64().unwrap() + 3600),
            },
        ] {
            let (md, html) = render(&i, &snap, source, SITE).unwrap();
            for page in [&md, &html] {
                assert_eq!(foreign_addresses(&i, page), Vec::<String>::new());
                for o in OTHER {
                    assert!(!page.contains(&o[2..]), "{o} on the page");
                }
            }
        }
        // Red: a snapshot value the page prints verbatim (the endpoint)
        // carrying another wallet: the reader refuses to write the page.
        let mut carried = committed();
        carried["rpc"] = json!(format!("https://rpc.example.test/{}", OTHER[1]));
        let refused = pass(&i, SITE, None, None, Ok(carried), 0).unwrap_err();
        assert!(
            refused.to_string().contains("does not publish"),
            "{refused}"
        );
        // The same guard on a page with one planted wallet.
        let (_, html) = render(&i, &snap, Source::Build, SITE).unwrap();
        let planted = html.replacen("<h2", &format!("<p>{}</p><h2", OTHER[2]), 1);
        assert_eq!(
            foreign_addresses(&i, &planted),
            vec![OTHER[2][2..].to_string()]
        );
    }

    #[test]
    fn the_page_says_where_its_values_come_from_and_how_old_they_are() {
        let i = input();
        let s = committed();
        let read = s["takenAt"].as_u64().unwrap();
        let (md, html) = render(&i, &s, Source::Build, SITE).unwrap();
        assert!(md.contains(" by the build: block ") && md.contains(". Not refreshed."));
        assert!(!md.contains("build-time snapshot"));
        let (block, made, at, sentence) = stamp(&html).unwrap();
        assert_eq!(block, s["block"].as_u64().unwrap());
        assert_eq!(made, s["blockTimestamp"].as_u64().unwrap());
        assert_eq!(at, read);
        assert!(md.contains(&sentence));
        let (md, _) = render(&i, &s, Source::Refreshed { failed_at: None }, SITE).unwrap();
        assert!(md.contains("Reread every 10 minutes; stale after 30 minutes."));
        // The delivery record is the build's, and says so in both places.
        assert_eq!(md.matches(" As of the build").count(), 2, "{md}");
        let (md, _) = render(
            &i,
            &s,
            Source::Refreshed {
                failed_at: Some(read + 25 * 60),
            },
            SITE,
        )
        .unwrap();
        assert!(md.contains("Reread failed at "));
        assert!(md.contains(", 25 minutes later."));
    }

    #[test]
    fn a_pass_keeps_a_good_read_and_otherwise_the_last_good_values_with_their_age() {
        let i = input();
        let build = committed();
        let mut read = committed();
        read["block"] = json!(read["block"].as_u64().unwrap() + 300);
        read["deliveries"] = json!({"jws": null, "readAt": 1});
        let now = read["takenAt"].as_u64().unwrap() + 600;
        let good = pass(&i, SITE, Some(&build), None, Ok(read.clone()), now).unwrap();
        let kept = good.snapshot.unwrap();
        // The build's delivery record, with the build's read time.
        assert_eq!(kept["deliveries"], build["deliveries"]);
        assert_eq!(kept["block"], read["block"]);
        assert!(good.failure.is_none());
        let (_, html) = good.pages.unwrap();
        assert_eq!(stamp(&html).unwrap().0, read["block"].as_u64().unwrap());

        let failed = pass(
            &i,
            SITE,
            Some(&build),
            Some(&kept),
            Err("timeout".into()),
            now,
        )
        .unwrap();
        assert!(failed.snapshot.is_none());
        assert_eq!(failed.failure.as_deref(), Some("timeout"));
        let (md, html) = failed.pages.unwrap();
        assert_eq!(stamp(&html).unwrap().0, read["block"].as_u64().unwrap());
        assert!(md.contains("Reread failed at "));
        assert!(
            !md.contains("timeout"),
            "the error goes to the journal only"
        );

        let nothing = pass(&i, SITE, Some(&build), None, Err("timeout".into()), now).unwrap();
        assert!(nothing.pages.is_none() && nothing.snapshot.is_none());
    }

    #[test]
    fn writes_replace_the_file_whole() {
        let dir = std::env::temp_dir().join(format!("nucleus-site-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("site/status/index.html");
        write_atomic(&path, b"one", 0o644).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let left: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `check-live`'s rule for `/status`, each check driven red on the defect
    /// it exists for, then green on a fresh refreshed page.
    #[test]
    fn a_served_status_page_is_checked_for_frame_structure_age_and_addresses() {
        let i = input();
        let s = committed();
        let (bmd, bhtml) = render(&i, &s, Source::Build, SITE).unwrap();
        let mut fresh = s.clone();
        fresh["block"] = json!(s["block"].as_u64().unwrap() + 1000);
        let made = s["blockTimestamp"].as_u64().unwrap() + 2000;
        fresh["blockTimestamp"] = json!(made);
        fresh["takenAt"] = json!(made + 5);
        let (md, html) = render(&i, &fresh, Source::Refreshed { failed_at: None }, SITE).unwrap();
        let now = made + 600;
        assert_eq!(
            check_served(&bhtml, &bmd, &html, &md, now),
            Vec::<String>::new()
        );
        let has = |f: Vec<String>, what: &str| {
            assert!(f.iter().any(|x| x.contains(what)), "{what} not in {f:?}");
        };
        // Red: stale (the build-time page, served days later).
        has(
            check_served(&bhtml, &bmd, &bhtml, &bmd, now + 86_400),
            "minutes old; the limit is 30",
        );
        has(
            check_served(&bhtml, &bmd, &html, &md, made + MAX_AGE_SECONDS + 60),
            "minutes old",
        );
        // Red: a missing read.
        has(
            check_served(
                &bhtml,
                &bmd,
                &html.replace("id=\"q-relayer-nonce\"", "id=\"x\""),
                &md,
                now,
            ),
            "no element with id q-relayer-nonce",
        );
        // Red: an extra address, in either form.
        let planted = html.replacen("<h2", &format!("<p>{}</p><h2", OTHER[0]), 1);
        has(
            check_served(&bhtml, &bmd, &planted, &md, now),
            "an address the built page does not name",
        );
        has(
            check_served(&bhtml, &bmd, &html, &format!("{md}\n{}", OTHER[1]), now),
            "an address the built page does not name",
        );
        // Red: another frame (a refresher from another commit).
        has(
            check_served(
                &bhtml,
                &bmd,
                &html.replace("/qed.css", "/qed2.css"),
                &md,
                now,
            ),
            "head or masthead",
        );
        has(
            check_served(&bhtml, &bmd, &html, &md.replace("Index:", "Contents:"), now),
            "Markdown index line",
        );
        // Red: no stamp, and a Markdown twin from another read.
        has(
            check_served(
                &bhtml,
                &bmd,
                &html.replace("data-block-time", "data-x"),
                &md,
                now,
            ),
            "no stamp",
        );
        has(
            check_served(&bhtml, &bmd, &html, &bmd, now),
            "stamp sentence",
        );
    }
}
