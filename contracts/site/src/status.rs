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
//! Addresses other than the contracts, the bounty buyer and the relayer are
//! not written to the snapshot: they are stored as "elided". The queries
//! return them to anyone who runs them.
use crate::doc::{Block, Doc, Line, code, code_link, h2, link, p, para, strong, t};
use crate::html::{self, Html};
use crate::ledger::rpc;
use crate::pages::{date, short};
use crate::{Input, Mainnet, Res, StatusInput, amount, hex, unhex};
use alloy_primitives::keccak256;
use serde_json::{Value, json};

pub const SNAPSHOT_PATH: &str = "contracts/site/input/status.snapshot.json";
pub const ELIDED: &str = "elided";

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
    if a == st.buyer || a == st.relayer {
        a
    } else {
        ELIDED.into()
    }
}

/// Read the main network's bounty, vaults and relayer at the latest block.
pub fn snapshot(input: &Input, now: u64) -> Res<Value> {
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
        "reads": r.reads,
    }))
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

pub fn page(input: &Input, snap: Option<&Value>) -> Option<Doc> {
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
    let mut blocks = vec![para(
        "Every number on this page is read from the chain at one block. Each comes with the JSON-RPC call that reproduces it, so anyone can run the same query against any Base endpoint and compare.",
    )];
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
    let pre = |id: &str, text: String| Block::Pre {
        id: format!("q-{id}"),
        text,
        copy: Some("Copy".into()),
    };
    let log_reads = |prefix: &str| -> Vec<Value> {
        reads
            .iter()
            .filter(|r| r["id"].as_str().is_some_and(|i| i.starts_with(prefix)))
            .cloned()
            .collect()
    };

    // Which values the reader is looking at.
    let source = format!(
        "Showing the build-time snapshot: block {block} on {} (chain {}), {}, read from {rpc_url}.",
        m.network.name,
        m.network.chain_id,
        date(now)
    );
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
    blocks.push(h2("source", "What you are looking at"));
    blocks.push(Block::Rendered {
        html: Html::join([
            html::tx(
                "p",
                &[("id", "status-source"), ("aria-live", "polite")],
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
    blocks.push(pre("block", curl(rpc_url, &read("block"), st)));

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
    let mut line = vec![t("Posted by the bounty buyer, ")];
    line.extend(wallet(&st.buyer, st, "bounty buyer"));
    line.push(t(format!(
        ", on the board {} in vault {}: {} per task, at most {} tasks, {} in all (the offer is the authors' configuration; the ",
        m.board.address, m.vault.address, usdc(u128::from(b.price)), b.tasks, usdc(u128::from(b.budget))
    )));
    line.push(link("/bounty", "bounty page"));
    line.push(t(" has the terms)."));
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
    blocks.push(p(vec![strong(format!(
        "{} posts on the board, {open} open at block {block}.",
        posts.len()
    ))]));
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
    for r in log_reads("board-logs") {
        blocks.push(pre(
            r["id"].as_str().unwrap_or("board"),
            curl(rpc_url, &r, st),
        ));
    }
    blocks.push(p(vec![
        strong(format!("Remaining: {remaining_tasks} of {} tasks, {} of {}.", b.tasks, usdc(u128::from(b.budget).saturating_sub(spent)), usdc(u128::from(b.budget)))),
        t(format!(
            " Derived, not read: the tasks the buyer has paid for are its Funded events on the vault less its Refunded events ({} funded, {} refunded); the budget left is {} less what those deposits total. The buyer's own count lives in its journal, which is not on chain.",
            buyer_funded.len(),
            buyer_refunded.len(),
            usdc(u128::from(b.budget))
        )),
    ]));
    let mut fund = vec![
        strong(format!("Funding: {}", usdc(n(&s["buyerUsdc"])))),
        t(" held by the bounty buyer (USDC balanceOf at block "),
        t(format!("{block}).")),
    ];
    if n(&s["buyerUsdc"]) < u128::from(b.price) {
        fund.push(t(" That is less than one task's price, so the buyer cannot fund an order until it is topped up."));
    }
    blocks.push(p(fund));
    blocks.push(pre("buyer-usdc", curl(rpc_url, &read("buyer-usdc"), st)));

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
    blocks.push(Block::Ul(vec![
        vec![t(format!("Deposits held for orders not yet settled or refunded: {} (Funded less the deposits of settled and refunded orders).", usdc(held_deposits)))],
        vec![t(format!("Booked and not yet claimed: {} (each Settled event's seller, fee and royalty shares, plus refunds, less Claimed).", usdc(owed)))],
        vec![t(format!(
            "USDC the vault holds: {}. {}",
            usdc(holds),
            if holds == held_deposits + owed { "It equals the two lines above." } else { "It does not equal the two lines above: a transfer to the vault outside fund, or an event this page does not read." }
        ))],
    ]));
    for r in log_reads("vault0-logs") {
        blocks.push(pre(
            r["id"].as_str().unwrap_or("vault"),
            curl(rpc_url, &r, st),
        ));
    }
    blocks.push(pre("vault0-usdc", curl(rpc_url, &read("vault0-usdc"), st)));

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
        ". It holds {} at block {block}; its floor is {}, set as {}. {}",
        eth(wei),
        eth(floor),
        st.relayer_floor_source,
        if wei > floor {
            format!("It can spend {} before it refuses.", eth(wei - floor))
        } else {
            "At or below its floor it refuses every call.".into()
        }
    )));
    blocks.push(p(line));
    blocks.push(pre("relayer-eth", curl(rpc_url, &read("relayer-eth"), st)));
    let reach = &s["relayerReach"];
    blocks.push(p(vec![
        strong(match reach["answer"]["status"].as_u64() {
            Some(401) => "Up: a request without a proof was refused with 401.".to_string(),
            Some(code) => format!("Answered {code} to a request without a proof (401 is what a running relayer answers)."),
            None => "No answer to a request without a proof.".to_string(),
        }),
        t(format!(" Checked {} from the machine that built this page. Run it yourself; 401 means up:", date(reach["checkedAt"].as_u64().unwrap_or(0)))),
    ]));
    blocks.push(pre(
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
        "Relayed transactions: {vault_events} events on the vaults the relayer serves ({}) and {} sweep(s) were in transactions sent by the relayer's wallet: {} transactions. Each event's transaction was read with eth_getTransactionByHash and its from field compared; a sweep is a USDC Transfer out of an address a vault paid (the payee of a Claimed event), from its first claim on. The wallet has sent {sent} transactions in all (eth_getTransactionCount at block {block}){}.",
        st.vaults.iter().map(|v| v.address.as_str()).collect::<Vec<_>>().join(", "),
        sweeps.len(),
        found.len(),
        if sent as usize == found.len() {
            ", so every one is listed here".to_string()
        } else {
            format!("; {} are not identified on this page", (sent as usize).saturating_sub(found.len()))
        }
    ))]));
    blocks.push(pre(
        "relayer-nonce",
        curl(rpc_url, &read("relayer-nonce"), st),
    ));
    for r in log_reads("sweeps") {
        blocks.push(pre(
            r["id"].as_str().unwrap_or("sweeps"),
            curl(rpc_url, &r, st),
        ));
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
            "The earlier vault {address} holds {} at block {block}: shares booked there and not yet claimed. Its events, in ranges of at most {} blocks (what the endpoint answers in one call):",
            usdc(n(&v["usdcHeld"])),
            m.network.log_range.unwrap_or(10_000)
        ))];
        for r in log_reads(&format!("vault{index}-logs")) {
            queries.push(pre(
                r["id"].as_str().unwrap_or("vault"),
                curl(rpc_url, &r, st),
            ));
        }
        queries.push(pre(
            &format!("vault{index}-usdc"),
            curl(rpc_url, &read(&format!("vault{index}-usdc")), st),
        ));
        blocks.push(Block::Details {
            summary: format!("Queries for the earlier vault {}", short(address)),
            blocks: queries,
        });
    }
    blocks.push(para(
        "Not shown as fact: how much of its per-restart gas budget the relayer has left. That counter lives in the relayer's memory, resets when it restarts, and is not on chain.",
    ));
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
        path: "status".into(),
        title: "Status — QED".into(),
        description: "The bounty, the vault's books and the gas relayer on Base, each number read from the chain at one block with the query that reproduces it.".into(),
        heading: "Status".into(),
        blocks,
        script: data.is_some(),
        data: data.map(|d| ("site-data".into(), d.to_string())),
    }
}
