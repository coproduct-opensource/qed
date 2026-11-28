//! What the market index shows: rounds, posts with their joined orders,
//! `market.json`, and the `/market` page. Built from a filtered index only.
use super::promotion::{self, Match, PromotionInput};
use super::{Event, Index, Market, ModelPost, Round, model_events, word};
use crate::doc::{Block, Doc, Line, code, code_link, h2, link, p, para, strong, t};
use crate::html::{self, Html};
use crate::pages::{date, short};
use crate::status::{ELIDED, Source};
use crate::{Input, Mainnet, amount};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// The page's path, and the data file beside it, both rewritten by the
/// host's reader.
pub const MARKET_PATH: &str = "market";
pub const JSON_PATH: &str = "market/market.json";
pub const JSON_SCHEMA: &str = "qed-market/1";

/// One round's numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundView {
    pub name: String,
    pub price: u64,
    pub budget: u64,
    pub tasks: u32,
    pub opened: String,
    /// The block of its first post, read from the chain.
    pub start_block: Option<u64>,
    pub funded: u128,
    pub refunded: u128,
    pub funded_tasks: u64,
    pub refunded_tasks: u64,
    pub settled_tasks: u64,
    /// `None`: funded beyond the budget net of refunds.
    pub remaining: Option<u128>,
    pub remaining_tasks: Option<u64>,
}

/// What the site already serves for a post or order.
#[derive(Clone, Debug, Default)]
pub struct Known {
    /// Order digests with a receipt (`/transactions/<digest>`), lower case.
    pub receipts: BTreeSet<String>,
    /// Artifact keccak-256 values served at `/artifacts/<hash>.bin`, no 0x.
    pub artifacts: BTreeSet<String>,
    /// Statement SHA-256 (no 0x) → file name under `/statements/`.
    pub statements: BTreeMap<String, String>,
}

impl Known {
    pub fn from_ledger(s: &crate::ledger::Snapshot) -> Known {
        Known {
            receipts: s
                .receipts()
                .iter()
                .filter_map(|r| r["id"].as_str().map(str::to_ascii_lowercase))
                .collect(),
            artifacts: s.artifacts.iter().map(|(k, _)| k.clone()).collect(),
            statements: s
                .statements
                .iter()
                .map(|(f, _)| (f.split('.').next().unwrap_or("").to_owned(), f.clone()))
                .collect(),
        }
    }
    /// From `ledger.snapshot.json` beside the input, when it is there and reads.
    pub fn from_input_dir(dir: &std::path::Path) -> Known {
        crate::ledger::Snapshot::read(&dir.join("ledger.snapshot.json"))
            .map(|s| Known::from_ledger(&s))
            .unwrap_or_default()
    }
}

fn round_starts(index: &Index, m: &Mainnet) -> Vec<Option<u64>> {
    m.bounty
        .rounds
        .iter()
        .map(|r| {
            index.events.iter().find_map(|l| match &l.event {
                Event::Posted { id, .. } if id.eq_ignore_ascii_case(&r.first_task) => Some(l.block),
                _ => None,
            })
        })
        .collect()
}

/// Which round a post of `buyer` belongs to, by its block.
fn round_of(starts: &[Option<u64>], buyer: &str, p: &ModelPost) -> Option<usize> {
    if !p.poster.eq_ignore_ascii_case(buyer) {
        return None;
    }
    let mut found = None;
    for (k, s) in starts.iter().enumerate() {
        if let Some(s) = s
            && p.block >= *s
        {
            found = Some(k);
        }
    }
    found
}

pub fn rounds(index: &Index, now: u64, m: &Mainnet, buyer: &str) -> Vec<RoundView> {
    let market = Market::replay(&model_events(index, now));
    let starts = round_starts(index, m);
    m.bounty
        .rounds
        .iter()
        .enumerate()
        .map(|(k, r)| {
            let member = |p: &ModelPost| round_of(&starts, buyer, p) == Some(k);
            let round = Round {
                budget: u128::from(r.budget),
                tasks: u64::from(r.tasks),
                member: &member,
            };
            let settled_tasks = market
                .posts
                .iter()
                .filter(|p| member(p))
                .map(|p| market.joined(p).filter(|o| o.phase.rank() >= 5).count() as u64)
                .sum();
            RoundView {
                name: r.name.clone(),
                price: r.price,
                budget: r.budget,
                tasks: r.tasks,
                opened: r.opened.clone(),
                start_block: starts[k],
                funded: market.funded_amount(&round),
                refunded: market.refund_amount(&round),
                funded_tasks: market.funded_tasks(&round),
                refunded_tasks: market.refund_tasks(&round),
                settled_tasks,
                remaining: market.remaining(&round),
                remaining_tasks: market.remaining_tasks(&round),
            }
        })
        .collect()
}

/// `market.json`: every post with its state, round and joined orders.
pub fn data(input: &Input, index: &Index, taken_at: u64) -> Value {
    let Some(m) = input.mainnet.as_ref() else {
        return Value::Null;
    };
    let buyer = m.status.as_ref().map_or("", |s| s.buyer.as_str());
    let now = index.cursor_time;
    let market = Market::replay(&model_events(index, now));
    let matches: Vec<Match> = m
        .promotion
        .as_ref()
        .map(|p| promotion::decide(index, p))
        .unwrap_or_default();
    let saved = super::savings::decide(index, &m.referrals);
    let starts = round_starts(index, m);
    // Per order: where it was funded, settled, refunded and claimed.
    let mut orders: BTreeMap<String, Value> = BTreeMap::new();
    let mut settled_at: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for l in &index.events {
        match &l.event {
            Event::Funded {
                digest,
                amount,
                payee_key,
                ..
            } => {
                orders.insert(
                    digest.clone(),
                    json!({"digest": digest, "vault": l.contract, "amount": amount,
                           "fundedIn": l.transaction, "fundedBlock": l.block}),
                );
                settled_at.insert(digest.clone(), (u64::MAX, payee_key.clone()));
            }
            Event::Settled {
                digest,
                artifact_hash,
                ..
            } => {
                if let Some(o) = orders.get_mut(digest) {
                    o["settledIn"] = json!(l.transaction);
                    o["artifactHash"] = json!(artifact_hash);
                }
                if let Some(s) = settled_at.get_mut(digest) {
                    s.0 = l.block;
                }
            }
            Event::Refunded { digest, .. } => {
                if let Some(o) = orders.get_mut(digest) {
                    o["refundedIn"] = json!(l.transaction);
                }
            }
            Event::Claimed { payee_key, .. } => {
                for (d, (at, key)) in &settled_at {
                    if key == payee_key
                        && *at <= l.block
                        && let Some(o) = orders.get_mut(d)
                        && o["claimedIn"].is_null()
                    {
                        o["claimedIn"] = json!(l.transaction);
                    }
                }
            }
            _ => {}
        }
    }
    let role = |poster: &str| -> &str {
        let st = m.status.as_ref();
        if st.is_some_and(|s| poster.eq_ignore_ascii_case(&s.buyer)) {
            "bounty buyer"
        } else if st
            .and_then(|s| s.ladder_buyer.as_deref())
            .is_some_and(|l| poster.eq_ignore_ascii_case(l))
        {
            "ladder buyer"
        } else if poster == ELIDED {
            "elided"
        } else {
            "other"
        }
    };
    let mut posts = Vec::new();
    for l in &index.events {
        let Event::Posted {
            id,
            poster,
            vault,
            statement_sha256,
            statement_blake3,
            policy_hash,
            asset,
            maximum_amount,
            verifier,
            program,
            fund_by,
            deliver_by,
            buyer_node,
            buyer_key_binding,
            salt,
            buyer_address,
        } = &l.event
        else {
            continue;
        };
        let Some(mp) = market.posts.iter().find(|p| super::hx(&p.id) == *id) else {
            continue;
        };
        let state = market.state(mp);
        let withdrawn_in = index.events.iter().find_map(|w| match &w.event {
            Event::Withdrawn { id: wid } if wid == id => Some(w.transaction.clone()),
            _ => None,
        });
        let joined: Vec<Value> = market
            .joined(mp)
            .map(|o| {
                let d = super::hx(&o.digest);
                let mut v = orders
                    .get(&d)
                    .cloned()
                    .unwrap_or_else(|| json!({"digest": d}));
                v["phase"] = json!(o.phase.name());
                if let Some(r) = saved.iter().find(|r| r.digest == o.digest) {
                    v["saving"] = saving_data(r);
                }
                v
            })
            .collect();
        let round = round_of(&starts, buyer, mp).map(|k| m.bounty.rounds[k].name.clone());
        let matched = matches.iter().find(|g| g.post == mp.id).map(|g| {
            json!({"amount": g.amount.to_string(), "seller": g.seller,
                   "order": super::hx(&g.digest), "block": g.block})
        });
        posts.push(json!({
            "id": id, "state": state.name(),
            "taken": market.taken(&word(statement_sha256)),
            "round": round, "poster": poster, "posterRole": role(poster), "vault": vault,
            "statementSha256": statement_sha256, "statementBlake3": statement_blake3,
            "policyHash": policy_hash, "asset": asset, "maximumAmount": maximum_amount,
            "verifier": verifier, "program": program, "fundBy": fund_by, "deliverBy": deliver_by,
            "buyerNode": buyer_node, "buyerKeyBinding": buyer_key_binding, "salt": salt,
            "buyerAddress": buyer_address, "block": l.block, "transaction": l.transaction,
            "withdrawnIn": withdrawn_in, "orders": joined,
            "matched": matched,
        }));
    }
    posts.reverse();
    let rounds: Vec<Value> = rounds(index, now, m, buyer)
        .into_iter()
        .map(|r| {
            json!({"name": r.name, "price": r.price.to_string(), "budget": r.budget.to_string(),
                   "tasks": r.tasks, "opened": r.opened, "startBlock": r.start_block,
                   "funded": r.funded.to_string(), "refunded": r.refunded.to_string(),
                   "fundedTasks": r.funded_tasks, "refundedTasks": r.refunded_tasks,
                   "settledTasks": r.settled_tasks,
                   "remaining": r.remaining.map(|x| x.to_string()),
                   "remainingTasks": r.remaining_tasks})
        })
        .collect();
    json!({
        "schema": JSON_SCHEMA,
        "chainId": index.chain_id,
        "board": index.board,
        "vaults": index.vaults,
        "block": index.cursor,
        "blockTimestamp": now,
        "takenAt": taken_at,
        "model": "proofs/commerce/Market.lean",
        "joinRule": "an order joins a post iff its context is keccak256(keccak256(\"NucleusContextV1\") || post id || buyerKeyBinding) and its policyHash is the post's",
        "rounds": rounds,
        "promotion": promotion_data(m, &matches),
        "savings": {"model": "proofs/commerce/Savings.lean",
                    "rule": "saving = maximumAmount - amount; 30 % to the referrer the order's salt binds, 20 % divided among the authors of reused lemmas, the rest to the buyer",
                    "authors": "not computed on this page: settlements carry no walked artifact here, so author shares read 0 and their 20 % as the buyer's"},
        "posts": posts,
    })
}

fn usdc(m: &Mainnet, units: u128) -> String {
    format!(
        "{} {}",
        amount(u64::try_from(units).unwrap_or(u64::MAX), m.token.decimals),
        m.token.name
    )
}

/// "Round r1: 0 of 5 tasks, 0 USDC of 5 USDC remain." for each round, the
/// open one first.
pub fn round_lines(m: &Mainnet, rounds: &[RoundView]) -> Vec<Line> {
    rounds
        .iter()
        .rev()
        .map(|r| {
            let left = match (r.remaining_tasks, r.remaining) {
                (Some(n), Some(a)) => format!(
                    "{n} of {} tasks, {} of {} remain",
                    r.tasks,
                    usdc(m, a),
                    usdc(m, u128::from(r.budget))
                ),
                _ => format!(
                    "funded {} in {} orders against a budget of {}: over budget",
                    usdc(m, r.funded - r.refunded),
                    r.funded_tasks - r.refunded_tasks,
                    usdc(m, u128::from(r.budget))
                ),
            };
            vec![
                strong(format!("Round {}: {left}.", r.name)),
                t(format!(
                    " {} a task; {} funded, {} refunded, {} settled.",
                    usdc(m, u128::from(r.price)),
                    r.funded_tasks,
                    r.refunded_tasks,
                    r.settled_tasks
                )),
            ]
        })
        .collect()
}

fn state_cell(m: &Mainnet, post: &Value) -> Line {
    let mut line = vec![t(post["state"].as_str().unwrap_or("").to_owned())];
    let settled = matches!(post["state"].as_str(), Some("settled" | "claimed"));
    if post["taken"] == true && !settled {
        line.push(t(", statement taken"));
    }
    if let Some(a) = post["matched"]["amount"].as_str() {
        line.push(t(format!(", matched +{}", usdc(m, a.parse().unwrap_or(0)))));
    }
    for o in post["orders"].as_array().into_iter().flatten() {
        let s = &o["saving"];
        let saved: u128 = s["saving"]
            .as_str()
            .and_then(|x| x.parse().ok())
            .unwrap_or(0);
        if saved > 0 {
            line.push(t(format!(", saved {}", usdc(m, saved))));
            if s["referrer"].is_string() {
                let share: u128 = s["split"]["referrer"]
                    .as_str()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(0);
                line.push(t(format!(" ({} of it to the referrer)", usdc(m, share))));
            }
        }
    }
    line
}

/// `market.json`'s `promotion`: the terms and the admitted matches. Null
/// without a promotion. The matching buyer is named only when the input
/// publishes wallets.
fn promotion_data(m: &Mainnet, matches: &[Match]) -> Value {
    let Some(p) = m.promotion.as_ref() else {
        return Value::Null;
    };
    let published = m.status.as_ref().is_some_and(|s| s.publish_wallets);
    let total = promotion::paid(matches);
    json!({
        "model": "proofs/commerce/Promotion.lean",
        "startBlock": p.start_block,
        "pool": p.pool.to_string(),
        "perPoster": p.per_poster.to_string(),
        "fractionBps": p.fraction_bps,
        "perStatement": p.per_statement.to_string(),
        "listed": p.listed,
        "matchingBuyer": if published { json!(p.matching_buyer) } else { Value::Null },
        "matched": total.to_string(),
        "left": u128::from(p.pool).saturating_sub(total).to_string(),
        "matches": matches.iter().map(|g| json!({
            "post": super::hx(&g.post), "statementSha256": super::hx(&g.statement),
            "order": super::hx(&g.digest), "seller": g.seller, "block": g.block,
            "price": g.price.to_string(), "amount": g.amount.to_string(),
        })).collect::<Vec<_>>(),
    })
}

fn percent(bps: u64) -> String {
    if bps.is_multiple_of(100) {
        format!("{} %", bps / 100)
    } else {
        format!("{}.{:02} %", bps / 100, bps % 100)
    }
}

/// The promotion's section: what it pays, to whom, and what it has matched.
fn promotion_blocks(
    m: &Mainnet,
    terms: &PromotionInput,
    data: &Value,
    known: &Known,
) -> Vec<Block> {
    let published = m.status.as_ref().is_some_and(|s| s.publish_wallets);
    let matched: u128 = data["matched"]
        .as_str()
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let left: u128 = data["left"]
        .as_str()
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let n = data["matches"].as_array().map_or(0, Vec::len);
    let buyer = if published {
        vec![
            t("The matching buyer, "),
            code(terms.matching_buyer.clone()),
            t(", pays it"),
        ]
    } else {
        vec![t(
            "The matching buyer (its address is not listed here) pays it",
        )]
    };
    let mut owed = vec![t("A match shown here is owed, not yet paid. ")];
    owed.extend(buyer);
    owed.push(t(
        " as a second order on the same statement, and that order then shows under the post.",
    ));
    let listed: Vec<Line> = terms
        .listed
        .iter()
        .map(|s| {
            let sha = s.trim_start_matches("0x");
            match known.statements.get(sha) {
                Some(file) => vec![code_link(format!("/statements/{file}"), short(sha))],
                None => vec![code(short(sha))],
            }
        })
        .collect();
    vec![
        h2("promotion", "Bootstrap matching"),
        para(&format!(
            "From block {}, the first settlement of a statement on the reviewed list earns that settlement's seller a match: {} of the post's price (or of the order's amount, when lower), at most {} for one statement and {} across one poster's posts, from a pool of {}.",
            terms.start_block,
            percent(terms.fraction_bps),
            usdc(m, u128::from(terms.per_statement)),
            usdc(m, u128::from(terms.per_poster)),
            usdc(m, u128::from(terms.pool)),
        )),
        para(&format!(
            "Matched so far: {} for {n} statement{}; {} of the pool left.",
            usdc(m, matched),
            if n == 1 { "" } else { "s" },
            usdc(m, left),
        )),
        para(
            "Nothing is matched for posting, or for a later settlement of a statement already settled. One wallet can post, fund, and settle its own post from a second wallet, and the chain shows two strangers; only a first proof of a reviewed statement earns a match.",
        ),
        p(owed),
        para(&format!(
            "The reviewed list, {} statements (SHA-256):",
            terms.listed.len()
        )),
        Block::Ul(listed),
        p(vec![
            t("The rules: "),
            code("proofs/commerce/Promotion.lean"),
            t("."),
        ]),
    ]
}

/// The `/market` page, from a snapshot whose `market` index is filtered.
pub fn page_from(
    input: &Input,
    snap: Option<&Value>,
    source: Source,
    known: &Known,
) -> Option<Doc> {
    let m = input.mainnet.as_ref()?;
    let st = m.status.as_ref()?;
    let mut blocks = vec![p(vec![
        t("The rules: "),
        code("proofs/commerce/Market.lean"),
        t("."),
    ])];
    let index: Option<Index> = snap
        .and_then(|s| s.get("market"))
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let (Some(s), Some(index)) = (snap, index) else {
        blocks.push(para(
            "This build has no market index, so no posts are shown.",
        ));
        return Some(doc(blocks));
    };
    let data = data(input, &index, s["takenAt"].as_u64().unwrap_or(0));
    let source_text = crate::status::source_sentence(m, s, source);
    let stamp = [
        s["block"].as_u64().unwrap_or(0).to_string(),
        s["blockTimestamp"].as_u64().unwrap_or(0).to_string(),
        s["takenAt"].as_u64().unwrap_or(0).to_string(),
    ];
    blocks.push(h2("source", "Snapshot"));
    blocks.push(Block::Rendered {
        html: Html::join([html::tx(
            "p",
            &[
                ("id", "status-source"),
                ("data-block", &stamp[0]),
                ("data-block-time", &stamp[1]),
                ("data-read-at", &stamp[2]),
            ],
            &source_text,
        )]),
        markdown: source_text.clone(),
    });
    let posts: Vec<Value> = data["posts"].as_array().cloned().unwrap_or_default();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for p in &posts {
        *counts.entry(p["state"].as_str().unwrap_or("")).or_default() += 1;
    }
    let order = [
        "listed",
        "funded",
        "settled",
        "claimed",
        "refunded",
        "expired",
        "withdrawn",
    ];
    let tally = order
        .iter()
        .filter_map(|s| counts.get(s).map(|n| format!("{n} {s}")))
        .collect::<Vec<_>>()
        .join(", ");
    let rv = rounds(&index, index.cursor_time, m, &st.buyer);
    let mut summary = vec![vec![strong(format!("{} posts: {tally}.", posts.len()))]];
    summary.extend(round_lines(m, &rv));
    blocks.push(Block::Ul(summary));
    if let Some(p) = m.promotion.as_ref() {
        blocks.extend(promotion_blocks(m, p, &data["promotion"], known));
    }
    blocks.push(h2("posts", "Posts"));
    let ex = &m.network.explorer;
    let rows: Vec<Vec<Line>> = posts
        .iter()
        .map(|post| {
            let id = post["id"].as_str().unwrap_or("");
            let poster = post["poster"].as_str().unwrap_or("");
            let poster_cell = match post["posterRole"].as_str() {
                Some("bounty buyer") => vec![t("the bounty buyer")],
                Some("ladder buyer") => vec![t("the ladder buyer")],
                Some("other") => vec![code(poster.to_owned())],
                _ => vec![t("elided")],
            };
            let sha = post["statementSha256"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("0x");
            let statement = match known.statements.get(sha) {
                Some(file) => vec![code_link(format!("/statements/{file}"), short(sha))],
                None => vec![code(short(sha))],
            };
            let mut orders: Line = Vec::new();
            for o in post["orders"].as_array().cloned().unwrap_or_default() {
                if !orders.is_empty() {
                    orders.push(t("; "));
                }
                let d = o["digest"].as_str().unwrap_or("").to_owned();
                if known.receipts.contains(&d) {
                    orders.push(code_link(format!("/transactions/{d}"), short(&d)));
                } else {
                    orders.push(code(short(&d)));
                }
                orders.push(t(format!(" {}", o["phase"].as_str().unwrap_or(""))));
                if let Some(a) = o["artifactHash"].as_str() {
                    let k = a.trim_start_matches("0x");
                    orders.push(t(", "));
                    if known.artifacts.contains(k) {
                        orders.push(link(format!("/artifacts/{k}.bin"), "artifact"));
                    } else if let Some(tx) = o["settledIn"].as_str() {
                        orders.push(link(format!("{ex}/tx/{tx}"), "artifact in calldata"));
                    }
                }
            }
            if orders.is_empty() {
                orders.push(t("none"));
            }
            vec![
                vec![code_link(
                    format!("{ex}/tx/{}", post["transaction"].as_str().unwrap_or("")),
                    short(id),
                )],
                state_cell(m, post),
                vec![t(post["round"].as_str().unwrap_or("").to_owned())],
                vec![t(usdc(
                    m,
                    post["maximumAmount"]
                        .as_str()
                        .and_then(|a| a.parse().ok())
                        .unwrap_or(0),
                ))],
                vec![t(date(post["fundBy"].as_u64().unwrap_or(0)))],
                vec![t(date(post["deliverBy"].as_u64().unwrap_or(0)))],
                poster_cell,
                statement,
                orders,
            ]
        })
        .collect();
    blocks.push(Block::Table {
        caption: "Posts, newest first, with the orders that joined each".into(),
        head: [
            "Post",
            "State",
            "Round",
            "Price cap",
            "Fund by",
            "Deliver by",
            "Posted by",
            "Statement (SHA-256)",
            "Orders",
        ]
        .map(String::from)
        .to_vec(),
        rows,
    });
    blocks.push(h2("rules", "How a post is read"));
    blocks.push(Block::Ul(vec![
        vec![t("An order joins a post when its context is the post's ID and key binding hashed together and its policy hash is the post's. The context comes from the fund call; the digest is recomputed to check it.")],
        vec![t("A post shows the furthest phase any joined order reached; the vault allows more than one. Without one: withdrawn, expired after its funding deadline, or listed.")],
        vec![t("A statement is taken once an order joined to any post of it has settled.")],
        vec![
            t("Posters other than the bounty buyer and the ladder buyer are shown by address; the authors' other wallets read elided. Data: "),
            link(format!("/{JSON_PATH}"), "market.json"),
            t("."),
        ],
    ]));
    let scan = &index.scan;
    blocks.push(Block::Details {
        summary: "How it was read".into(),
        blocks: vec![para(&format!(
            "eth_getLogs on the board {} and the vaults {} in ranges of at most {} blocks, and eth_getTransactionByHash for each vault event. Last read: {} scan, blocks {} to {}, {} calls.",
            m.board.address,
            st.vaults.iter().map(|v| v.address.as_str()).collect::<Vec<_>>().join(", "),
            m.network.log_range.unwrap_or(10_000),
            scan.kind,
            scan.from,
            scan.to,
            scan.calls
        ))],
    });
    Some(doc(blocks))
}

fn doc(blocks: Vec<Block>) -> Doc {
    Doc {
        path: MARKET_PATH.into(),
        title: "Market — QED".into(),
        description: "Every post on the board, ours and anyone's, with the orders that answer it and its state, read from the chain.".into(),
        heading: "Market".into(),
        blocks,
        script: false,
        data: None,
    }
}

/// The page's addresses beyond the input's: the posters it shows.
pub fn shown_addresses(snap: &Value) -> BTreeSet<String> {
    snap.get("market")
        .and_then(|v| serde_json::from_value::<Index>(v.clone()).ok())
        .map(|i| super::shown_posters(&i))
        .unwrap_or_default()
}

/// Element ids every market page carries; `check-live` requires each.
pub const REQUIRED_IDS: [&str; 4] = ["status-source", "source", "posts", "rules"];

/// `check-live`'s rule for a served `/market`: the status page's rule
/// (frame, ids, age, stamp) with the posters the served `market.json`
/// shows admitted as addresses. Which posters are the authors' cannot be
/// checked here: the reader's list decides that, and the release audit.
pub fn check_served(
    built_html: &str,
    built_md: &str,
    served_html: &str,
    served_md: &str,
    served_json: &str,
    now: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    let extra: BTreeSet<String> = match serde_json::from_str::<Value>(served_json) {
        Ok(v) if v["schema"] == JSON_SCHEMA => v["posts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|p| p["posterRole"] == "other")
            .filter_map(|p| p["poster"].as_str())
            .map(|a| a.trim_start_matches("0x").to_ascii_lowercase())
            .collect(),
        _ => {
            out.push(format!("{JSON_PATH} is not a {JSON_SCHEMA} document"));
            BTreeSet::new()
        }
    };
    out.extend(crate::status::check_served_with(
        built_html,
        built_md,
        served_html,
        served_md,
        now,
        &REQUIRED_IDS,
        &[],
        &extra,
    ));
    out
}

/// One settled order's saving and its split, as `market.json` carries it.
fn saving_data(r: &super::savings::Record) -> Value {
    let cap = r.cap;
    json!({
        "cap": cap.to_string(), "amount": r.amount.to_string(),
        "saving": cap.saturating_sub(r.amount).to_string(),
        "referrer": r.referrer,
        "split": {"referrer": r.split.referrer.to_string(),
                  "perAuthor": r.split.per_author.to_string(),
                  "authors": r.split.authors,
                  "buyer": r.split.buyer.to_string()},
    })
}
