//! The market index over Base, as `nucleus-site market-capture` recorded it
//! (tests/fixtures/market-base.json: every board and vault event from block
//! 56772992 to 62256533, addresses filtered for publication), replayed by
//! the Rust mirror of proofs/commerce/Market.lean. The table and the
//! numbers are the Lean file's `Real` examples, decided there.
#![allow(clippy::unwrap_used, clippy::panic)]
use nucleus_site::market::{self, Event, Index, Market, ModelEvent, ModelPost, Round, State};

fn fixture() -> Index {
    serde_json::from_str(include_str!("fixtures/market-base.json")).unwrap()
}
const BUYER: &str = "0x133c25a80fb323de143e8ad5c6c620bf8713edfd";
const LADDER: &str = "0xca1f8b498d3df887fe9f0a3cd637b059bb35ad1a";
const KEY: &str = "0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8";
const STATEMENT: &str = "0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c";
const R1_START: u64 = 62_001_659;
const R1_POST: &str = "0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727";

/// Market.lean `Real.table`: (post ID, context), each recomputed here.
const TABLE: [(&str, &str); 11] = [
    (
        "0x28daaf524e25938fc92d7c55cab97516f4e55b3cbd120b6de885e3e4cd2098dd",
        "0x59596d4ce2add9f61560384abf166e7074dfa13126b745180c7250ae8c155f54",
    ),
    (
        "0x2ca29bcf72cfddc732019e72d64750a13f458590bd042804ec07e5ea66b48812",
        "0x5b6e8ee307d614489776fd8725a45c880f2cbe2e8c6ce79adb1841ebca91663f",
    ),
    (
        "0xb454a434583caf2c899e4d48b18d4776951128bbe029fd73f5c57a4c31a3bf7e",
        "0xe822fb25d1e4cc66aecf2b928d9e6495a54051d8b2682baf956d4c42f3920f94",
    ),
    (
        "0x7b746a3c85353e75d03acbf0b1bd22ea3be925b583808f6a059ad8a409f35eb7",
        "0xd0d7f94faa8419f9bc81831c54ddc9a04e9eac068c7cc14a41caac0f7b3cc4d5",
    ),
    (
        "0xec8668825da64c8724ae06170db5d42226cf34524795fe3799f727caa8e51bba",
        "0xb24d0bba9ea90262ec441448c30c1c95056067e9ab3e16f8d250ffd45df98902",
    ),
    (
        "0x625e31dab83ec36ff2b3babc3be3e61ca9f1ea7ab39d32fe85c42989c49cba6b",
        "0x08770b74dba1a800a78f85b235cb8d92b27bf51a9e80bf531f8afb0bfe630370",
    ),
    (
        "0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727",
        "0xa1c0369fd35a3f2efc5cce7182544495e07615e47a576f5568958e8de7dc3bd3",
    ),
    (
        "0x41099437d91be57496eb2a6207f3c017a3b2a675768926cf36cd9782cc81e353",
        "0x991bac0166894d824c265792f3109ad18a3ee6188333b6802e04275bb2d53522",
    ),
    (
        "0xa739b0af1703182ac734efed744237f62dc93c61b6a49a354ee5ffcd9722b299",
        "0x998e2b4a7d895f6cf37f517782cba19f767818b2487c634717f8fd51adee1d5b",
    ),
    (
        "0x34f01e4c96f3a234590bfd6f157bfff002e29828c9c4f3733d4869ae727f761c",
        "0xaa6233c4a19742bdef130a47958e2a9a2465057f8c0e8de8b310f0d1f8a15171",
    ),
    (
        "0x86fff8186702d87007c8383584af57dc88a512c17b03f136095b27c290459485",
        "0xec3f72259e9fad2ff626e866db3cbfc871a9e3a7326499b64771ffa8b93a96d1",
    ),
];
/// docs/rfcs/qed-first-outside-settlements-2026-11-25.md.
const OUTSIDE: [&str; 4] = [
    "0xcdea51489e4a4e03a07d63d5443a4f978e93b94a6ca1850ab242458fe8946c24",
    "0xb5c5bdf7feaeb0d2b93d188facfd17812fe78e0047ef458067ecf4e0fbf7859a",
    "0xf894cd7e822b16dfc96059edb16ef0226a4453fb7e9bcc3f91411d44d9f14881",
    "0x47e69316147efd3853a60912e499b84f8a9c42e6ff265bb85197c10d97906885",
];

fn round1(p: &ModelPost) -> bool {
    p.poster == BUYER && (57_110_912..R1_START).contains(&p.block)
}
fn r1(p: &ModelPost) -> bool {
    p.poster == BUYER && p.block >= R1_START
}
fn post<'a>(m: &'a Market, id: &str) -> &'a ModelPost {
    m.posts.iter().find(|p| market::hx(&p.id) == id).unwrap()
}

#[test]
fn the_context_table_is_keccak() {
    for (id, ctx) in TABLE {
        assert_eq!(
            market::hx(&market::context(&market::word(id), &market::word(KEY))),
            ctx
        );
    }
}

#[test]
fn every_order_terms_were_decoded_and_checked_against_its_digest() {
    let index = fixture();
    let funded: Vec<_> = index
        .events
        .iter()
        .filter_map(|l| match &l.event {
            Event::Funded { terms, .. } => Some(terms),
            _ => None,
        })
        .collect();
    assert_eq!(funded.len(), 12);
    assert!(
        funded
            .iter()
            .all(|t| t.as_ref().is_some_and(|t| t.from == "fund"))
    );
}

#[test]
fn the_four_outside_settlements_join_round_one_posts() {
    let index = fixture();
    let m = Market::replay(&market::model_events(&index, index.cursor_time));
    for digest in OUTSIDE {
        let joined: Vec<&ModelPost> = m
            .posts
            .iter()
            .filter(|p| m.joined(p).any(|o| market::hx(&o.digest) == digest))
            .collect();
        assert_eq!(joined.len(), 1, "{digest}");
        assert!(round1(joined[0]), "{digest}");
        assert_eq!(m.state(joined[0]), State::Claimed);
    }
}

#[test]
fn states_on_base_at_block_62256533() {
    let index = fixture();
    let m = Market::replay(&market::model_events(&index, index.cursor_time));
    assert_eq!(m.posts.len(), 25);
    let count = |s: State| m.posts.iter().filter(|p| m.state(p) == s).count();
    assert_eq!(
        [
            State::Listed,
            State::Expired,
            State::Withdrawn,
            State::Funded,
            State::Refunded,
            State::Settled,
            State::Claimed
        ]
        .map(count),
        [2, 0, 12, 0, 1, 0, 10]
    );
    assert_eq!(m.state(post(&m, TABLE[0].0)), State::Withdrawn);
    assert_eq!(m.state(post(&m, TABLE[1].0)), State::Refunded);
    // The two listed posts are the ladder buyer's; past their funding
    // deadline, with nothing joined, they read expired.
    let listed: Vec<&ModelPost> = m
        .posts
        .iter()
        .filter(|p| m.state(p) == State::Listed)
        .collect();
    assert!(listed.iter().all(|p| p.poster == LADDER));
    let mut later = m.clone();
    later.apply(&ModelEvent::Tick(
        listed.iter().map(|p| p.fund_by).max().unwrap() + 1,
    ));
    assert!(listed.iter().all(|p| later.state(p) == State::Expired));
    // The one order joined to no post: the first relayed trade on the
    // earlier vault, funded before the board was deployed.
    let unjoined: Vec<_> = m
        .orders
        .iter()
        .filter(|o| !m.posts.iter().any(|p| Market::joins(p, o)))
        .map(|o| market::hx(&o.digest))
        .collect();
    assert_eq!(
        unjoined,
        ["0x91e79768b93b5d0b81c6142bac9dc4d512cf8efb1b8cdd2477a162d01810bb94"]
    );
    assert!(m.taken(&market::word(STATEMENT)));
}

#[test]
fn rounds_on_base() {
    let index = fixture();
    let m = Market::replay(&market::model_events(&index, index.cursor_time));
    let one = Round {
        budget: 100_000_000,
        tasks: 4,
        member: &round1,
    };
    assert_eq!(
        (m.funded_amount(&one), m.refund_amount(&one)),
        (125_000_000, 25_000_000)
    );
    assert_eq!(
        (m.remaining(&one), m.remaining_tasks(&one)),
        (Some(0), Some(0))
    );
    let two = Round {
        budget: 5_000_000,
        tasks: 5,
        member: &r1,
    };
    assert_eq!(
        (m.remaining(&two), m.remaining_tasks(&two)),
        (Some(0), Some(0))
    );
    assert_eq!(m.funded_amount(&two), 5_000_000);
    // Mutant M4 on the real round 1: without refunds, 125 of 100 spent.
    assert_eq!(one.budget.checked_sub(m.funded_amount(&one)), None);

    // At r1's first post (the events before its first funding).
    let cut: Vec<ModelEvent> = market::model_events(&index, 0)
        .into_iter()
        .zip(&index.events)
        .take_while(|(_, l)| l.block <= R1_START)
        .map(|(e, _)| e)
        .chain([ModelEvent::Tick(1_795_590_707)])
        .collect();
    let open = Market::replay(&cut);
    assert_eq!(open.state(post(&open, R1_POST)), State::Listed);
    assert_eq!(
        (open.remaining(&two), open.remaining_tasks(&two)),
        (Some(5_000_000), Some(5))
    );
    assert!(
        open.taken(&market::word(STATEMENT)),
        "taken by round 1 before r1 opened"
    );
}

/// The committed fixture names no wallet beyond the contracts, the token
/// and the three published ones.
#[test]
fn the_fixture_names_no_other_wallet() {
    let input = nucleus_site::Input::read(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/input/arbitrum-sepolia.json"
    )))
    .unwrap();
    let text = include_str!("fixtures/market-base.json");
    assert_eq!(
        nucleus_site::status::foreign_addresses(&input, text),
        Vec::<String>::new()
    );
}

fn input() -> nucleus_site::Input {
    nucleus_site::Input::read(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/input/arbitrum-sepolia.json"
    )))
    .unwrap()
}
const OUTSIDER: &str = "0xd15c105ed0d15c105ed0d15c105ed0d15c105ed0";
const SITE: &str = "https://qed.example.test";

/// The committed snapshot with one elided poster replaced by an outside
/// address, as a reader holding the authors' list would publish it.
fn with_outside_poster() -> serde_json::Value {
    let mut s: serde_json::Value =
        serde_json::from_str(include_str!("../input/status.snapshot.json")).unwrap();
    let events = s["market"]["events"].as_array_mut().unwrap();
    let posted = events
        .iter_mut()
        .find(|e| e["event"] == "Posted" && e["poster"] == "elided")
        .unwrap();
    posted["poster"] = serde_json::json!(OUTSIDER);
    s
}

#[test]
fn the_market_page_names_outside_posters_and_refuses_an_authors_wallet() {
    use nucleus_site::{market, status};
    let i = input();
    let known = market::view::Known::default();
    let s = with_outside_poster();
    let names = status::default_names(&i);
    let (md, html, json) =
        status::render_market(&i, &s, status::Source::Build, SITE, &names, &known)
            .unwrap()
            .unwrap();
    assert!(
        md.contains(&format!("`{OUTSIDER}`")),
        "the poster by address"
    );
    assert!(html.contains(OUTSIDER) && json.contains(OUTSIDER));
    assert!(
        md.contains("**Round r1: 0 of 5 tasks, 0 USDC of 5 USDC remain.**"),
        "{md}"
    );
    assert!(md.contains("**Round 1: 0 of 4 tasks, 0 USDC of 100 USDC remain.**"));
    // Red: the same address on the authors' list: refused, nothing written.
    let authors = market::Names {
        published: names.published.clone(),
        authors: Some([OUTSIDER.to_owned()].into()),
    };
    let refused = status::render_market(&i, &s, status::Source::Build, SITE, &authors, &known);
    assert!(refused.is_err());
    // The host's real list (2026-11-26): every author wallet, the published
    // ones included. Those the page names by design; it still renders.
    let with_published = market::Names {
        published: names.published.clone(),
        authors: Some(names.published.iter().cloned().collect()),
    };
    assert!(
        status::render_market(&i, &s, status::Source::Build, SITE, &with_published, &known)
            .unwrap()
            .is_some()
    );
    // check-live: the poster market.json shows is admitted; a planted one
    // is not.
    let built = status::render_market(&i, &s, status::Source::Build, SITE, &names, &known)
        .unwrap()
        .unwrap();
    let now = s["blockTimestamp"].as_u64().unwrap() + 60;
    assert_eq!(
        market::view::check_served(&built.1, &built.0, &html, &md, &json, now),
        Vec::<String>::new()
    );
    let planted = html.replacen(
        "<h2",
        "<p>0xfeedfacefeedfacefeedfacefeedfacefeedface</p><h2",
        1,
    );
    let found = market::view::check_served(&built.1, &built.0, &planted, &md, &json, now);
    assert!(
        found.iter().any(|f| f.contains("does not name")),
        "{found:?}"
    );
    let found = market::view::check_served(&built.1, &built.0, &html, &md, "{}", now);
    assert!(
        found.iter().any(|f| f.contains("is not a qed-market/1")),
        "{found:?}"
    );
}

/// A reader pass writes the market page and its data beside /status.
#[test]
fn a_pass_renders_the_market_beside_the_status_page() {
    use nucleus_site::{market, status};
    let i = input();
    let s: serde_json::Value =
        serde_json::from_str(include_str!("../input/status.snapshot.json")).unwrap();
    let now = s["takenAt"].as_u64().unwrap() + 600;
    let names = status::default_names(&i);
    let good = status::pass_with(
        &i,
        SITE,
        Some(&s),
        None,
        Ok(s.clone()),
        now,
        &names,
        &market::view::Known::default(),
    )
    .unwrap();
    let (md, _, json) = good.market.unwrap();
    assert!(md.contains("Reread every 10 minutes"));
    let data: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(data["posts"].as_array().unwrap().len(), 25);
    assert_eq!(data["rounds"][1]["remainingTasks"], 0);
    // A failed read keeps the last good market, saying so.
    let failed = status::pass_with(
        &i,
        SITE,
        Some(&s),
        Some(&s),
        Err("timeout".into()),
        now,
        &names,
        &market::view::Known::default(),
    )
    .unwrap();
    assert!(failed.market.unwrap().0.contains("Reread failed at "));
}

// ---- The bootstrap promotion (proofs/commerce/Promotion.lean) ----------------

const MATCHER: &str = "0x3a7c4e5d6f708192a3b4c5d6e7f8091a2b3c4d5e";
/// The bounty statement's first settlement: 1 USDC, block 57144774, on a post
/// by one of the authors' unpublished wallets (elided), buyer and seller elided.
const FIRST_SETTLEMENT: &str = "0xa2f139e12b7aaee29d7c800754b4f4db2007e69b112274d26c417e3d701f07a6";
const FIRST_SETTLED_POST: &str =
    "0x2a1acff4651608392403967165ac8a709d9b4d17e196fda9ef5285a4ed79b4c9";

fn terms(listed: &[&str], start_block: u64) -> market::promotion::PromotionInput {
    market::promotion::PromotionInput {
        start_block,
        pool: 100_000_000,
        per_poster: 40_000_000,
        fraction_bps: 5000,
        per_statement: 20_000_000,
        listed: listed.iter().map(|s| (*s).to_owned()).collect(),
        matching_buyer: MATCHER.into(),
    }
}

/// On Base: the bounty statement's first settlement was the authors' own
/// 1 USDC trade, before the outside seller's four. Listed from before it,
/// that trade would earn the match (half of 1 USDC) and the outside
/// seller nothing: the case the reviewed list exists for. Not listed (its
/// proof is public), or listed only from after it: nothing.
#[test]
fn on_base_only_the_first_settlement_of_a_listed_statement_is_matched() {
    let index = fixture();
    let g = market::promotion::decide(&index, &terms(&[STATEMENT], 57_000_000));
    assert_eq!(g.len(), 1, "{g:?}");
    assert_eq!(market::hx(&g[0].post), FIRST_SETTLED_POST);
    assert_eq!(market::hx(&g[0].digest), FIRST_SETTLEMENT);
    assert_eq!((g[0].price, g[0].amount), (1_000_000, 500_000));
    assert_eq!(g[0].poster, "elided");
    assert!(
        !g.iter()
            .any(|m| OUTSIDE.contains(&market::hx(&m.digest).as_str())),
        "the outside seller's settlements came after: not first"
    );
    assert!(market::promotion::decide(&index, &terms(&[STATEMENT], 57_144_775)).is_empty());
    assert!(market::promotion::decide(&index, &terms(&[], 57_000_000)).is_empty());
    assert!(market::promotion::decide(&index, &terms(&[STATEMENT], R1_START)).is_empty());
}

fn with_promotion(publish: bool) -> nucleus_site::Input {
    let mut i = input();
    let m = i.mainnet.as_mut().unwrap();
    m.promotion = Some(terms(&[STATEMENT], 57_000_000));
    m.status.as_mut().unwrap().publish_wallets = publish;
    i.check().unwrap();
    i
}

#[test]
fn the_market_page_shows_the_match_and_names_the_matching_buyer_only_when_published() {
    use nucleus_site::{market, status};
    let known = market::view::Known::default();
    let s: serde_json::Value =
        serde_json::from_str(include_str!("../input/status.snapshot.json")).unwrap();
    let i = with_promotion(true);
    let names = status::default_names(&i);
    let (md, html, json) =
        status::render_market(&i, &s, status::Source::Build, SITE, &names, &known)
            .unwrap()
            .unwrap();
    assert!(md.contains("claimed, matched +0.5 USDC"), "{md}");
    assert!(md.contains("## Bootstrap matching"));
    assert!(md.contains("earns that settlement's seller a match: 50 % of the post's price"));
    assert!(md.contains("Matched so far: 0.5 USDC for 1 statement; 99.5 USDC of the pool left."));
    assert!(md.contains(MATCHER) && html.contains(MATCHER));
    let data: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(data["promotion"]["matchingBuyer"], MATCHER);
    assert_eq!(data["promotion"]["matches"].as_array().unwrap().len(), 1);
    let matched: Vec<&serde_json::Value> = data["posts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| !p["matched"].is_null())
        .collect();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0]["id"], FIRST_SETTLED_POST);
    assert_eq!(matched[0]["matched"]["order"], FIRST_SETTLEMENT);
    // The authors' list holds the matching buyer too: published, it renders.
    let with_list = market::Names {
        published: names.published.clone(),
        authors: Some([MATCHER.to_owned()].into()),
    };
    assert!(
        status::render_market(&i, &s, status::Source::Build, SITE, &with_list, &known)
            .unwrap()
            .is_some()
    );
    // Not published: the page says the match and not the address.
    let quiet = with_promotion(false);
    let public = status::public(&s, &status::default_names(&quiet));
    let d = market::view::page_from(&quiet, Some(&public), status::Source::Build, &known).unwrap();
    let md = nucleus_site::doc::markdown(&d, Some(SITE));
    assert!(md.contains("matched +0.5 USDC"));
    assert!(md.contains("its address is not listed here"));
    assert!(!md.contains(MATCHER));
    let index: market::Index = serde_json::from_value(public["market"].clone()).unwrap();
    assert!(market::view::data(&quiet, &index, 0)["promotion"]["matchingBuyer"].is_null());
}

/// No promotion in the input: no section, no matched posts.
#[test]
fn without_a_promotion_the_page_says_nothing_of_one() {
    use nucleus_site::{market, status};
    let i = input();
    let s: serde_json::Value =
        serde_json::from_str(include_str!("../input/status.snapshot.json")).unwrap();
    let (md, _, json) = status::render_market(
        &i,
        &s,
        status::Source::Build,
        SITE,
        &status::default_names(&i),
        &market::view::Known::default(),
    )
    .unwrap()
    .unwrap();
    assert!(!md.contains("matching") && !md.contains("matched"));
    let data: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(data["promotion"].is_null());
}

// ---- Proof-carrying savings (proofs/commerce/Savings.lean) ---------------------

/// Every settlement on Base so far paid its post's cap: no saving, a zero
/// split for each settled order.
#[test]
fn on_base_no_settlement_saved_its_buyer_anything() {
    let index = fixture();
    let records = market::savings::decide(&index, &[]);
    assert!(!records.is_empty());
    for r in &records {
        assert!(r.amount >= r.cap, "{r:?}");
        assert_eq!(r.split, Default::default());
        assert_eq!(r.referrer, None);
    }
}

/// The first outside settlement, as if its post had a 40 USDC cap and its
/// salt bound a referrer: 15 USDC saved, 4.5 to the referrer, 10.5 to the
/// buyer (no authors on this page). The same referral with a wrong nonce,
/// or for another order, binds nothing. Driven red by matching on the
/// order alone, without the salt: the wrong nonce counted.
#[test]
fn a_referral_counts_only_when_it_opens_the_orders_salt() {
    let mut index = fixture();
    let order = OUTSIDE[0];
    let (referrer, nonce) = ([0x5e_u8; 20], [0x11_u8; 32]);
    let salt = market::hx(&market::savings::referral_salt(&referrer, &nonce));
    for l in &mut index.events {
        if let Event::Funded {
            digest,
            terms: Some(t),
            ..
        } = &mut l.event
            && digest.as_str() == order
        {
            t.salt = salt.clone();
        }
    }
    let records = market::savings::decide(&index, &[]);
    let r = records
        .iter()
        .find(|r| market::hx(&r.digest) == order)
        .unwrap();
    let post_id = market::hx(&r.post);
    for l in &mut index.events {
        if let Event::Posted {
            id, maximum_amount, ..
        } = &mut l.event
            && *id == post_id
        {
            *maximum_amount = "40000000".into();
        }
    }
    let referral = |order: &str, nonce: [u8; 32]| market::savings::ReferralInput {
        order: order.into(),
        referrer: market::hx(&referrer),
        nonce: market::hx(&nonce),
    };
    let find = |records: Vec<market::savings::Record>| {
        records
            .into_iter()
            .find(|r| market::hx(&r.digest) == order)
            .unwrap()
    };
    let r = find(market::savings::decide(&index, &[referral(order, nonce)]));
    assert_eq!((r.cap, r.amount), (40_000_000, 25_000_000));
    assert_eq!(r.referrer.as_deref(), Some(market::hx(&referrer).as_str()));
    assert_eq!((r.split.referrer, r.split.buyer), (4_500_000, 10_500_000));
    let wrong = find(market::savings::decide(
        &index,
        &[referral(order, [0x12; 32])],
    ));
    assert_eq!((wrong.referrer, wrong.split.referrer), (None, 0));
    let elsewhere = find(market::savings::decide(
        &index,
        &[referral(OUTSIDE[1], nonce)],
    ));
    assert_eq!(elsewhere.referrer, None);
}
