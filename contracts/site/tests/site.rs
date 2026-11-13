//! The built site, checked as files: the cards against the A2A schema and
//! the proto's required fields, the signature, every page for outside
//! references and for strings that must not be published, the values
//! against the inputs, the receipts against the snapshot, and the decoder's
//! test logs against the Rust reference.
use nucleus_site::{
    AUTHORS_ONLY, BINDING, CARD_PATH, Counterparties, EXAMPLE_NODE, Input, JWKS_PATH, Options,
    POSSESSION_EXTENSION, SELLER_CARD_PATH, SETTLEMENT_EXTENSION, SPEC_PATH, apex, apex_path, card,
    card_violations, elide_counterparties,
    ledger::{LedgerInput, Snapshot},
    live, published, schema, serving, signing, site,
};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use std::path::Path;

const SITE: &str = "https://qed.example.test";

fn repository() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}
fn input() -> Input {
    Input::read(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/input/arbitrum-sepolia.json"
    )))
    .unwrap()
}
fn ledger() -> (LedgerInput, Snapshot) {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/input"));
    (
        LedgerInput::read(&dir.join("ledger.json")).unwrap(),
        Snapshot::read(&dir.join("ledger.snapshot.json")).unwrap(),
    )
}
/// A key for tests only; the real one is a file outside the repository.
fn test_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).unwrap()
}
fn built_with(input: &Input, url: Option<&str>, signed: bool) -> Vec<(String, Vec<u8>)> {
    let (l, s) = ledger();
    let key = test_key();
    let options = Options {
        site_url: url,
        ledger: Some((&l, &s)),
        card_key: signed.then_some(&key),
        source_commit: Some("0123456789ab"),
    };
    site(input, repository(), &options).unwrap()
}
fn built(input: &Input, url: Option<&str>) -> Vec<(String, Vec<u8>)> {
    built_with(input, url, true)
}
fn file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a str {
    std::str::from_utf8(
        &files
            .iter()
            .find(|(path, _)| path == name)
            .unwrap_or_else(|| panic!("{name} not built"))
            .1,
    )
    .unwrap()
}
fn html_files(files: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
    files
        .iter()
        .filter(|(p, _)| p.ends_with(".html"))
        .map(|(p, b)| (p.clone(), String::from_utf8(b.clone()).unwrap()))
        .collect()
}

/// Strings no built file may contain. Only generic needles are written
/// here: home-directory prefixes. Names specific to whoever builds the site
/// (a login name, a person's name, internal hosts or projects) are never
/// written into the tree; they are passed at run time in
/// `NUCLEUS_SITE_FORBIDDEN`, comma-separated. Without it the generic checks
/// still run, and the test says that no specific needles were supplied.
fn forbidden() -> Vec<String> {
    let mut list = vec!["/Users/".to_owned(), "/home/".to_owned()];
    match std::env::var("NUCLEUS_SITE_FORBIDDEN") {
        Ok(more) => {
            let specific: Vec<String> = more
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            eprintln!(
                "forbidden strings: 2 generic and {} supplied in NUCLEUS_SITE_FORBIDDEN",
                specific.len()
            );
            list.extend(specific);
        }
        Err(_) => eprintln!(
            "forbidden strings: 2 generic only; NUCLEUS_SITE_FORBIDDEN not supplied, so no name specific to this builder was checked"
        ),
    }
    list
}
fn leaks(text: &str, forbidden: &[String]) -> Vec<String> {
    let lower = text.to_lowercase();
    forbidden
        .iter()
        .filter(|needle| lower.contains(&needle.to_lowercase()))
        .cloned()
        .collect()
}

#[test]
fn the_card_fits_the_schema_and_the_protos_required_fields() {
    let input = input();
    let programs = published(&input, repository()).unwrap();
    let bundle = schema::Bundle::vendored();
    let good = card(&input, &programs, Some(SITE));
    assert_eq!(bundle.check("AgentCard", &good), vec![]);
    assert_eq!(card_violations(&good), Vec::<String>::new());
    let mut broken = good.clone();
    broken.as_object_mut().unwrap().remove("skills");
    assert!(!card_violations(&broken).is_empty());
    // The served card, signed, still fits.
    let files = built(&input, Some(SITE));
    let served: Value = serde_json::from_str(file(&files, CARD_PATH)).unwrap();
    assert_eq!(card_violations(&served), Vec::<String>::new());
}

#[test]
fn the_card_is_signed_per_a2a_and_a_changed_card_or_another_key_fails() {
    let files = built(&input(), Some(SITE));
    let card: Value = serde_json::from_str(file(&files, CARD_PATH)).unwrap();
    let jwks: Value = serde_json::from_str(file(&files, JWKS_PATH)).unwrap();
    let kid = signing::verify(&card, &jwks).unwrap();
    assert_eq!(kid, signing::thumbprint(test_key().verifying_key()));
    // The protected header carries what A2A 1.0.1 §8.4.2 asks for.
    use base64::Engine;
    let protected = card["signatures"][0]["protected"].as_str().unwrap();
    let header: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JOSE");
    assert_eq!(header["jku"], format!("{SITE}/{JWKS_PATH}"));
    // Red: a changed description fails; so does a JWKS of another key.
    let mut changed = card.clone();
    changed["description"] = json!("something else");
    assert!(signing::verify(&changed, &jwks).is_err());
    let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
    assert!(signing::verify(&card, &signing::jwks(other.verifying_key())).is_err());
    // No default-valued field is left in the card (§8.4.1).
    assert_eq!(
        signing::strip_defaults(&card).get("capabilities"),
        card.get("capabilities")
    );
    // Unsigned builds serve no JWKS.
    let unsigned = built_with(&input(), Some(SITE), false);
    assert!(!unsigned.iter().any(|(p, _)| p == JWKS_PATH));
    let card: Value = serde_json::from_str(file(&unsigned, CARD_PATH)).unwrap();
    assert!(card.get("signatures").is_none());
}

#[test]
fn the_card_is_served_at_the_well_known_path_and_claims_no_a2a_interface() {
    let files = built(&input(), Some(SITE));
    assert_eq!(CARD_PATH, ".well-known/agent-card.json");
    assert_eq!(file(&files, CARD_PATH), file(&files, "agent-card.json"));
    let card: Value = serde_json::from_str(file(&files, CARD_PATH)).unwrap();
    assert_eq!(card["supportedInterfaces"], json!([]));
    assert_eq!(
        card["capabilities"]["extensions"][0]["uri"],
        SETTLEMENT_EXTENSION
    );
    assert!(card["description"].as_str().unwrap().contains(BINDING));
    assert_eq!(card["documentationUrl"], format!("{SITE}/"));
    for skill in card["skills"].as_array().unwrap() {
        assert!(
            skill["description"]
                .as_str()
                .unwrap()
                .contains("This is not an A2A operation")
        );
    }
}

#[test]
fn the_example_seller_card_is_the_one_the_seller_software_serves_and_names_an_iroh_interface() {
    let files = built(&input(), Some(SITE));
    let card: Value = serde_json::from_str(file(&files, SELLER_CARD_PATH)).unwrap();
    assert_eq!(
        card,
        nucleus_a2a_iroh_card::card(
            EXAMPLE_NODE,
            card["name"].as_str().unwrap(),
            card["description"].as_str().unwrap(),
            card["version"].as_str().unwrap(),
        )
    );
    assert_eq!(card_violations(&card), Vec::<String>::new());
    assert_eq!(card["supportedInterfaces"][0]["protocolBinding"], BINDING);
    let required: Vec<&str> = card["capabilities"]["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["required"] == true)
        .filter_map(|e| e["uri"].as_str())
        .collect();
    assert!(required.contains(&POSSESSION_EXTENSION));
}

#[test]
fn every_extension_identifier_has_a_document_for_the_apex_host() {
    let files = apex(repository(), Some(SITE)).unwrap();
    for uri in [BINDING, POSSESSION_EXTENSION, SETTLEMENT_EXTENSION] {
        let path = format!("{}/index.html", apex_path(uri).unwrap());
        let page = file(&files, &path);
        assert!(!page.contains("<script"), "{path}");
    }
    let page = nucleus_site::docs::spec_page("# t\n\n<script>alert(1)</script>\n", "t").unwrap();
    assert!(!page.contains("<script>"));
}

#[test]
fn every_document_has_html_and_markdown_and_the_markdown_says_the_same_facts() {
    let files = built(&input(), Some(SITE));
    let docs: Vec<String> = files
        .iter()
        .filter(|(p, _)| p.ends_with("index.html"))
        .map(|(p, _)| p.trim_end_matches("index.html").to_owned())
        .collect();
    assert!(docs.len() >= 8 + 16, "{} documents", docs.len());
    for d in &docs {
        let md = file(&files, &format!("{d}index.md"));
        assert!(md.starts_with("# "), "{d}");
        if !d.starts_with("protocol/a2a-iroh-binding") {
            assert!(!md.contains("<"), "{d}: markup in Markdown");
        }
    }
    let home = file(&files, "index.md");
    for fact in [
        AUTHORS_ONLY,
        "unaudited",
        "Don't trust us. Ask your agent.",
        CARD_PATH,
    ] {
        assert!(home.contains(fact), "{fact}");
    }
}

#[test]
fn the_serving_table_the_caddy_block_and_the_preview_agree_and_check_live_finds_a_difference() {
    for path in [
        CARD_PATH,
        "agent-card.json",
        JWKS_PATH,
        SELLER_CARD_PATH,
        "deployment.json",
        "receipts/index.json",
        "receipts/0xab.json",
        "artifacts/ab.bin",
    ] {
        assert!(
            serving::headers(path, true).contains(&("access-control-allow-origin", "*")),
            "{path}"
        );
    }
    for path in [
        "",
        "index.html",
        "protocol/index.html",
        SPEC_PATH,
        "abi/NucleusBoard.json",
        "qed.js",
    ] {
        assert!(
            !serving::headers(path, true)
                .iter()
                .any(|(n, _)| *n == "access-control-allow-origin"),
            "{path}"
        );
    }
    assert!(serving::headers("", true).contains(&("vary", "Accept, Accept-Encoding")));
    assert!(serving::varies_on_accept("Accept, Accept-Encoding"));
    assert!(serving::varies_on_accept("accept-encoding, Accept"));
    // The substring test this replaced passed on encoding alone.
    assert!(!serving::varies_on_accept("Accept-Encoding"));
    assert_eq!(
        serving::cache_control("artifacts/ab.bin"),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        serving::media_type("protocol/index.md"),
        "text/markdown; charset=utf-8"
    );
    let caddy = serving::caddy("qed.example.test", "/srv/qed");
    // Caddy applies an unconditional header directive after the matched
    // ones, so Cache-Control is set only through disjoint matchers: the
    // live host served every artifact for 300 s until this was found.
    let unconditional = caddy
        .split("\theader {\n")
        .nth(1)
        .and_then(|r| r.split("\t}\n").next())
        .unwrap();
    assert!(!unconditional.contains("Cache-Control"), "{unconditional}");
    let (served, errors) = caddy.split_once("\thandle_errors 404 {\n").unwrap();
    assert_eq!(served.matches("Cache-Control \"").count(), 3);
    // The not-found page: HTML, never cached past the next release, and
    // the site's own file rather than Caddy's empty body.
    for present in [
        "rewrite * /404.html",
        "header Content-Type \"text/html; charset=utf-8\"",
        "header Cache-Control \"no-cache\"",
        "header Vary \"Accept, Accept-Encoding\"",
        "header -Server",
        "status 404",
    ] {
        assert!(errors.contains(present), "{present}");
    }
    assert!(caddy.contains("\tencode zstd gzip {\n"));
    // One value per line: `caddy validate` refused several on one line
    // ("malformed header matcher: expected both field and value").
    for media in serving::COMPRESSED {
        assert!(caddy.contains(&format!("\t\t\theader Content-Type {media}\n")));
    }
    assert!(!caddy.contains("header Content-Type text/* "));
    // Every type the site serves is compressible: Caddy's default list
    // left out NDJSON and octet-stream statements.
    for path in [
        "", "a.md", "a.json", "a.css", "a.js", "a.txt", "a.xml", "a.wasm", "a.ndjson", "a.v2",
        "a.bin",
    ] {
        let media = serving::media_type(path);
        assert!(
            serving::COMPRESSED
                .iter()
                .any(|p| media.starts_with(p.trim_end_matches('*'))),
            "{path} {media}"
        );
    }
    assert!(caddy.contains("@cache_short not path /abi/* /artifacts/* /statements/*\n"));
    assert_eq!(
        serving::cache_control("statements/ab.v2"),
        serving::cache_control("artifacts/ab.bin")
    );
    for absent in ["reverse_proxy", "browse", "templates", "php"] {
        assert!(!caddy.contains(absent), "{absent}");
    }
    for present in [
        "header_regexp Accept (?i)text/markdown",
        "file {path}/index.md",
        "try_files {path} {path}/index.html",
        "Vary \"Accept, Accept-Encoding\"",
        "/receipts/*",
        "/artifacts/*",
    ] {
        assert!(caddy.contains(present), "{present}");
    }

    let root = std::env::temp_dir().join(format!("nucleus-site-live-{}", std::process::id()));
    let served = root.join("served");
    let other = root.join("other");
    for dir in [&served, &other] {
        for (path, bytes) in built(&input(), Some(SITE)) {
            let target = dir.join(&path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
    }
    std::fs::write(other.join("deployment.json"), b"{}\n").unwrap();
    std::fs::write(other.join("protocol/index.md"), b"# other\n").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let dir = served.clone();
    std::thread::spawn(move || {
        let _ = nucleus_site::preview::serve_on(&dir, listener);
    });
    assert_eq!(live::check(&base, &served).unwrap(), Vec::new());
    let findings = live::check(&base, &other).unwrap();
    let paths: Vec<&str> = findings.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["/deployment.json", "/protocol"], "{findings:?}");
    assert!(live::check("http://localhost:1", &served).is_err());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn nothing_generated_names_the_builder_or_the_private_workspace() {
    let forbidden = forbidden();
    for url in [None, Some(SITE)] {
        let all = built(&input(), url)
            .into_iter()
            .chain(apex(repository(), url).unwrap());
        for (path, bytes) in all {
            let text = String::from_utf8_lossy(&bytes);
            assert_eq!(leaks(&text, &forbidden), Vec::<String>::new(), "{path}");
        }
    }
    // The scanner fires on a generic needle, and on one supplied at run time.
    assert_eq!(leaks("see /Users/someone/x", &forbidden), vec!["/Users/"]);
    assert_eq!(
        leaks("as Example-Needle", &["example-needle".to_owned()]).len(),
        1
    );
}

/// With `discloseAuthorAddresses` off (the default), none of the authors'
/// wallet addresses appears anywhere as the authors': not in the card,
/// `deployment.json`, `/verify`, the ledger index or its live-board data,
/// and no role label or per-receipt counterparty note is published. The
/// buyer and seller inside a receipt, and on that receipt's own page, are
/// chain data read from the settle transaction and stay. Turning the input
/// on puts them back, which is what makes this test able to fail.
#[test]
fn author_addresses_are_not_named_unless_the_input_says_so() {
    let mut i = input();
    assert!(
        !i.disclose_author_addresses,
        "the input should default to off"
    );
    // A synthetic wallet, so the test does not depend on the real list,
    // which a published copy of this input carries empty.
    i.our_addresses.push(nucleus_site::Named {
        role: "Synthetic author wallet (test only)".into(),
        address: "0xd15c105ed0d15c105ed0d15c105ed0d15c105ed0".into(),
    });
    let chain_data =
        |path: &str| path.starts_with("receipts/0x") || path.starts_with("transactions/0x");
    let labelled = |files: &[(String, Vec<u8>)], i: &Input| -> Vec<String> {
        let mut found = Vec::new();
        for (path, bytes) in files {
            if path.starts_with("assets/") || path.ends_with(".js") || path.ends_with(".bin") {
                continue;
            }
            let text = String::from_utf8_lossy(bytes).to_lowercase();
            for named in &i.our_addresses {
                let address = named.address.to_lowercase();
                let bare = address.trim_start_matches("0x");
                if !chain_data(path) && text.contains(bare) {
                    found.push(format!("{path}: {}", named.address));
                }
                // Role labels from the input ("Vault treasury (a test key)"),
                // not single protocol words like "Seller".
                if named.role.contains(' ') && text.contains(&named.role.to_lowercase()) {
                    found.push(format!("{path}: role {:?}", named.role));
                }
            }
            if text.contains("\"counterparties\":\"buyer") || text.contains("keys were both held") {
                found.push(format!("{path}: per-receipt counterparty note"));
            }
        }
        found
    };
    let off = built(&i, Some(SITE));
    assert_eq!(labelled(&off, &i), Vec::<String>::new());
    assert!(
        file(&off, "index.html").contains(&nucleus_site::html::esc(AUTHORS_ONLY)),
        "the general statement stays"
    );
    i.disclose_author_addresses = true;
    let on = built(&i, Some(SITE));
    assert!(
        !labelled(&on, &i).is_empty(),
        "with disclosure on, the treasury and the live board's list name the authors' addresses"
    );
}

/// The main-network bounty: its page states the offer from the input, the
/// card and `deployment.json` carry the deployment, and the main-network
/// treasury is named nowhere unless author addresses are disclosed.
#[test]
fn the_bounty_page_states_the_input_and_names_no_mainnet_treasury() {
    let i = input();
    let m = i
        .mainnet
        .clone()
        .expect("the input carries a mainnet bounty");
    let treasury = m.vault.treasury.to_lowercase();
    let bare = treasury.trim_start_matches("0x").to_owned();
    let files = built(&i, Some(SITE));
    let page = file(&files, "bounty/index.html");
    let price = nucleus_site::amount(m.bounty.price, m.token.decimals);
    let receives = nucleus_site::amount(m.seller_receives(), m.token.decimals);
    assert_eq!(receives, "24.9375", "25 USDC less 25 basis points");
    for needle in [
        format!("{price} {}", m.token.name),
        format!("{receives} {}", m.token.name),
        m.board.address.clone(),
        m.vault.address.clone(),
        m.treasury_kind.clone(),
    ] {
        assert!(page.contains(&needle), "bounty page lacks {needle}");
    }
    assert!(file(&files, "index.html").contains("href=\"/bounty\""));
    let deployment: Value = serde_json::from_str(file(&files, "deployment.json")).unwrap();
    assert_eq!(deployment["mainnet"]["board"]["address"], m.board.address);
    assert!(deployment["mainnet"]["vault"].get("treasury").is_none());
    // A published copy of the input carries the zero address in place of
    // the treasury, and forty zeros occur in receipts as ordinary chain data,
    // so the scan applies to a real treasury only (as for the test vault's).
    // Found 2026-11-13: the public tree's CI would have failed here.
    let redacted = bare.bytes().all(|b| b == b'0');
    for (path, bytes) in &files {
        if redacted || path.ends_with(".bin") {
            continue;
        }
        let text = String::from_utf8_lossy(bytes).to_lowercase();
        assert!(!text.contains(&bare), "{path} names the mainnet treasury");
    }
}

#[test]
fn no_page_loads_anything_from_another_site() {
    let files = built(&input(), Some(SITE));
    for (path, html) in html_files(&files) {
        assert_eq!(
            serving::fetching_markers(&html),
            Vec::<String>::new(),
            "{path}"
        );
        assert!(!html.contains("<script>"), "{path}: inline script");
        assert!(!html.contains("<style"), "{path}: inline style");
    }
    let js = file(&files, "qed.js");
    // Two network calls: the live list's, to the endpoint the reader sees
    // and can edit; and the checker's, only to paths on this site (its
    // guard refuses anything else, and the /verify CSP admits only 'self').
    assert_eq!(js.matches("fetch(").count(), 2);
    assert_eq!(js.matches("await fetch(url, {").count(), 2);
    assert!(js.contains(
        "if (!/^\\/[^\\/\\\\]/.test(url)) throw new Error(url + \": not a path on this site\");\n      var response = await fetch(url, { credentials: \"omit\" });"
    ));
    for never in [
        "sendBeacon",
        "XMLHttpRequest",
        "WebSocket",
        "EventSource",
        "document.cookie",
        "localStorage",
        "sessionStorage",
        "eval(",
    ] {
        assert!(!js.contains(never), "{never}");
    }
    let css = file(&files, "qed.css");
    assert!(!css.contains("@import") && !css.contains("url("));
    // The scanner fires.
    assert!(
        !serving::fetching_markers("<script src=\"https://cdn.example/x.js\"></script>").is_empty()
    );
}

#[test]
fn the_receipts_are_the_snapshot_and_their_artifacts_hash_to_the_vaults_record() {
    let input = input();
    let files = built(&input, Some(SITE));
    let (_, snap) = ledger();
    assert!(snap.receipts().len() >= 16);
    for receipt in snap.receipts() {
        let id = receipt["id"].as_str().unwrap();
        let served = file(&files, &format!("receipts/{id}.json"));
        // Served as the snapshot, less what the input does not disclose.
        // Plus `acceptance`: the buyer's policy and statement, each tied to
        // the chain by a hash checked here.
        let mut published = elide_counterparties(receipt, input.disclose_author_addresses);
        let acceptance = snap
            .acceptance(receipt)
            .expect("every settled order's policy and statement are published");
        assert_eq!(acceptance["policyHashesTo"], receipt["order"]["policyHash"]);
        let statement_sha = acceptance["statement"]["sha256"].as_str().unwrap();
        assert_eq!(acceptance["policy"]["statementSha256"], statement_sha);
        let statement_url = acceptance["statement"]["url"].as_str().unwrap();
        let statement = &files
            .iter()
            .find(|(p, _)| format!("/{p}") == statement_url)
            .unwrap()
            .1;
        assert_eq!(
            nucleus_site::hex(<sha2::Sha256 as sha2::Digest>::digest(statement).as_slice()),
            statement_sha
        );
        published["acceptance"] = acceptance;
        assert_eq!(served, format!("{}\n", signing::jcs(&published).unwrap()));
        let k = receipt["artifact"]["keccak256"].as_str().unwrap();
        assert_eq!(receipt["artifact"]["recordedByVault"], k);
        assert_eq!(receipt["artifact"]["inSettledLog"], k);
        let bytes = &files
            .iter()
            .find(|(p, _)| *p == format!("artifacts/{}.bin", &k[2..]))
            .unwrap()
            .1;
        assert_eq!(
            format!(
                "0x{}",
                nucleus_site::hex(alloy_primitives::keccak256(bytes).as_slice())
            ),
            k
        );
        assert_eq!(receipt["asserted"]["assertedBy"], "authors");
        assert_eq!(
            receipt["settlement"]["transaction"].as_str().unwrap().len(),
            66
        );
        assert!(!receipt["funding"].is_null(), "{id}: funding not found");
        let html = file(&files, &format!("transactions/{id}/index.html"));
        assert!(html.contains(id));
    }
    // Two settlements were in real money, both on Base (the second-form
    // vault, then the first relayed trade on the third-form vault); the rest
    // were in test tokens.
    let real: Vec<_> = snap
        .receipts()
        .iter()
        .filter(|r| !r["asserted"]["realMoney"].is_null())
        .collect();
    assert_eq!(real.len(), 2);
    assert!(real.iter().all(|r| r["network"]["chainId"] == 8453));
}

#[test]
fn the_values_on_the_pages_are_the_inputs() {
    let input = input();
    let files = built(&input, Some(SITE));
    let verify = file(&files, "verify/index.html");
    for value in [
        &input.board.code_keccak,
        &input.vault.code_keccak,
        &input.registry.code_keccak,
        &input.verifier.code_keccak,
    ] {
        assert!(verify.contains(value.trim_start_matches("0x")), "{value}");
    }
    // The treasury is one of the authors' keys: listed only on request. A
    // published copy of the input carries the zero address in its place, and
    // a run of forty zeros is not a distinctive string, so the check applies
    // to a real treasury only.
    let redacted = input.vault.treasury == "0x0000000000000000000000000000000000000000";
    if !redacted {
        assert_eq!(
            verify.contains(input.vault.treasury.trim_start_matches("0x")),
            input.disclose_author_addresses
        );
    }
    for program in published(&input, repository()).unwrap() {
        assert!(verify.contains(&program.sha256));
        assert!(verify.contains(&program.image_id));
    }
    let deployment: Value = serde_json::from_str(file(&files, "deployment.json")).unwrap();
    assert_eq!(deployment["vault"]["address"], input.vault.address);
}

#[test]
fn the_decoders_test_logs_are_published_and_embedded_for_the_ledger_page() {
    let input = input();
    let files = built(&input, Some(SITE));
    let vectors: Value =
        serde_json::from_str(file(&files, "verification/test-vectors/board-logs.json")).unwrap();
    assert_eq!(vectors, nucleus_site::vectors(&input).unwrap());
    let page = file(&files, "transactions/index.html");
    assert!(page.contains("id=\"site-data\""));
    let jcs: Value =
        serde_json::from_str(file(&files, "verification/test-vectors/jcs.json")).unwrap();
    for case in jcs.as_array().unwrap() {
        assert_eq!(
            signing::jcs(&case["input"]).unwrap(),
            case["canonical"].as_str().unwrap()
        );
    }
}

#[test]
fn who_has_traded_is_said_until_the_input_says_otherwise_with_evidence() {
    let input = input();
    assert!(matches!(
        input.assurance.counterparties,
        Counterparties::AuthorsOnly
    ));
    let files = built(&input, Some(SITE));
    for page in ["index.html", "transactions/index.html"] {
        assert!(
            file(&files, page).contains(&nucleus_site::html::esc(AUTHORS_ONLY)),
            "{page}"
        );
    }
    let mut outside = input.clone();
    outside.assurance.counterparties = Counterparties::Outside {
        first_outside_settlement: "0x".to_owned() + &"1".repeat(64),
    };
    let home = built(&outside, Some(SITE));
    assert!(file(&home, "index.html").contains("A party other than the authors"));
}

#[test]
fn the_same_inputs_give_the_same_bytes() {
    assert_eq!(built(&input(), Some(SITE)), built(&input(), Some(SITE)));
}

/// RFC 9116: with the source public and a dated snapshot, the site serves
/// `security.txt` whose contact is the repository's private reporting (no
/// email), whose expiry is under a year after the snapshot, and whose
/// canonical URL is itself. With the source not public there is no file, so
/// the site never advertises a contact that does not exist.
#[test]
fn security_txt_names_the_repositorys_private_reporting_only_when_public() {
    let i = input();
    let files = built(&i, Some(SITE));
    let text = file(&files, nucleus_site::SECURITY_TXT_PATH);
    let fields: Vec<(&str, &str)> = text.lines().filter_map(|l| l.split_once(": ")).collect();
    let get = |k: &str| fields.iter().find(|(f, _)| *f == k).map(|(_, v)| *v);
    let nucleus_site::Software::Public { url } = &i.software else {
        panic!("the input should name a public source");
    };
    assert_eq!(
        get("Contact"),
        Some(format!("{url}/security/advisories/new").as_str())
    );
    assert_eq!(
        get("Canonical"),
        Some(format!("{SITE}/{}", nucleus_site::SECURITY_TXT_PATH).as_str())
    );
    assert!(get("Expires").is_some_and(|e| e.ends_with('Z') && e.len() == 20));
    assert!(!text.contains('@'), "no email address");
    let mut private = i.clone();
    private.software = nucleus_site::Software::OnRequest;
    assert!(
        !built(&private, Some(SITE))
            .iter()
            .any(|(p, _)| p == nucleus_site::SECURITY_TXT_PATH)
    );
}

#[test]
fn the_seller_page_names_the_released_image_and_how_to_check_it() {
    let i = input();
    let files = built(&i, Some(SITE));
    let page = file(&files, "sellers/run/index.html");
    let release = &nucleus_site::pages::SELLER_RELEASE;
    let digest = release.digest.trim_start_matches("sha256:");
    assert!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "the release digest is not a SHA-256: {}",
        release.digest
    );
    let image = format!("{}@{}", release.image, release.digest);
    assert!(page.contains(&format!("cosign verify {image}")), "{page}");
    assert!(page.contains(&format!("gh attestation verify oci://{image}")));
    assert!(page.contains("nucleus-acceptance-host order2-image"));
    assert!(!page.contains("Not published yet."));
    // The bounty's board, its deployment block and the relayer.
    let m = i
        .mainnet
        .as_ref()
        .expect("the input carries a mainnet bounty");
    assert!(page.contains(&m.board.address));
    let start = format!("\"startBlock\": {}", m.board.deploy_block.unwrap());
    assert!(page.contains(&start.replace('"', "&quot;")) || page.contains(&start));
    assert!(page.contains("Gas relayer") && !page.contains("Gas relayer (planned)"));
    assert!(
        page.contains("&quot;relayer&quot;: &quot;https://relay.qed.coproduct.dev&quot;")
            || page.contains("\"relayer\": \"https://relay.qed.coproduct.dev\"")
    );
    assert!(page.contains("Fetch the Groth16 data"), "no measured table");
    let markdown = file(&files, "sellers/run/index.md");
    assert!(
        markdown.contains(&format!("cosign verify {image}")),
        "{markdown}"
    );
    assert!(
        file(&files, "bounty/index.html").contains("href=\"/sellers/run\""),
        "the bounty page does not point to the seller page"
    );
    assert!(
        file(&files, "index.html").contains("href=\"/sellers/run\""),
        "the seller page is not reachable from the index"
    );
}
