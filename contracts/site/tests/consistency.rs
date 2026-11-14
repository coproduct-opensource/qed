//! What the pages say about the relayer and about which network is live,
//! where the authors' wallets may appear, and what the status page shows.
use nucleus_site::{
    Input, Options,
    ledger::{LedgerInput, Snapshot},
    site,
};
use p256::ecdsa::SigningKey;
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
fn built(input: &Input) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/input"));
    let l = LedgerInput::read(&dir.join("ledger.json")).unwrap();
    let s = Snapshot::read(&dir.join("ledger.snapshot.json")).unwrap();
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let options = Options {
        site_url: Some(SITE),
        ledger: Some((&l, &s)),
        card_key: Some(&key),
        source_commit: Some("0123456789ab"),
    };
    site(input, repository(), &options).unwrap()
}
fn text_files(files: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
    files
        .iter()
        .filter(|(p, _)| p.ends_with(".md") || p.ends_with(".json"))
        .filter(|(p, _)| !p.starts_with("verification/test-vectors/"))
        .map(|(p, b)| (p.clone(), String::from_utf8_lossy(b).into_owned()))
        .collect()
}
fn file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a str {
    std::str::from_utf8(&files.iter().find(|(p, _)| p == name).unwrap().1).unwrap()
}

/// Sentences, each with the heading of the section it is in. A sentence
/// ends at ". ", at a line end, or at "; " inside JSON strings.
fn sentences(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut heading = String::new();
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            heading = h.to_string();
            continue;
        }
        for s in line.replace(".** ", ". ").split(". ") {
            out.push((heading.clone(), s.to_string()));
        }
    }
    out
}

/// Sentences that call the relayer planned or unavailable.
fn relayer_findings(path: &str, text: &str) -> Vec<String> {
    const NOT_RUNNING: [&str; 6] = [
        "planned",
        "not available",
        "unavailable",
        "not deployed",
        "not yet running",
        "not running",
    ];
    sentences(text)
        .into_iter()
        .filter(|(_, s)| s.to_lowercase().contains("relayer"))
        .filter(|(_, s)| NOT_RUNNING.iter().any(|w| s.to_lowercase().contains(w)))
        .map(|(_, s)| format!("{path}: {s}"))
        .collect()
}

/// Sentences that present the test network as live: they name it, are in a
/// section about what is current or live (or say so themselves), and do not
/// say it is history.
fn testnet_findings(path: &str, text: &str, test: &str, stopped: &str) -> Vec<String> {
    const LIVE: [&str; 7] = [
        " live",
        "live ",
        "current",
        " now",
        "post tasks",
        "posts tasks",
        "open for",
    ];
    sentences(text)
        .into_iter()
        .filter(|(_, s)| s.contains(test))
        .filter(|(h, s)| {
            let (h, l) = (h.to_lowercase(), s.to_lowercase());
            LIVE.iter().any(|w| l.contains(w) || h.contains(w.trim()))
        })
        .filter(|(_, s)| !s.contains(stopped) && !s.to_lowercase().contains("history"))
        .map(|(h, s)| format!("{path} [{h}]: {s}"))
        .collect()
}

/// The public README and protocol text: the overlay in this repository, or
/// the files at the root of the public one.
fn public_docs() -> Vec<(String, String)> {
    let overlay = repository().join("contracts/release/overlay-qed");
    let dir = if overlay.exists() {
        overlay
    } else {
        repository().to_path_buf()
    };
    ["README.md", "PROTOCOL.md"]
        .iter()
        .filter_map(|f| {
            std::fs::read_to_string(dir.join(f))
                .ok()
                .map(|t| (f.to_string(), t))
        })
        .collect()
}

#[test]
fn no_page_calls_the_relayer_unavailable_or_the_test_network_live() {
    let i = input();
    let stopped = i
        .test_buyers_stopped
        .clone()
        .expect("the test buyers' stop date");
    let mut docs = text_files(&built(&i));
    docs.extend(public_docs());
    // A site built elsewhere (for example the one being served), checked by
    // the same rules: NUCLEUS_SITE_CHECK_BUILT=DIR.
    if let Ok(dir) = std::env::var("NUCLEUS_SITE_CHECK_BUILT") {
        let mut stack = vec![std::path::PathBuf::from(&dir)];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "md" || e == "json") {
                    let rel = p.strip_prefix(&dir).unwrap().to_string_lossy().into_owned();
                    if !rel.starts_with("verification/test-vectors/") {
                        docs.push((format!("built:{rel}"), std::fs::read_to_string(&p).unwrap()));
                    }
                }
            }
        }
    }
    let mut findings = Vec::new();
    for (path, text) in &docs {
        findings.extend(relayer_findings(path, text));
        findings.extend(testnet_findings(path, text, &i.network.name, &stopped));
    }
    assert_eq!(findings, Vec::<String>::new());

    // Red, on sentences the site and README carried before 2026-11-14.
    let before = [
        (
            "README.md",
            "The relayer is planned. A seller needs a little ETH until it runs.",
        ),
        (
            "bounty/index.md",
            "- The gas relayer is not available yet; send your own fund, settle and claim.",
        ),
        (
            "transactions/index.md",
            "## Tasks on the board now\n\nThe live list of posts is read from the chain by the page's script. To read it yourself, call eth_getLogs on the board 0x81711f647826fe53749c6b73804716655a1bf7c9 from block 328913580 on Arbitrum Sepolia (chain 421614)",
        ),
        (
            "protocol/index.md",
            "## The current deployment\n\nArbitrum Sepolia, chain 421614",
        ),
        (
            "agent-card.json",
            "Buyers post tasks on a board contract on Base and Arbitrum Sepolia; sellers answer over iroh",
        ),
    ];
    for (path, text) in before {
        let found = relayer_findings(path, text).len()
            + testnet_findings(path, text, &i.network.name, &stopped).len();
        assert!(found > 0, "{path}: {text:?} was not flagged");
    }
}

/// The authors' wallets, from `NUCLEUS_SITE_WALLETS` (comma-separated, never
/// written into the tree), appear only in chain data (receipts and their
/// pages) and, for the two the owner published, on the status page.
#[test]
fn author_wallets_appear_only_where_published() {
    let i = input();
    let published: Vec<String> = i
        .mainnet
        .as_ref()
        .and_then(|m| m.status.as_ref())
        .filter(|s| s.publish_wallets)
        .map(|s| vec![s.buyer.clone(), s.relayer.clone()])
        .unwrap_or_default()
        .iter()
        .map(|a| a.trim_start_matches("0x").to_lowercase())
        .collect();
    let wallets: Vec<String> = match std::env::var("NUCLEUS_SITE_WALLETS") {
        Ok(list) => list
            .split(',')
            .map(|w| w.trim().trim_start_matches("0x").to_lowercase())
            .filter(|w| w.len() == 40)
            .collect(),
        Err(_) => {
            eprintln!(
                "NUCLEUS_SITE_WALLETS not supplied: only the two published wallets and a synthetic one are checked"
            );
            published.clone()
        }
    };
    let check = |files: &[(String, Vec<u8>)], wallets: &[String]| -> Vec<String> {
        let mut found = Vec::new();
        for (path, bytes) in files {
            if path.ends_with(".bin") {
                continue;
            }
            let chain_data = path.starts_with("receipts/0x") || path.starts_with("transactions/0x");
            let status = path.starts_with("status/");
            let text = String::from_utf8_lossy(bytes).to_lowercase();
            for w in wallets {
                let allowed = chain_data || (status && published.contains(w));
                if !allowed && text.contains(w.as_str()) {
                    found.push(format!("{path}: {w}"));
                }
            }
        }
        found
    };
    let files = built(&i);
    assert_eq!(check(&files, &wallets), Vec::<String>::new());
    // The two published wallets are on the status page, in both forms.
    for w in &published {
        assert!(file(&files, "status/index.md").contains(w.as_str()));
        assert!(file(&files, "status/index.html").contains(w.as_str()));
    }
    // Red: a wallet on the home page, and a published one on another page.
    let synthetic = "d15c105ed0d15c105ed0d15c105ed0d15c105ed0".to_string();
    let mut planted = files.clone();
    planted.push((
        "index.md".into(),
        format!("paid by 0x{synthetic}").into_bytes(),
    ));
    if let Some(w) = published.first() {
        planted.push((
            "bounty/index.md".into(),
            format!("buyer 0x{w}").into_bytes(),
        ));
    }
    let mut all = wallets.clone();
    all.push(synthetic);
    assert_eq!(check(&planted, &all).len(), 1 + published.len().min(1));
}

/// The Mac QuickStart is one script, generated from the release and the
/// deployment: the seller page and the Agent Card's skill carry it, and the
/// public README must carry it verbatim, so a new release digest is changed
/// in one place and the README cannot drift from it.
#[test]
fn the_mac_quickstart_is_the_same_on_the_page_in_the_card_and_in_the_readme() {
    let i = input();
    let m = i.mainnet.as_ref().unwrap();
    let script = nucleus_site::pages::mac_quickstart_script(m);
    assert!(script.contains(nucleus_site::pages::SELLER_RELEASE.digest));
    assert!(script.contains("container system start"));
    assert!(!script.contains("docker"));
    let files = built(&i);
    let page = file(&files, "sellers/run/index.md");
    assert!(page.contains(&script), "the seller page");
    let card: serde_json::Value = serde_json::from_str(file(&files, "agent-card.json")).unwrap();
    let skill = card["skills"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "run-seller-mac")
        .expect("the card's Mac skill");
    assert!(skill["description"].as_str().unwrap().contains(&script));
    let readme = public_docs()
        .into_iter()
        .find(|(f, _)| f == "README.md")
        .expect("the public README")
        .1;
    assert!(
        readme.contains(&script),
        "the README's Mac QuickStart differs from the generated one:\n{script}"
    );
    // The Questions line, the same on the page, in the card and the README.
    let questions = nucleus_site::pages::questions();
    assert!(page.contains(nucleus_site::pages::DISCUSSIONS));
    assert!(skill["description"].as_str().unwrap().contains(&questions));
    assert!(readme.contains(&questions), "the README's Questions line");
    // Until the published release has `sweep`, its line is a comment and
    // the page says the command needs the next release.
    let sweep = "container run --rm -v qed:/data --entrypoint nucleus-seller \"$IMAGE\" sweep";
    if nucleus_site::pages::SELLER_RELEASE.has_sweep {
        assert!(script.lines().any(|l| l.starts_with(sweep)));
        for text in [page, readme.as_str()] {
            assert!(!text.contains("Needs the next seller release."));
            assert!(text.contains("FAILED: nothing to sweep"));
        }
    } else {
        assert!(!script.lines().any(|l| l.starts_with(sweep)));
        assert!(script.contains(&format!("# {sweep}")));
        assert!(page.contains("Needs the next seller release."));
        assert!(readme.contains("Needs the next seller release."));
    }
}

/// With the build switch off, the status page names neither wallet and its
/// queries carry placeholders.
#[test]
fn the_status_page_names_the_two_wallets_only_with_the_switch_on() {
    let mut i = input();
    let st = i.mainnet.as_ref().unwrap().status.clone().unwrap();
    let on = built(&i);
    let md = file(&on, "status/index.md");
    assert!(md.contains("Showing the build-time snapshot: block "));
    for id in [
        "q-block",
        "q-buyer-usdc",
        "q-relayer-eth",
        "q-vault0-usdc",
        "q-board-logs-0",
    ] {
        assert!(
            file(&on, "status/index.html").contains(&format!("id=\"{id}\"")),
            "{id}"
        );
    }
    assert!(md.contains("not on chain"));
    i.mainnet
        .as_mut()
        .unwrap()
        .status
        .as_mut()
        .unwrap()
        .publish_wallets = false;
    let off = built(&i);
    for page in ["status/index.md", "status/index.html"] {
        let text = file(&off, page);
        for w in [&st.buyer, &st.relayer] {
            assert!(
                !text.contains(w.trim_start_matches("0x")),
                "{page} names {w}"
            );
        }
        assert!(text.contains("BUYER_ADDRESS") && text.contains("RELAYER_ADDRESS"));
    }
}
