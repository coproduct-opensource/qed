//! The brief's agent-readability table, as tests over the built site served
//! by the local preview (which follows the same serving table as the host).
//! Each check passes on the real build and is then driven red on a copy
//! broken in exactly the way the check exists to catch.
use nucleus_site::{
    AUTHORS_ONLY, CARD_PATH, Input, Options, SPEC_PATH,
    harness::{self, Response},
    ledger::{LedgerInput, Snapshot},
    site,
};
use p256::ecdsa::SigningKey;
use std::path::{Path, PathBuf};

const SITE: &str = "https://qed.example.test";

fn build_into(dir: &Path) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let input = Input::read(&manifest.join("input/arbitrum-sepolia.json")).unwrap();
    let ledger = LedgerInput::read(&manifest.join("input/ledger.json")).unwrap();
    let snapshot = Snapshot::read(&manifest.join("input/ledger.snapshot.json")).unwrap();
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let options = Options {
        site_url: Some(SITE),
        ledger: Some((&ledger, &snapshot)),
        card_key: Some(&key),
        source_commit: Some("0123456789ab"),
    };
    for (path, bytes) in site(&input, &manifest.join("../.."), &options).unwrap() {
        let target = dir.join(&path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, bytes).unwrap();
    }
}

/// A fresh build in its own directory, served by the preview.
struct Served {
    dir: PathBuf,
    base: String,
}
impl Served {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("qed-harness-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        build_into(&dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let root = dir.clone();
        std::thread::spawn(move || {
            let _ = nucleus_site::preview::serve_on(&root, listener);
        });
        Self { dir, base }
    }
    fn edit(&self, path: &str, f: impl FnOnce(String) -> String) {
        let p = self.dir.join(path);
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, f(text)).unwrap();
    }
    fn documents(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![self.dir.clone()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().is_some_and(|n| n == "index.html") {
                    let rel = p.parent().unwrap().strip_prefix(&self.dir).unwrap();
                    out.push(format!("/{}", rel.display()).replace("//", "/"));
                }
            }
        }
        out.sort();
        out
    }
}
impl Drop for Served {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const FACTS: [&str; 8] = [
    "Q.E.D.",
    "Don't trust us. Ask your agent.",
    AUTHORS_ONLY,
    "The contracts are unaudited.",
    "Live on Base mainnet, in USDC.",
    "Sellers need no ETH.",
    "The current proof programs rebuild from source, byte for byte.",
    "Plain HTML. No account required.",
];

#[test]
fn the_root_page_is_complete_without_scripts() {
    let s = Served::new("home");
    assert_eq!(
        harness::homepage_complete_without_script(&s.base, &FACTS).unwrap(),
        Vec::<String>::new()
    );
    // Red: a fact moved into an element shown only by the script.
    s.edit("index.html", |t| {
        t.replace(
            "<strong>The contracts are unaudited.</strong>",
            "<span hidden>The contracts are unaudited.</span>",
        )
    });
    assert_eq!(
        harness::homepage_complete_without_script(&s.base, &FACTS)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn the_card_is_discoverable_from_the_root_page_and_at_the_well_known_path() {
    let s = Served::new("card");
    assert_eq!(
        harness::card_discoverable(&s.base).unwrap(),
        Vec::<String>::new()
    );
    // Red: the root page loses its alternate link.
    s.edit("index.html", |t| {
        t.replace(
            "rel=\"alternate\" type=\"application/json\"",
            "rel=\"x\" type=\"application/json\"",
        )
    });
    assert!(!harness::card_discoverable(&s.base).unwrap().is_empty());
}

#[test]
fn the_cards_signature_validates_against_the_served_jwks() {
    let s = Served::new("sig");
    assert_eq!(
        harness::card_signature_valid(&s.base).unwrap(),
        Vec::<String>::new()
    );
    // Red: one word of the served card changed.
    s.edit(CARD_PATH, |t| {
        t.replacen("Payment for Lean 4 proofs", "Payment for Lean 3 proofs", 1)
    });
    assert_eq!(harness::card_signature_valid(&s.base).unwrap().len(), 1);
}

#[test]
fn transactions_are_enumerable_as_canonical_receipts() {
    let s = Served::new("receipts");
    assert_eq!(
        harness::transactions_enumerable(&s.base).unwrap(),
        Vec::<String>::new()
    );
    // Red: one receipt re-serialised with whitespace.
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(s.dir.join("receipts/index.json")).unwrap()).unwrap();
    let first = index["receipts"][0]["url"]
        .as_str()
        .unwrap()
        .trim_start_matches('/')
        .to_owned();
    s.edit(&first, |t| {
        let v: serde_json::Value = serde_json::from_str(&t).unwrap();
        serde_json::to_string_pretty(&v).unwrap()
    });
    assert_eq!(harness::transactions_enumerable(&s.base).unwrap().len(), 1);
}

#[test]
fn a_settlements_evidence_is_two_links_from_the_ledger_and_hashes_to_the_vaults_record() {
    let s = Served::new("evidence");
    assert_eq!(
        harness::evidence_within_two_links(&s.base).unwrap(),
        Vec::<String>::new()
    );
    // Red: an artifact file altered after the snapshot.
    let artifact = std::fs::read_dir(s.dir.join("artifacts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&artifact).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&artifact, bytes).unwrap();
    assert!(
        !harness::evidence_within_two_links(&s.base)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_verify_page_gives_a_check_for_each_claim() {
    let s = Served::new("verify");
    assert_eq!(
        harness::verify_covers_each_claim(&s.base).unwrap(),
        Vec::<String>::new()
    );
    // Red: the DNS section removed.
    s.edit("verify/index.html", |t| {
        t.replace("id=\"dns\"", "id=\"gone\"")
    });
    assert_eq!(harness::verify_covers_each_claim(&s.base).unwrap().len(), 1);
}

#[test]
fn the_threat_model_distinguishes_proven_tested_and_assumed() {
    let s = Served::new("threats");
    assert_eq!(
        harness::threat_model_distinguishes(&s.base).unwrap(),
        Vec::<String>::new()
    );
    // Red: every status flattened to one word.
    s.edit("protocol/threat-model/index.html", |t| {
        t.replace(">Assumed<", ">Fine<")
    });
    assert_eq!(
        harness::threat_model_distinguishes(&s.base).unwrap().len(),
        1
    );
}

#[test]
fn no_page_asks_for_an_account_a_wallet_or_a_login() {
    let s = Served::new("account");
    let docs = s.documents();
    assert!(docs.len() >= 25, "{docs:?}");
    assert_eq!(
        harness::no_account_or_script_needed(&s.base, &docs).unwrap(),
        Vec::<String>::new()
    );
    // Red: a page asks the reader to connect a wallet.
    s.edit("verify/index.html", |t| {
        t.replacen(
            "<main id=\"main\">",
            "<main id=\"main\"><p>Connect wallet to continue.</p>",
            1,
        )
    });
    assert_eq!(
        harness::no_account_or_script_needed(&s.base, &docs)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn every_document_answers_markdown_when_asked_and_varies_on_accept() {
    let s = Served::new("markdown");
    let docs = s.documents();
    assert_eq!(
        harness::markdown_negotiation(&s.base, &docs, &s.dir).unwrap(),
        Vec::<String>::new()
    );
    // A browser's Accept gets HTML.
    let r: Response = harness::get(
        &s.base,
        "/protocol",
        Some("text/html,application/xhtml+xml,*/*;q=0.8"),
    )
    .unwrap();
    assert!(r.content_type.starts_with("text/html"));
    // A protocol object is never converted.
    let r = harness::get(&s.base, &format!("/{CARD_PATH}"), Some("text/markdown")).unwrap();
    assert!(r.content_type.starts_with("application/json"));
    // Red: one document's Markdown missing.
    std::fs::remove_file(s.dir.join("protocol/index.md")).unwrap();
    assert!(
        !harness::markdown_negotiation(&s.base, &docs, &s.dir)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn every_internal_link_and_anchor_resolves() {
    let s = Served::new("links");
    let docs = s.documents();
    assert_eq!(
        harness::internal_links_resolve(&s.base, &docs).unwrap(),
        Vec::<String>::new()
    );
    // Red: a link to a section that does not exist.
    s.edit("index.html", |t| {
        t.replacen("href=\"/verify#control\"", "href=\"/verify#nowhere\"", 1)
    });
    assert_eq!(
        harness::internal_links_resolve(&s.base, &docs)
            .unwrap()
            .len(),
        1
    );
}

/// Where pages may link out to, besides the site itself: one list for the
/// local and the live checks, so the two cannot disagree.
fn outbound(site: &str) -> Vec<String> {
    [
        site,
        "https://sepolia.arbiscan.io/",
        "https://basescan.org/",
        "https://developers.circle.com/",
        // The iroh project, linked from the binding's specification.
        "https://iroh.computer",
        // The public source repository, linked from /verification/source.
        "https://github.com/coproduct-opensource/qed",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

#[test]
fn nothing_is_loaded_from_another_site_and_links_out_go_where_expected() {
    let s = Served::new("external");
    let docs = s.documents();
    let allowed = outbound(SITE);
    assert_eq!(
        harness::nothing_external(&s.base, &docs, &allowed).unwrap(),
        Vec::<String>::new()
    );
    // The specification page is a document like the others.
    assert!(docs.contains(&format!("/{SPEC_PATH}")));
    // Red: a stylesheet from a CDN.
    s.edit("protocol/index.html", |t| {
        t.replacen(
            "</head>",
            "<link rel=\"stylesheet\" href=\"https://cdn.example/x.css\"></head>",
            1,
        )
    });
    assert_eq!(
        harness::nothing_external(&s.base, &docs, &allowed)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn the_checker_is_fetched_only_on_request_and_is_the_parity_tested_module() {
    let s = Served::new("checker");
    let docs = s.documents();
    assert_eq!(
        harness::checker_on_demand(&s.base, &docs).unwrap(),
        Vec::<String>::new()
    );
    // The page names the module the parity test ran on
    // (proof-acceptance/wasm-checker/tests/parity.rs, QED_CHECKER_WASM).
    let shipped =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/qed-checker.wasm"))
            .unwrap();
    let sha = nucleus_site::hex(<sha2::Sha256 as sha2::Digest>::digest(&shipped).as_slice());
    let verify = std::fs::read_to_string(s.dir.join("verify/index.html")).unwrap();
    assert!(verify.contains(&format!("data-sha256=\"{sha}\"")));
    // Red, four ways: a preload on the home page; the controls shown
    // without scripts; the fallback text removed; the module swapped.
    s.edit("index.html", |t| {
        t.replacen(
            "</head>",
            "<link rel=\"preload\" href=\"/checker/qed-checker.wasm\" as=\"fetch\"></head>",
            1,
        )
    });
    s.edit("verify/index.html", |t| {
        t.replace("<div id=\"checker\" hidden", "<div id=\"checker\"")
            .replace("<noscript>", "<div>")
            .replace("</noscript>", "</div>")
    });
    let mut module = shipped.clone();
    *module.last_mut().unwrap() ^= 1;
    std::fs::write(s.dir.join("checker/qed-checker.wasm"), module).unwrap();
    let found = harness::checker_on_demand(&s.base, &docs).unwrap();
    assert_eq!(found.len(), 4, "{found:?}");
    for (finding, cause) in found.iter().zip([
        "/ names the checker in <link href>",
        "is not the module /verify names",
        "shows the checker's controls",
        "has no text for readers without scripts",
    ]) {
        assert!(finding.contains(cause), "{finding} vs {cause}");
    }
}

/// The same table against a deployed site, run by hand after a deploy:
///
///   QED_LIVE_URL=https://qed.coproduct.dev QED_LIVE_BUILT=<built site dir> \
///     cargo test --test agents -- --ignored live
///
/// Paths come from the build that was deployed; every check must find
/// nothing to report.
#[test]
#[ignore = "reaches the public internet; set QED_LIVE_URL and QED_LIVE_BUILT"]
fn live_site_passes_the_table() {
    let base = std::env::var("QED_LIVE_URL").expect("QED_LIVE_URL");
    let built = PathBuf::from(std::env::var("QED_LIVE_BUILT").expect("QED_LIVE_BUILT"));
    let mut docs = Vec::new();
    let mut stack = vec![built.clone()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == "index.html") {
                let rel = p.parent().unwrap().strip_prefix(&built).unwrap();
                docs.push(format!("/{}", rel.display()).replace("//", "/"));
            }
        }
    }
    docs.sort();
    assert!(docs.len() >= 25, "{docs:?}");
    let allowed = outbound(&base);
    let checks: Vec<(&str, Vec<String>)> = vec![
        (
            "root page complete without scripts",
            harness::homepage_complete_without_script(&base, &FACTS).unwrap(),
        ),
        (
            "card discoverable",
            harness::card_discoverable(&base).unwrap(),
        ),
        (
            "card signature",
            harness::card_signature_valid(&base).unwrap(),
        ),
        (
            "transactions enumerable",
            harness::transactions_enumerable(&base).unwrap(),
        ),
        (
            "evidence within two links",
            harness::evidence_within_two_links(&base).unwrap(),
        ),
        (
            "verify covers claims",
            harness::verify_covers_each_claim(&base).unwrap(),
        ),
        (
            "threat model",
            harness::threat_model_distinguishes(&base).unwrap(),
        ),
        (
            "no account or script",
            harness::no_account_or_script_needed(&base, &docs).unwrap(),
        ),
        (
            "markdown negotiation",
            harness::markdown_negotiation(&base, &docs, &built).unwrap(),
        ),
        (
            "internal links",
            harness::internal_links_resolve(&base, &docs).unwrap(),
        ),
        (
            "nothing external",
            harness::nothing_external(&base, &docs, &allowed).unwrap(),
        ),
        (
            "checker on demand",
            harness::checker_on_demand(&base, &docs).unwrap(),
        ),
    ];
    for (name, found) in &checks {
        eprintln!("{name}: {}", if found.is_empty() { "ok" } else { "FAIL" });
    }
    let failures: Vec<_> = checks.into_iter().filter(|(_, f)| !f.is_empty()).collect();
    assert!(failures.is_empty(), "{failures:?}");
}
