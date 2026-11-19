//! `/visits`: the published visit counts, what the collector stores, the Lean
//! theorems about it, an in-browser check of the part of the argument that
//! is finite, and what none of it covers. contracts/analytics.
//!
//! The theorem statements are read from the Lean sources at build time, so
//! the page shows what the files say. The deployed collector's digest, its
//! build and the audit of the request path are inputs
//! ([`INPUT_PATH`]): facts about a machine, which no build can derive.
use crate::doc::{Block, Doc, Line, code, h2, link, t};
use crate::html::{el, tx};
use crate::{Input, Res, Software};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// The collector's deployed binary and the path audit, recorded by whoever
/// deployed it.
pub const INPUT_PATH: &str = "contracts/site/input/analytics.json";

/// The claim checked in the browser, its proof's export and its policy,
/// written by `contracts/proof-acceptance/wasm-checker/examples/visits_claim.rs`.
pub const CHECK_INPUT: &str = "contracts/site/input/visits-check";
/// Where the site serves them.
pub const CHECK_PATH: &str = "visits/check";
/// The files served from [`CHECK_INPUT`] at [`CHECK_PATH`].
pub const CHECK_FILES: [&str; 4] = ["statement.v2", "artifact.v2", "policy.json", "record.json"];
/// The Lean sources of the browser check (Lean core only).
pub const CHECK_SOURCES: [&str; 2] = [
    "contracts/analytics/browser-check/QedVisits/Statement.lean",
    "contracts/analytics/browser-check/QedVisits/Proof.lean",
];

/// Source files the page names, with their SHA-256 computed at build time.
pub const SOURCES: [(&str, &str); 6] = [
    (
        "contracts/analytics/lean/QedAnalytics/Spec.lean",
        "the meaning and the privacy theorems",
    ),
    (
        "contracts/analytics/lean/QedAnalytics/History.lean",
        "the rule until 2026-11-15, and why it was replaced",
    ),
    (
        "contracts/analytics/lean/QedAnalytics/Refines.lean",
        "the translated code computes the meaning",
    ),
    (
        "contracts/analytics/lean/QedAnalytics/Funs.lean",
        "Aeneas's translation of core.rs",
    ),
    ("contracts/analytics/src/core.rs", "the collector's core"),
    (
        "contracts/analytics/src/store.rs",
        "what is written to disk",
    ),
];

/// The full proofs the browser check does not cover, and what each holds.
pub const NOT_IN_THE_BROWSER: [(&str, &str); 3] = [
    (
        "contracts/analytics/lean/QedAnalytics/Spec.lean",
        "the noise's law sums to 1 (lap_total) and is the sampler's (difference_nonneg, difference_neg); sums over infinite sets of outputs (window_dp); every cell and window together (one_window, publication_dp); Mathlib",
    ),
    (
        "contracts/analytics/lean/QedAnalytics/Refines.lean",
        "the translated Rust computes the model's functions (handle_refines, week_refines, publish_cell_refines)",
    ),
    (
        "contracts/analytics/lean/QedAnalytics/Funs.lean",
        "the translation of core.rs those proofs are about",
    ),
];

/// The theorems shown, by file, in order.
pub const THEOREMS: [(&str, &str, &str); 17] = [
    (
        "Refines.lean",
        "core_handle_noninterference",
        "(a) translated code",
    ),
    ("Refines.lean", "core_handle_total", "translated code"),
    (
        "Refines.lean",
        "core_publish_suppresses",
        "(b) translated code",
    ),
    (
        "Refines.lean",
        "core_publish_at_least_k",
        "(b) translated code",
    ),
    (
        "Refines.lean",
        "core_publish_is_post",
        "(c) translated code",
    ),
    ("Spec.lean", "week_iff", "model: the window"),
    ("Spec.lean", "sensitivity", "model"),
    ("Spec.lean", "one_window", "model"),
    ("Spec.lean", "difference_nonneg", "model of the sampler"),
    ("Spec.lean", "postprocess", "model"),
    ("Spec.lean", "window_dp", "(c) model"),
    ("Spec.lean", "visit_dp", "(c) model"),
    ("Spec.lean", "publication_dp", "(c) model, every window"),
    ("Spec.lean", "shown_below_k", "model"),
    ("Spec.lean", "shown_zero", "model"),
    ("Spec.lean", "shown_nine", "model"),
    (
        "History.lean",
        "threshold_breaks_dp",
        "the rule until 2026-11-15",
    ),
];

/// The statement of `theorem NAME` in a Lean source: from that line to the
/// line holding `:=`, without the proof.
pub fn statement(source: &str, name: &str) -> Option<String> {
    let start = source.find(&format!("\ntheorem {name} "))? + 1;
    let rest = &source[start..];
    let end = rest.find(":=")?;
    Some(rest[..end].trim_end().to_string())
}

/// The definition of `def claim` in the browser check's statement, through
/// the line before the next blank line.
pub fn claim(source: &str) -> Option<String> {
    let start = source.find("\ndef claim : Prop :=")? + 1;
    let rest = &source[start..];
    let end = rest.find("\n\n").unwrap_or(rest.len());
    Some(rest[..end].trim_end().to_string())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// The browser check's files as the site serves them.
pub fn check_files(repository: &Path) -> Res<Vec<(String, Vec<u8>)>> {
    CHECK_FILES
        .iter()
        .map(|name| {
            let path = repository.join(CHECK_INPUT).join(name);
            let bytes = fs::read(&path).map_err(|e| format!("{CHECK_INPUT}/{name}: {e}"))?;
            Ok((format!("{CHECK_PATH}/{name}"), bytes))
        })
        .collect()
}

/// The in-browser check of the finite part: a closed box that fetches
/// nothing until asked. Only when the site serves the checker module.
fn check_section(repository: &Path, file_link: &dyn Fn(&str, &str) -> Line) -> Res<Vec<Block>> {
    let read = |path: &str| -> Res<Vec<u8>> {
        fs::read(repository.join(path)).map_err(|e| format!("{path}: {e}").into())
    };
    let record: Value = serde_json::from_slice(&read(&format!("{CHECK_INPUT}/record.json"))?)?;
    let policy: Value = serde_json::from_slice(&read(&format!("{CHECK_INPUT}/policy.json"))?)?;
    let statement = read(&format!("{CHECK_INPUT}/statement.v2"))?;
    let artifact = read(&format!("{CHECK_INPUT}/artifact.v2"))?;
    // The served bytes are the ones the record and the policy name.
    for (what, bytes, want) in [
        ("statement", &statement, text(&record["statementSha256"])),
        ("artifact", &artifact, text(&record["artifactSha256"])),
        (
            "policy statement",
            &statement,
            text(&policy["statementSha256"]),
        ),
    ] {
        if sha256(bytes) != want {
            return Err(format!("{CHECK_INPUT}: the {what} is not the one recorded").into());
        }
    }
    let mut checked = Vec::new();
    for path in CHECK_SOURCES {
        let bytes = read(path)?;
        let recorded = &record["sources"][path.rsplit_once("browser-check/").map_or(path, |p| p.1)];
        if sha256(&bytes) != text(recorded) {
            return Err(format!("{path} changed since {CHECK_INPUT} was exported").into());
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        checked.push(vec![file_link(path, name), vec![code(sha256(&bytes))]]);
    }
    let claim_text = claim(&String::from_utf8_lossy(&read(CHECK_SOURCES[0])?))
        .ok_or("the browser check's statement has no `def claim`")?;
    let mut not_checked = Vec::new();
    for (path, what) in NOT_IN_THE_BROWSER {
        let name = path.rsplit('/').next().unwrap_or(path);
        not_checked.push(vec![
            file_link(path, name),
            vec![t(what)],
            vec![code(sha256(&read(path)?))],
        ]);
    }
    let wasm_sha = sha256(crate::CHECKER_WASM);
    let wasm_url = format!("/{}", crate::CHECKER_PATH);
    let size = crate::CHECKER_WASM.len().to_string();
    let at = |name: &str| format!("/{CHECK_PATH}/{name}");
    let total_kb = (crate::CHECKER_WASM.len() + statement.len() + artifact.len()).div_ceil(1024);
    // A table, so the controls add no counted words (the site's limit,
    // `words.rs`): nothing is fetched until the button is pressed.
    let html = el(
        "table",
        &[("id", "visits-check-box")],
        [
            tx(
                "caption",
                &[],
                &format!(
                    "Run the check in this tab ({total_kb} KB download: the checker, the statement and the proof)."
                ),
            ),
            el(
                "tr",
                &[],
                [el(
                    "td",
                    &[],
                    [
                        el(
                            "noscript",
                            &[],
                            [tx(
                                "p",
                                &[],
                                "Needs JavaScript. Without it, run the example named above, or any Lean 4 checker on the statement and proof.",
                            )],
                        ),
                        el(
                            "div",
                            &[
                                ("id", "visits-check"),
                                ("hidden", ""),
                                ("data-wasm", wasm_url.as_str()),
                                ("data-sha256", wasm_sha.as_str()),
                                ("data-bytes", size.as_str()),
                                ("data-policy", at("policy.json").as_str()),
                                ("data-statement", at("statement.v2").as_str()),
                                ("data-artifact", at("artifact.v2").as_str()),
                                ("data-policy-hash", text(&record["policyHash"]).as_str()),
                            ],
                            [
                                tx(
                                    "button",
                                    &[("type", "button"), ("id", "visits-check-run")],
                                    "Check",
                                ),
                                el(
                                    "p",
                                    &[("id", "visits-check-status"), ("aria-live", "polite")],
                                    [],
                                ),
                                el("dl", &[("id", "visits-check-verdict"), ("hidden", "")], []),
                            ],
                        ),
                    ],
                )],
            ),
        ],
    );
    let declarations = record["declarations"].to_string();
    Ok(vec![
        Block::Table {
            caption: "In-browser check of the noise's ratio: what the button below runs, and on what.".into(),
            head: vec!["".into(), "".into()],
            rows: vec![
                vec![
                    vec![t("Checker")],
                    vec![
                        t("The acceptance rule /verify runs, as WebAssembly: "),
                        code(wasm_url.clone()),
                        t(format!(", {size} bytes, SHA-256 ")),
                        code(wasm_sha.clone()),
                        t(". Its SHA-256 is checked before it is compiled."),
                    ],
                ],
                vec![
                    vec![t("Statement")],
                    vec![
                        code(at("statement.v2")),
                        t(format!(
                            ", {} bytes, SHA-256 ",
                            record["statementBytes"]
                        )),
                        code(text(&record["statementSha256"])),
                        t(": the claim below and every definition it uses, from Lean core only (no Mathlib)."),
                    ],
                ],
                vec![
                    vec![t("Proof")],
                    vec![
                        code(at("artifact.v2")),
                        t(format!(", {} bytes, SHA-256 ", record["artifactBytes"])),
                        code(text(&record["artifactSha256"])),
                        t(format!(
                            ": QedVisits.proof and what it uses; {declarations} declarations are checked in all."
                        )),
                    ],
                ],
                vec![
                    vec![t("Policy")],
                    vec![
                        code(at("policy.json")),
                        t(": claim QedVisits.claim, the statement's SHA-256, axioms allowed: "),
                        code(
                            policy["permittedAxioms"]
                                .as_array()
                                .map(|a| a.iter().map(text).collect::<Vec<_>>().join(", "))
                                .unwrap_or_default(),
                        ),
                        t(". Policy hash "),
                        code(text(&record["policyHash"])),
                        t("."),
                    ],
                ],
                vec![
                    vec![t("Made with")],
                    vec![
                        t("Lean 4.30.0 and lean4export 3.1.0 (binary SHA-256 "),
                        code(text(&record["exporter"]["binarySha256"])),
                        t(") by "),
                        code("cargo run --example visits_claim"),
                        t(" in contracts/proof-acceptance/wasm-checker, which also checks the pair natively."),
                    ],
                ],
            ],
        },
        Block::Pre {
            id: "visits-claim".into(),
            text: claim_text,
            copy: None,
        },
        Block::Rendered {
            html,
            markdown: format!(
                "On the HTML page, a button runs {wasm_url} (SHA-256 {wasm_sha}) on {} and {} with {}.",
                at("statement.v2"),
                at("artifact.v2"),
                at("policy.json")
            ),
        },
        Block::Table {
            caption: "Checked by the button: the files of the claim and its proof.".into(),
            head: vec!["File".into(), "SHA-256".into()],
            rows: checked,
        },
        Block::Table {
            caption: "Not checked by the button: the pointwise ratio is all it covers. These Mathlib proofs hold the rest; check them with Lean (lake build in contracts/analytics/lean).".into(),
            head: vec!["File".into(), "What it proves".into(), "SHA-256".into()],
            rows: not_checked,
        },
    ])
}

pub fn page(input: &Input, repository: &Path, checker_served: bool) -> Res<Doc> {
    let base = match &input.software {
        Software::Public { url } => Some(format!("{}/blob/main", url.trim_end_matches('/'))),
        _ => None,
    };
    let file_link = |path: &str, label: &str| -> Line {
        match &base {
            Some(base) => vec![link(format!("{base}/{path}"), label.to_string())],
            None => vec![code(label.to_string())],
        }
    };
    let read = |path: &str| -> Res<String> {
        fs::read_to_string(repository.join(path)).map_err(|e| format!("{path}: {e}").into())
    };
    let mut statements = String::new();
    let mut theorem_rows = Vec::new();
    for (file, name, over) in THEOREMS {
        let path = format!("contracts/analytics/lean/QedAnalytics/{file}");
        let source = read(&path)?;
        let stated =
            statement(&source, name).ok_or_else(|| format!("{path}: no theorem {name}"))?;
        statements.push_str(&stated);
        statements.push_str("\n\n");
        theorem_rows.push(vec![
            vec![code(name)],
            vec![t(over)],
            file_link(&path, file),
        ]);
    }
    let mut file_rows = Vec::new();
    for (path, what) in SOURCES {
        let digest = sha256(read(path)?.as_bytes());
        let name = path.rsplit('/').next().unwrap_or(path);
        file_rows.push(vec![
            file_link(path, name),
            vec![t(what)],
            vec![code(digest)],
        ]);
    }
    let recorded: Option<Value> = match fs::read(repository.join(INPUT_PATH)) {
        Ok(bytes) => {
            Some(serde_json::from_slice(&bytes).map_err(|e| format!("{INPUT_PATH}: {e}"))?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{INPUT_PATH}: {e}").into()),
    };
    let mut not_proved: Vec<Vec<Line>> = Vec::new();
    match &recorded {
        Some(r) => {
            let c = &r["collector"];
            not_proved.push(vec![
                vec![t(
                    "The binary answering /analytics/beacon is built from this source",
                )],
                vec![
                    t("SHA-256 "),
                    code(text(&c["sha256"])),
                    t(format!(
                        " on the host. Built twice from scratch with the same result from {}, on {}, with ",
                        text(&c["source"]),
                        text(&c["built"]),
                    )),
                    code(text(&c["command"])),
                ],
            ]);
            for row in r["audit"]["rows"].as_array().into_iter().flatten() {
                not_proved.push(vec![vec![t(text(&row[0]))], vec![t(text(&row[1]))]]);
            }
        }
        None => not_proved.push(vec![
            vec![t(
                "The binary answering /analytics/beacon is built from this source",
            )],
            vec![t("No deployed binary is recorded.")],
        ]),
    }
    not_proved.extend([
        vec![
            vec![t("The noise is fair")],
            vec![
                t("Two counts of 1 bits before a 0 bit, from "),
                code("/dev/urandom"),
                t("; the law of their difference is a theorem, the bytes are the operating system's."),
            ],
        ],
        vec![
            vec![t("A cell under 10 is never shown")],
            vec![
                t("Not since 2026-11-15: a cell with true count c under 10 is shown with probability 1/(3 · 2^(9 − c)), 1/1536 at 0 and 1/3 at 9 ("),
                code("shown_below_k"),
                t("). The rule before it read the true count and never showed one, and was not differentially private between 9 and 10 ("),
                code("threshold_breaks_dp"),
                t("). No day was published under it."),
            ],
        ],
        vec![
            vec![t("Several beacons from one browser")],
            vec![
                t("Each beacon is ε = ln 2; m beacons, m · ln 2 ("),
                code("window_ratio"),
                t("). This site's script sends at most one beacon per label per UTC day (a list of labels sent today, in localStorage), so a browser that runs it sends at most 16 a day: 16 · ln 2 a day, 112 · ln 2 a week. That is a convention of the script, not enforced by the collector, which cannot tell browsers apart: a sender that does not run the script is limited only by the rate limit."),
            ],
        ],
        vec![
            vec![t("Days published before 2026-11-18")],
            vec![t("Until 2026-11-18 each UTC day was published on its own (ε = ln 2 per day per beacon). Those lines stay in /analytics/published, labelled as days. The first week is counted from the day the weekly collector started; its earlier days were published as days. No beacon is in both.")],
        ],
    ]);

    let table = el(
        "div",
        &[("id", "visits")],
        [
            tx("p", &[("id", "visits-status"), ("aria-live", "polite")], ""),
            el(
                "p",
                &[],
                [el(
                    "a",
                    &[("href", "/analytics/published")],
                    [tx("code", &[], "/analytics/published")],
                )],
            ),
        ],
    );
    let stored = "Everything the collector stores, in /var/lib/qed-analytics:\n\n\
window.json (replaced at most once a minute):\n\
{\"record\":\"qed-visits-window/1\",\"window\":2968,\"from\":20773,\"cells\":[0,0,3,1,…34 counts]}\n\n\
published.jsonl (one line per finished week, appended once):\n\
{\"record\":\"qed-visits-week/1\",\"week\":2968,\"from\":\"2026-11-16\",\"to\":\"2026-11-22\",\"days\":7,\n \"k\":10,\"suppressed\":\"count plus noise under k\",\n \"paths\":[[\"/\",null,12],[\"/status\",14,null],…],\"malformed\":null,\"limited\":null}\n\n\
Lines written before 2026-11-18 are days, {\"record\":\"qed-visits/1\",\"day\":20772,\"date\":\"2026-11-15\",…}, kept as history.";
    let mut blocks = vec![
        Block::Table {
            caption: "One beacon per page view, POST /analytics/beacon.".into(),
            head: vec!["Sent".into(), "Value".into()],
            rows: vec![
                vec![vec![t("The page's label")], vec![code("/status")]],
                vec![
                    vec![t("Whether this browser sent one earlier that day (UTC)")],
                    vec![
                        code("0"),
                        t(" or "),
                        code("1"),
                        t(", from this browser's localStorage"),
                    ],
                ],
                vec![
                    vec![t("How often")],
                    vec![t("At most once per label per UTC day from this browser: the script keeps today's date and the labels it sent today under one localStorage key, and sends nothing if it cannot read and write it. Enforced by the script, not by the collector.")],
                ],
                vec![
                    vec![t("Anything else")],
                    vec![t("Nothing: no cookie or identifier, and the host removes every header, the address included, before the collector reads the request.")],
                ],
            ],
        },
        Block::Rendered {
            html: table,
            markdown: "Published weeks (and, before 2026-11-18, days), as JSON: /analytics/published.".into(),
        },
        Block::Pre {
            id: "visits-stored".into(),
            text: stored.into(),
            copy: None,
        },
        h2("theorems", "Theorems"),
        Block::Table {
            caption: "Lean 4.30.0; translation by Charon and Aeneas (release nightly-2026.06.10). Axioms: propext, Classical.choice, Quot.sound.".into(),
            head: vec!["Theorem".into(), "Over".into(), "File".into()],
            rows: theorem_rows,
        },
        Block::Pre {
            id: "visits-statements".into(),
            text: statements.trim_end().into(),
            copy: None,
        },
        Block::Table {
            caption: "Sources, SHA-256 of this build's copies.".into(),
            head: vec!["File".into(), "What".into(), "SHA-256".into()],
            rows: file_rows,
        },
        Block::Table {
            caption: "k chosen 2026-11-15, weeks 2026-11-18; the owner may change them.".into(),
            head: vec!["".into(), "Value".into()],
            rows: vec![
                vec![vec![t("Window")], vec![t("A week, Monday 00:00 UTC to Sunday 24:00 UTC; published after it ends. Until 2026-11-18, a UTC day.")]],
                vec![vec![t("k")], vec![t("10: a cell whose count plus noise is under 10 is suppressed; nothing under 10 is published. A true count c under 10 is shown with probability 1/(3 · 2^(9 − c)): 1/1536 at 0, 1/3 at 9. At noise standard deviation 2, a shown count is within ±2 of its true value with probability 5/6.")]],
                vec![vec![t("ε")], vec![t("ln 2 per beacon, for the whole publication: one beacon changes one cell of one week by one, which changes that week's noisy likelihood by at most a factor of 2, and suppression reads only the noisy value. Cells and weeks hold disjoint beacons (one_window, publication_dp).")]],
                vec![vec![t("Noise")], vec![t("P(z) = 2^-|z| / 3, drawn once per cell per week; a week is never published twice.")]],
                vec![vec![t("Cells")], vec![t("16 paths × 2, plus malformed and rate-limited: 34 a week.")]],
                vec![vec![t("Rate limit")], vec![t("600 at once, 5 a second, for all senders together; no address is kept.")]],
            ],
        },
    ];
    if checker_served {
        blocks.extend(check_section(repository, &file_link)?);
    }
    blocks.extend([
        h2("not-proved", "Not proved"),
        Block::Table {
            caption: recorded
                .as_ref()
                .map(|r| format!("Checked {}.", text(&r["audit"]["checked"])))
                .unwrap_or_default(),
            head: vec!["".into(), "Where it stands".into()],
            rows: not_proved,
        },
    ]);
    Ok(Doc {
        path: "visits".into(),
        title: "Visits — QED".into(),
        description: "Visit counts per week, path and first-visit bit, published with noise and suppressed when count plus noise is under 10; what is stored; the Lean theorems about the collector, a check of the noise's ratio in the browser, and what they do not cover.".into(),
        heading: "Visits".into(),
        blocks,
        script: true,
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_statement_stops_before_its_proof() {
        let source = "x\ntheorem foo (a : Nat) :\n    a = a := by\n  rfl\n";
        assert_eq!(
            statement(source, "foo").as_deref(),
            Some("theorem foo (a : Nat) :\n    a = a")
        );
        assert!(statement(source, "fo").is_none());
    }

    #[test]
    fn the_claim_is_its_definition() {
        let source = "x\n/-- doc -/\ndef claim : Prop :=\n  True ∧\n  True\n\nend X\n";
        assert_eq!(
            claim(source).as_deref(),
            Some("def claim : Prop :=\n  True ∧\n  True")
        );
    }
}
