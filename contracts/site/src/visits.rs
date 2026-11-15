//! `/visits`: the published visit counts, what the collector stores, the Lean
//! theorems about it, and what they do not cover. contracts/analytics.
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

/// Source files the page names, with their SHA-256 computed at build time.
pub const SOURCES: [(&str, &str); 5] = [
    (
        "contracts/analytics/lean/QedAnalytics/Spec.lean",
        "the meaning and the privacy theorems",
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

/// The theorems shown, by file, in order.
pub const THEOREMS: [(&str, &str, &str); 9] = [
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
    ("Refines.lean", "core_publish_is_spec", "translated code"),
    ("Spec.lean", "sensitivity", "model"),
    ("Spec.lean", "difference_nonneg", "model of the sampler"),
    ("Spec.lean", "day_dp", "(c) model"),
    ("Spec.lean", "visit_dp", "(c) model"),
    ("Spec.lean", "threshold_breaks_dp", "model"),
];

/// The statement of `theorem NAME` in a Lean source: from that line to the
/// line holding `:=`, without the proof.
pub fn statement(source: &str, name: &str) -> Option<String> {
    let start = source.find(&format!("\ntheorem {name} "))? + 1;
    let rest = &source[start..];
    let end = rest.find(":=")?;
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

pub fn page(input: &Input, repository: &Path) -> Res<Doc> {
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
            vec![t("A cell crossing 10")],
            vec![
                code("threshold_breaks_dp"),
                t(": suppressing on the true count is not differentially private where a cell moves between 9 and 10."),
            ],
        ],
        vec![
            vec![t("Several beacons from one browser")],
            vec![t("Each beacon is ε = ln 2; m beacons in a day, m · ln 2.")],
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
today.json (replaced at most once a minute):\n\
{\"record\":\"qed-visits-today/1\",\"day\":20772,\"cells\":[0,0,3,1,…34 counts]}\n\n\
published.jsonl (one line per finished day, appended once):\n\
{\"record\":\"qed-visits/1\",\"day\":20772,\"date\":\"2026-11-15\",\"k\":10,\n \"paths\":[[\"/\",null,12],[\"/status\",14,null],…],\"malformed\":null,\"limited\":null}";
    let blocks = vec![
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
                        t(", from a date in this browser's localStorage"),
                    ],
                ],
                vec![
                    vec![t("Anything else")],
                    vec![t("Nothing: no cookie or identifier, and the host removes every header, the address included, before the collector reads the request.")],
                ],
            ],
        },
        Block::Rendered {
            html: table,
            markdown: "Published days, as JSON: /analytics/published.".into(),
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
            caption: "Chosen 2026-11-15; the owner may change them.".into(),
            head: vec!["".into(), "Value".into()],
            rows: vec![
                vec![vec![t("k")], vec![t("10: a cell under 10 beacons is suppressed. At noise standard deviation 2, a shown count is within ±2 of its true value with probability 5/6.")]],
                vec![vec![t("ε")], vec![t("ln 2 per day per beacon: one beacon changes one cell by one, which changes any output's likelihood by at most a factor of 2. Days and cells hold disjoint beacons, so they compose in parallel.")]],
                vec![vec![t("Noise")], vec![t("P(z) = 2^-|z| / 3, drawn once per cell per day; a day is never published twice.")]],
                vec![vec![t("Cells")], vec![t("16 paths × 2, plus malformed and rate-limited: 34 a day.")]],
                vec![vec![t("Rate limit")], vec![t("600 at once, 5 a second, for all senders together; no address is kept.")]],
            ],
        },
        h2("not-proved", "Not proved"),
        Block::Table {
            caption: recorded
                .as_ref()
                .map(|r| format!("Checked {}.", text(&r["audit"]["checked"])))
                .unwrap_or_default(),
            head: vec!["".into(), "Where it stands".into()],
            rows: not_proved,
        },
    ];
    Ok(Doc {
        path: "visits".into(),
        title: "Visits — QED".into(),
        description: "Visit counts per day, path and first-visit bit, published with noise and suppression under 10; what is stored; the Lean theorems about the collector, and what they do not cover.".into(),
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
}
