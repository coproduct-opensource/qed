//! The Lean Proof Board (`/board`): open-source Lean repositories ranked by
//! their QED Check verdict, with the verdict files themselves served beside
//! the page so every row is checkable from its link.
//!
//! The input is `input/board/`: `board.json` (the ordered rows) and one
//! `qed-check-verdict/1` file per row under `verdicts/<owner>__<repo>/`.
//! [`derive`] makes both from the board page the leaderboard tool wrote and
//! the verdicts it ran (`cargo run --example board`); [`read`] checks them
//! against each other before a build uses them. The tier, the kernel count
//! and the order are recomputed from the verdicts on every build, by the
//! rules the leaderboard tool uses, so `board.json` cannot drift from them.
//!
//! The right column is a model's opinion. It never moves a row: the order is
//! tier, then kernels that accepted, then stars, then name.
use crate::Res;
use crate::doc::{Block, Doc, link, p, t};
use crate::html::{Html, el, tx};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

/// Where the board's input sits, relative to the repository root.
pub const INPUT_DIR: &str = "contracts/site/input/board";
/// The page's route.
pub const PATH: &str = "board";
/// `board.json`'s schema.
pub const SCHEMA: &str = "qed-board/1";
/// The verdict schema each row's file must carry.
pub const VERDICT_SCHEMA: &str = "qed-check-verdict/1";
/// What the opinion column says until a model's summary is approved.
pub const AWAITING: &str = "awaiting model approval";
/// How much of a verdict's reasons a row shows; the verdict holds the rest.
/// The leaderboard tool's `REASON_CHARS`.
pub const REASON_CHARS: usize = 240;
/// What a checking host's work directory is written as, in a verdict that
/// named it (see [`derive`]).
pub const REDACTED_WORK_DIR: &str = "$SRC/";
/// Strings no committed board file may hold: home-directory prefixes.
pub const HOME_PREFIXES: [&str; 2] = ["/home/", "/Users/"];
/// The page's columns, as the leaderboard tool writes them.
pub const COLUMNS: [&str; 4] = [
    "#",
    "Repository",
    "Proofs (QED Check)",
    "LLM summary — opinion",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Board {
    pub schema: String,
    /// Unix seconds at which the leaderboard tool wrote the board.
    pub generated_at: u64,
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Row {
    pub rank: usize,
    /// `owner/name` on GitHub.
    pub repository: String,
    pub url: String,
    pub license: String,
    pub stars: u64,
    /// The Lean toolchain's version, as the board shows it (`v4.35.0`).
    pub toolchain: String,
    /// `acceptedByAll` | `acceptedBySome` | `rejected` | `couldNotRun`.
    pub tier: String,
    pub kernels: Kernels,
    /// The verdict's own reasons, cut at [`REASON_CHARS`]; none when accepted.
    pub why: Option<String>,
    /// The verdict file, relative to `input/board/` and to `/board/`.
    pub verdict: String,
    /// SHA-256 of the verdict file as committed and served.
    pub verdict_sha256: String,
    /// SHA-256 of the verdict file as QED Check wrote it. Differs from
    /// `verdictSha256` only where a host work directory was redacted.
    pub source_verdict_sha256: String,
    /// The opinion column.
    pub summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernels {
    pub accepted: usize,
    pub total: usize,
}

/// Files as (relative path, bytes), as the site builds them.
pub type Files = Vec<(String, Vec<u8>)>;

/// The board as a build uses it: the rows and each verdict's bytes, in row
/// order, as (path under `input/board/`, bytes).
#[derive(Clone, Debug)]
pub struct Loaded {
    pub board: Board,
    pub verdicts: Vec<(String, Vec<u8>)>,
}

/// The tier of a `qed-check-verdict/1` document (the leaderboard tool's
/// `tier_of`).
pub fn tier_of(verdict: &Value) -> &'static str {
    match verdict["outcome"]["kind"].as_str() {
        Some("Accepted") => "acceptedByAll",
        Some("Disagreement") => "acceptedBySome",
        Some("Rejected") => "rejected",
        _ => "couldNotRun",
    }
}

/// QED Check's words for a tier, as the leaderboard tool prints them.
pub fn tier_label(tier: &str) -> &'static str {
    match tier {
        "acceptedByAll" => "accepted by every kernel",
        "acceptedBySome" => "kernels disagree",
        "rejected" => "rejected",
        _ => "could not run",
    }
}

fn tier_rank(tier: &str) -> u8 {
    match tier {
        "acceptedByAll" => 0,
        "acceptedBySome" => 1,
        "rejected" => 2,
        _ => 3,
    }
}

/// Kernels that accepted, of those the verdict lists.
pub fn kernel_agreement(verdict: &Value) -> Kernels {
    let ks = verdict["kernels"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    Kernels {
        accepted: ks
            .iter()
            .filter(|k| k["result"]["kind"].as_str() == Some("Accepted"))
            .count(),
        total: ks.len(),
    }
}

/// The verdict's reasons for any outcome but `Accepted`, joined with "; "
/// and cut at [`REASON_CHARS`] characters with "…".
pub fn reason_of(verdict: &Value) -> Option<String> {
    if verdict["outcome"]["kind"].as_str() == Some("Accepted") {
        return None;
    }
    let all: Vec<&str> = verdict["outcome"]["reasons"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let joined = all.join("; ");
    if joined.chars().count() <= REASON_CHARS {
        return Some(joined);
    }
    Some(joined.chars().take(REASON_CHARS).chain(['…']).collect())
}

/// Where a repository's verdict sits under `input/board/` and `/board/`.
pub fn verdict_path(repository: &str) -> String {
    format!("verdicts/{}/verdict.json", repository.replace('/', "__"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}

fn home_prefix(text: &str) -> Option<&'static str> {
    HOME_PREFIXES.into_iter().find(|p| text.contains(p))
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The text between `start` and the next `end` in `text`, and what follows.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Res<(&'a str, &'a str)> {
    let from = text
        .find(start)
        .ok_or_else(|| format!("no {start:?} in {text:.80}"))?
        + start.len();
    let rest = &text[from..];
    let to = rest
        .find(end)
        .ok_or_else(|| format!("no {end:?} after {start:?}"))?;
    Ok((&rest[..to], &rest[to + end.len()..]))
}

/// One row as the leaderboard tool's page prints it.
struct PageRow {
    rank: usize,
    url: String,
    repository: String,
    license: String,
    stars: u64,
    toolchain: String,
    tier: String,
    label: String,
    kernels: Kernels,
    verdict_href: String,
    why: Option<String>,
    summary: String,
}

fn page_row(line: &str) -> Res<PageRow> {
    for unsupported in ["class=\"sponsored\"", "class=\"tag\"", "t-none"] {
        if line.contains(unsupported) {
            return Err(format!("a row with {unsupported} is not supported: {line:.120}").into());
        }
    }
    let (rank, rest) = between(line, "<td class=\"n\">", "</td>")?;
    let (url, rest) = between(rest, "<a href=\"", "\">")?;
    let (repository, rest) = between(rest, "", "</a>")?;
    let (meta, rest) = between(rest, "<div class=\"why\">", "</div>")?;
    let meta = unescape(meta);
    let parts: Vec<&str> = meta.split(" · ").collect();
    let [license, stars, toolchain] = parts.as_slice() else {
        return Err(format!("{repository}: license · stars · toolchain, not {meta:?}").into());
    };
    let stars = stars
        .strip_prefix("★ ")
        .ok_or_else(|| format!("{repository}: stars {stars:?}"))?
        .parse()?;
    let (tier, rest) = between(rest, "<span class=\"tier t-", "\">")?;
    let (label, rest) = between(rest, "", "</span>")?;
    let (k, rest) = between(rest, "<span class=\"k\">", " kernels</span>")?;
    let (accepted, total) = k
        .split_once('/')
        .ok_or_else(|| format!("{repository}: kernels {k:?}"))?;
    let (verdict_href, rest) = between(rest, "<a href=\"", "\">verdict</a>")?;
    let (proof_rest, opinion) = between(rest, "", "<td class=\"op\">")?;
    let why = if proof_rest.contains("<div class=\"why\">") {
        Some(unescape(
            between(proof_rest, "<div class=\"why\">", "</div>")?.0,
        ))
    } else {
        None
    };
    let (summary, _) = between(opinion, "<span class=\"await\">", "</span>")?;
    Ok(PageRow {
        rank: rank.parse()?,
        url: unescape(url),
        repository: unescape(repository),
        license: (*license).to_owned(),
        stars,
        toolchain: (*toolchain).to_owned(),
        tier: tier.to_owned(),
        label: unescape(label),
        kernels: Kernels {
            accepted: accepted.parse()?,
            total: total.parse()?,
        },
        verdict_href: unescape(verdict_href),
        why,
        summary: unescape(summary),
    })
}

/// `board.json` and the verdict files to commit under `input/board/`, from
/// the page the leaderboard tool wrote (`index_html`) and the verdicts it
/// links (`verdict`, called with each link as the page writes it).
///
/// Every value the page prints is checked against the verdict it links: the
/// repository, the tier and its words, the kernel count, the reasons and the
/// toolchain. Any disagreement is an error, not a choice.
///
/// `host_work_dir`: a checking host's work directory that verdicts name in
/// build errors. Each occurrence, in the verdicts and in the reasons, is
/// written [`REDACTED_WORK_DIR`] and the row keeps the original file's hash
/// in `sourceVerdictSha256`. The prefix is passed at run time and never
/// written into the tree. A home-directory prefix left in any output is an
/// error.
pub fn derive(
    index_html: &str,
    verdict: &dyn Fn(&str) -> Res<Vec<u8>>,
    host_work_dir: Option<&str>,
) -> Res<(Board, Files)> {
    let (generated, _) = between(index_html, "Generated at unix time ", ".")?;
    let generated_at: u64 = generated.parse()?;
    let redact = |text: &str| -> String {
        match host_work_dir {
            Some(dir) if !dir.is_empty() => text.replace(dir, REDACTED_WORK_DIR),
            _ => text.to_owned(),
        }
    };
    let mut rows = Vec::new();
    let mut files = Vec::new();
    for line in index_html
        .lines()
        .filter(|l| l.starts_with("<tr><td class=\"n\">"))
    {
        let r = page_row(line)?;
        let name = &r.repository;
        let source = verdict(&r.verdict_href)?;
        let v: Value = serde_json::from_slice(&source).map_err(|e| format!("{name}: {e}"))?;
        if v["schema"] != VERDICT_SCHEMA {
            return Err(format!("{name}: schema {}", v["schema"]).into());
        }
        if v["subject"]["repository"].as_str() != Some(name) {
            return Err(
                format!("{name}: the verdict is for {}", v["subject"]["repository"]).into(),
            );
        }
        let tier = tier_of(&v);
        if r.tier != tier || r.label != tier_label(tier) {
            return Err(format!(
                "{name}: the page says {} ({}), the verdict {tier}",
                r.tier, r.label
            )
            .into());
        }
        if r.kernels != kernel_agreement(&v) {
            return Err(format!("{name}: the page's kernel count is not the verdict's").into());
        }
        if r.why != reason_of(&v) {
            return Err(format!("{name}: the page's reasons are not the verdict's").into());
        }
        if let Some(tc) = v["toolchain"]["name"].as_str()
            && tc.rsplit(':').next() != Some(r.toolchain.as_str())
        {
            return Err(format!("{name}: toolchain {tc}, the page says {}", r.toolchain).into());
        }
        if r.url != format!("https://github.com/{name}") {
            return Err(format!("{name}: url {}", r.url).into());
        }
        let committed = redact(std::str::from_utf8(&source)?).into_bytes();
        let path = verdict_path(name);
        let row = Row {
            rank: r.rank,
            repository: name.clone(),
            url: r.url,
            license: r.license,
            stars: r.stars,
            toolchain: r.toolchain,
            tier: tier.to_owned(),
            kernels: r.kernels,
            why: r.why.as_deref().map(redact),
            verdict: path.clone(),
            verdict_sha256: sha256_hex(&committed),
            source_verdict_sha256: sha256_hex(&source),
            summary: r.summary,
        };
        files.push((path, committed));
        rows.push(row);
    }
    let board = Board {
        schema: SCHEMA.into(),
        generated_at,
        rows,
    };
    let json = board_json(&board)?;
    files.insert(0, ("board.json".into(), json));
    for (path, bytes) in &files {
        if let Some(prefix) = home_prefix(&String::from_utf8_lossy(bytes)) {
            return Err(format!(
                "{path} holds {prefix}: pass the checking host's work directory to redact it"
            )
            .into());
        }
    }
    check(&board, &files[1..])?;
    Ok((board, files))
}

/// `board.json`'s bytes: pretty JSON and a newline.
pub fn board_json(board: &Board) -> Res<Vec<u8>> {
    let mut text = serde_json::to_string_pretty(board)?;
    text.push('\n');
    Ok(text.into_bytes())
}

/// What a build refuses: ranks that are not 1..n in order, an order other
/// than the leaderboard's, a verdict file missing, changed or holding a
/// home-directory prefix, or a row whose tier, kernel count, repository or
/// (for an unredacted verdict) reasons are not its verdict's.
pub fn check(board: &Board, verdicts: &[(String, Vec<u8>)]) -> Res<()> {
    if board.schema != SCHEMA {
        return Err(format!("board.json schema {}", board.schema).into());
    }
    if verdicts.len() != board.rows.len() {
        return Err("one verdict file per row".into());
    }
    let mut seen = BTreeSet::new();
    for (n, (row, (path, bytes))) in board.rows.iter().zip(verdicts).enumerate() {
        let name = &row.repository;
        if row.rank != n + 1 {
            return Err(format!("{name}: rank {} at position {}", row.rank, n + 1).into());
        }
        if !seen.insert(name.clone()) {
            return Err(format!("{name}: listed twice").into());
        }
        if *path != row.verdict || row.verdict != verdict_path(name) {
            return Err(format!("{name}: verdict path {}", row.verdict).into());
        }
        if sha256_hex(bytes) != row.verdict_sha256 {
            return Err(format!("{name}: {path} is not the file board.json names").into());
        }
        let text = std::str::from_utf8(bytes)?;
        if let Some(prefix) = home_prefix(text) {
            return Err(format!("{path} holds {prefix}").into());
        }
        let v: Value = serde_json::from_str(text).map_err(|e| format!("{path}: {e}"))?;
        if v["schema"] != VERDICT_SCHEMA || v["subject"]["repository"].as_str() != Some(name) {
            return Err(format!("{path}: not a {VERDICT_SCHEMA} verdict for {name}").into());
        }
        if row.tier != tier_of(&v) || row.kernels != kernel_agreement(&v) {
            return Err(format!("{name}: tier or kernel count is not the verdict's").into());
        }
        let redacted = row.verdict_sha256 != row.source_verdict_sha256;
        if redacted {
            if row.why.is_some() != reason_of(&v).is_some() {
                return Err(format!("{name}: reasons present on one side only").into());
            }
        } else if row.why != reason_of(&v) {
            return Err(format!("{name}: the reasons are not the verdict's").into());
        }
        if row.url != format!("https://github.com/{name}") {
            return Err(format!("{name}: url {}", row.url).into());
        }
    }
    for pair in board.rows.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let order = tier_rank(&a.tier)
            .cmp(&tier_rank(&b.tier))
            .then(b.kernels.accepted.cmp(&a.kernels.accepted))
            .then(b.stars.cmp(&a.stars))
            .then(a.repository.cmp(&b.repository));
        if order != std::cmp::Ordering::Less {
            return Err(format!(
                "{} is ranked above {} out of the board's order",
                a.repository, b.repository
            )
            .into());
        }
    }
    Ok(())
}

/// The committed board, checked, or `None` when the input has none.
pub fn read(repository: &Path) -> Res<Option<Loaded>> {
    let dir = repository.join(INPUT_DIR);
    let bytes = match fs::read(dir.join("board.json")) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{INPUT_DIR}/board.json: {e}").into()),
    };
    let board: Board =
        serde_json::from_slice(&bytes).map_err(|e| format!("{INPUT_DIR}/board.json: {e}"))?;
    let verdicts = board
        .rows
        .iter()
        .map(|r| {
            let bytes = fs::read(dir.join(&r.verdict))
                .map_err(|e| format!("{INPUT_DIR}/{}: {e}", r.verdict))?;
            Ok((r.verdict.clone(), bytes))
        })
        .collect::<Res<Vec<_>>>()?;
    check(&board, &verdicts)?;
    Ok(Some(Loaded { board, verdicts }))
}

/// The files the build serves besides the page: each verdict at
/// `/board/<verdict>`, byte for byte, and `board.json`.
pub fn files(loaded: &Loaded) -> Res<Vec<(String, Vec<u8>)>> {
    let mut out = vec![(format!("{PATH}/board.json"), board_json(&loaded.board)?)];
    out.extend(
        loaded
            .verdicts
            .iter()
            .map(|(path, bytes)| (format!("{PATH}/{path}"), bytes.clone())),
    );
    Ok(out)
}

/// A row's verdict link, as the page writes it.
pub fn verdict_href(row: &Row) -> String {
    format!("/{PATH}/{}", row.verdict)
}

fn meta(row: &Row) -> String {
    format!("{} · ★ {} · {}", row.license, row.stars, row.toolchain)
}

fn kernels_text(row: &Row) -> String {
    format!("{}/{} kernels", row.kernels.accepted, row.kernels.total)
}

/// The board's table: the leaderboard tool's columns and order, in the
/// site's markup. A `Block::Table` cannot carry the tier's class, so the
/// HTML is made here; the Markdown twin is that same table as a
/// `Block::Table`.
fn table(board: &Board) -> Block {
    let caption = format!(
        "{} repositories, in the board's order: tier, then kernels that accepted, then stars.",
        board.rows.len()
    );
    let html = el(
        "div",
        &[("class", "scroll board")],
        [el(
            "table",
            &[],
            [
                tx("caption", &[], &caption),
                el(
                    "thead",
                    &[],
                    [el(
                        "tr",
                        &[],
                        COLUMNS.iter().map(|h| tx("th", &[("scope", "col")], h)),
                    )],
                ),
                el(
                    "tbody",
                    &[],
                    board.rows.iter().map(|r| {
                        let tier_class = format!("tier t-{}", r.tier);
                        let href = verdict_href(r);
                        let mut proof = vec![
                            tx("span", &[("class", &tier_class)], tier_label(&r.tier)),
                            Html::text(" "),
                            tx("span", &[("class", "k")], &kernels_text(r)),
                            Html::text(" "),
                            tx("a", &[("href", &href)], "verdict"),
                        ];
                        if let Some(why) = &r.why {
                            proof.push(tx("div", &[("class", "why")], why));
                        }
                        el(
                            "tr",
                            &[],
                            [
                                tx("th", &[("scope", "row")], &r.rank.to_string()),
                                el(
                                    "td",
                                    &[],
                                    [
                                        tx("a", &[("href", &r.url)], &r.repository),
                                        tx("div", &[("class", "why")], &meta(r)),
                                    ],
                                ),
                                el("td", &[], proof),
                                el(
                                    "td",
                                    &[("class", "op")],
                                    [tx("span", &[("class", "await")], &r.summary)],
                                ),
                            ],
                        )
                    }),
                ),
            ],
        )],
    );
    let markdown = crate::doc::block_markdown(&Block::Table {
        caption,
        head: COLUMNS.iter().map(|h| (*h).to_owned()).collect(),
        rows: board
            .rows
            .iter()
            .map(|r| {
                let mut proof = vec![
                    t(format!("{} · {} · ", tier_label(&r.tier), kernels_text(r))),
                    link(verdict_href(r), "verdict"),
                ];
                if let Some(why) = &r.why {
                    proof.push(t(format!(" · {why}")));
                }
                vec![
                    vec![t(r.rank.to_string())],
                    vec![
                        link(r.url.clone(), r.repository.clone()),
                        t(format!(" · {}", meta(r))),
                    ],
                    proof,
                    vec![t(r.summary.clone())],
                ]
            })
            .collect(),
    });
    Block::Rendered {
        html,
        markdown: markdown.trim_end().to_owned(),
    }
}

/// The `/board` page.
pub fn page(board: &Board) -> Doc {
    let redacted = board
        .rows
        .iter()
        .filter(|r| r.verdict_sha256 != r.source_verdict_sha256)
        .count();
    let mut blocks = vec![
        p(vec![t(format!(
            "Open-source Lean repositories, ranked by their QED Check verdict. The right column is a model's opinion of practical use; it never changes a row's rank. Generated at unix time {} ({}).",
            board.generated_at,
            crate::pages::date(board.generated_at)
        ))]),
        p(vec![t(
            "Each row links the verdict file QED Check wrote; its tier and kernel count are read from that file. Out of memory refutes nothing: a kernel stopped at the memory limit could not run, which is not a rejection; check on a larger machine.",
        )]),
    ];
    let mut sources = vec![
        t("The rows as data: "),
        link(format!("/{PATH}/board.json"), "board.json"),
        t("."),
    ];
    if redacted > 0 {
        sources.push(t(format!(
            " In {redacted} verdicts the checking host's work directory is written {REDACTED_WORK_DIR}; for those, sourceVerdictSha256 in board.json is the SHA-256 of the file as QED Check wrote it."
        )));
    }
    blocks.push(p(sources));
    blocks.push(table(board));
    Doc {
        path: PATH.into(),
        title: "Lean Proof Board — QED".into(),
        description: "Open-source Lean repositories ranked by their QED Check verdict, each row linked to its verdict file.".into(),
        heading: "Lean Proof Board".into(),
        blocks,
        script: false,
        data: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const INDEX: &str = "<p class=\"sub\">Generated at unix time 1700000000.</p>\n\
<tr><td class=\"n\">1</td><td><a href=\"https://github.com/a/one\">a/one</a><div class=\"why\">MIT · ★ 5 · v4.35.0</div></td><td><span class=\"tier t-acceptedByAll\">accepted by every kernel</span> <span class=\"k\">1/1 kernels</span> <a href=\"work/verdicts/a__one/verdict.json\">verdict</a></td><td class=\"op\"><span class=\"await\">awaiting model approval</span></td></tr>\n\
<tr><td class=\"n\">2</td><td><a href=\"https://github.com/b/two\">b/two</a><div class=\"why\">MIT · ★ 9 · v4.35.0</div></td><td><span class=\"tier t-rejected\">rejected</span> <span class=\"k\">0/1 kernels</span> <a href=\"work/verdicts/b__two/verdict.json\">verdict</a><div class=\"why\">build: /home/x/w/src/b/lakefile.lean failed</div></td><td class=\"op\"><span class=\"await\">awaiting model approval</span></td></tr>\n";

    fn verdict(href: &str) -> Res<Vec<u8>> {
        let (repo, kind, reasons) = if href.contains("a__one") {
            ("a/one", "Accepted", "")
        } else {
            (
                "b/two",
                "Rejected",
                ", \"reasons\": [\"build: /home/x/w/src/b/lakefile.lean failed\"]",
            )
        };
        let k = if kind == "Accepted" {
            "Accepted"
        } else {
            "Rejected"
        };
        Ok(format!(
            "{{\"schema\": \"qed-check-verdict/1\", \"outcome\": {{\"kind\": \"{kind}\"{reasons}}}, \"subject\": {{\"repository\": \"{repo}\"}}, \"toolchain\": {{\"name\": \"leanprover/lean4:v4.35.0\"}}, \"kernels\": [{{\"result\": {{\"kind\": \"{k}\"}}}}]}}\n"
        )
        .into_bytes())
    }

    #[test]
    fn derive_reads_the_page_checks_it_against_the_verdicts_and_redacts_the_work_dir() {
        // Without the work directory, the home prefix is refused.
        assert!(derive(INDEX, &verdict, None).is_err());
        let (board, files) = derive(INDEX, &verdict, Some("/home/x/w/src/")).unwrap();
        assert_eq!(board.generated_at, 1_700_000_000);
        assert_eq!(board.rows.len(), 2);
        let two = &board.rows[1];
        assert_eq!(
            two.why.as_deref(),
            Some("build: $SRC/b/lakefile.lean failed")
        );
        assert_ne!(two.verdict_sha256, two.source_verdict_sha256);
        assert_eq!(
            board.rows[0].verdict_sha256,
            board.rows[0].source_verdict_sha256
        );
        // The unredacted verdict is committed byte for byte.
        assert_eq!(files[1].1, verdict("a__one").unwrap());
        // A page whose tier is not its verdict's is refused.
        let wrong = INDEX.replace("t-rejected\">rejected", "t-couldNotRun\">could not run");
        assert!(derive(&wrong, &verdict, Some("/home/x/w/src/")).is_err());
    }

    #[test]
    fn check_refuses_an_order_the_board_does_not_use_and_a_changed_file() {
        let (board, files) = derive(INDEX, &verdict, Some("/home/x/w/src/")).unwrap();
        assert!(check(&board, &files[1..]).is_ok());
        let mut swapped = board.clone();
        swapped.rows.swap(0, 1);
        swapped.rows[0].rank = 1;
        swapped.rows[1].rank = 2;
        let mut swapped_files = files[1..].to_vec();
        swapped_files.swap(0, 1);
        assert!(check(&swapped, &swapped_files).is_err());
        let mut changed = files[1..].to_vec();
        changed[0].1.push(b' ');
        assert!(check(&board, &changed).is_err());
    }
}
