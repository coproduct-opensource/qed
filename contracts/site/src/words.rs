//! How many words of prose the site asks a person to read.
//!
//! The owner's limit (2026-11-14): the whole site under [`LIMIT`] words, where
//! technical details, addresses and hashes are for agents and are not
//! counted. The rule, applied to the built files:
//!
//! 1. **Which files.** Every `.html` file the site serves: each document's
//!    `index.html` and `404.html`. Machine-readable files (JSON, the Agent
//!    Card and JWKS, `.well-known/`, ABIs, receipts, test vectors,
//!    `sitemap.xml`, `robots.txt`) and the Markdown twins are not prose
//!    pages and are not read.
//! 2. **Technical documents.** A specification rendered from `docs/specs`
//!    ([`TECHNICAL_DOCUMENTS`]: the A2A-over-iroh binding) is a wire
//!    protocol for implementers and their agents. It is not counted, and its
//!    words are reported beside the total so the exclusion is visible.
//! 3. **Which text.** Text inside `<body>`, outside `<pre>`, `<code>`,
//!    `<kbd>`, `<samp>`, `<script>`, `<style>`, `<template>`, `<svg>`,
//!    `<select>` and `<textarea>` (code, commands, data) and outside
//!    `<table>` (tables of values). Words in tables are reported per page
//!    beside the count, so prose moved into a table shows. Term lists
//!    (`<dl>`) and `<details>` disclosures are prose and count.
//! 4. **Which words.** Whitespace-separated tokens that contain a letter and
//!    are not technical tokens: `0x…` values, URLs (`://`), elided
//!    identifiers (`a…b`), and runs of 8 or more hexadecimal characters
//!    that include a digit (digests, IDs). Numbers alone are not words.
//! 5. **The header and footer** every page repeats (`<header>`, `<footer>`,
//!    and the skip link) are counted once for the site, block by block.
//! 6. **Transaction pages** (`transactions/0x…`) are generated from chain
//!    data, one per settlement. Of their counted text, each block
//!    (paragraph, list item, heading, term, …) is counted once across all of
//!    them, keyed by its counted words, so the shared template is counted
//!    once and a note written for one settlement is counted on its page.
//!
//! Every other page is counted in full: a sentence repeated on two content
//! pages counts twice.
use std::collections::BTreeSet;

/// The most counted words the whole site may have.
pub const LIMIT: usize = 3000;

/// Routes not counted under rule 2.
pub const TECHNICAL_DOCUMENTS: [&str; 1] = [crate::SPEC_PATH];

/// Elements whose text is not counted at all.
const SKIPPED: [&str; 10] = [
    "pre", "code", "kbd", "samp", "script", "style", "template", "svg", "select", "textarea",
];
/// Elements that end one block of text and start another.
const BLOCKS: [&str; 34] = [
    "p",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "dt",
    "dd",
    "div",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "main",
    "aside",
    "blockquote",
    "figcaption",
    "summary",
    "details",
    "caption",
    "br",
    "button",
    "label",
    "option",
    "ul",
    "ol",
    "form",
    "hr",
    "table",
    "th",
    "td",
];
const VOID: [&str; 9] = [
    "meta", "link", "br", "img", "input", "hr", "wbr", "source", "area",
];
/// Elements whose text is the site's repeated chrome.
const CHROME: [&str; 2] = ["header", "footer"];

/// The counted words of one page, or of the site's chrome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub path: String,
    /// Words counted toward the total.
    pub words: usize,
    /// Words in tables on this page, reported and not counted.
    pub in_tables: usize,
}

/// The site's count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Count {
    pub total: usize,
    /// Pages in path order, then the chrome as [`CHROME_ENTRY`].
    pub pages: Vec<Page>,
    /// Technical documents (rule 2): their own words, not counted.
    pub technical: Vec<Page>,
}

pub const CHROME_ENTRY: &str = "(header and footer, once)";

fn decode(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

/// Whether a token is a word a person reads (rule 4).
pub fn is_word(token: &str) -> bool {
    let token = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '…');
    if !token.chars().any(char::is_alphabetic) {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("0x") || lower.contains("://") {
        return false;
    }
    if let Some((a, b)) = token.split_once('…')
        && a.chars().last().is_some_and(char::is_alphanumeric)
        && b.chars().next().is_some_and(char::is_alphanumeric)
    {
        return false;
    }
    let (mut run, mut digit) = (0usize, false);
    for c in token.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            digit |= c.is_ascii_digit();
            if run >= 8 && digit {
                return false;
            }
        } else {
            (run, digit) = (0, false);
        }
    }
    true
}

/// One block of a page's text (rule 3's segmentation).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Block {
    chrome: bool,
    table: bool,
    words: Vec<String>,
}

/// A page's text, as blocks of counted words.
fn blocks(html: &str) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let (mut skip, mut chrome, mut table) = (0usize, 0usize, 0usize);
    let mut skip_link = false;
    let flush = |out: &mut Vec<Block>, current: &mut Vec<String>, chrome: bool, table: bool| {
        if !current.is_empty() {
            out.push(Block {
                chrome,
                table,
                words: std::mem::take(current),
            });
        }
    };
    let mut rest = match html.find("<body") {
        Some(i) => &html[i..],
        None => html,
    };
    while !rest.is_empty() {
        let lt = rest.find('<').unwrap_or(rest.len());
        if skip == 0 {
            current.extend(
                decode(&rest[..lt])
                    .split_whitespace()
                    .filter(|w| is_word(w))
                    .map(str::to_owned),
            );
        }
        if lt == rest.len() {
            break;
        }
        rest = &rest[lt..];
        if rest.starts_with("<!--") {
            rest = rest.find("-->").map_or("", |end| &rest[end + 3..]);
            continue;
        }
        let Some(gt) = rest.find('>') else { break };
        let tag = &rest[1..gt];
        rest = &rest[gt + 1..];
        let closing = tag.starts_with('/');
        let name = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let opens_skip_link = name == "a" && !closing && tag.contains("class=\"skip\"");
        if BLOCKS.contains(&name.as_str()) || opens_skip_link || (name == "a" && skip_link) {
            flush(&mut out, &mut current, chrome > 0 || skip_link, table > 0);
        }
        if opens_skip_link {
            skip_link = true;
        } else if name == "a" && closing {
            skip_link = false;
        }
        if VOID.contains(&name.as_str()) || tag.ends_with('/') {
            continue;
        }
        let count =
            |name: &str, by: isize, skip: &mut usize, chrome: &mut usize, table: &mut usize| {
                let step = |n: &mut usize| *n = n.saturating_add_signed(by);
                if SKIPPED.contains(&name) {
                    step(skip);
                }
                if CHROME.contains(&name) {
                    step(chrome);
                }
                if name == "table" {
                    step(table);
                }
            };
        if closing {
            if let Some(at) = stack.iter().rposition(|open| *open == name) {
                for open in stack.drain(at..) {
                    count(&open, -1, &mut skip, &mut chrome, &mut table);
                }
            }
        } else {
            count(&name, 1, &mut skip, &mut chrome, &mut table);
            stack.push(name);
        }
    }
    flush(&mut out, &mut current, chrome > 0, table > 0);
    out
}

/// The counted words of one page as a person reads it once: chrome
/// included, tables not.
pub fn page_words(html: &str) -> usize {
    blocks(html)
        .iter()
        .filter(|b| !b.table)
        .map(|b| b.words.len())
        .sum()
}

/// The counted blocks of one page, as text, for an author to see what
/// counts (chrome marked, tables left out).
pub fn counted_blocks(html: &str) -> Vec<String> {
    blocks(html)
        .into_iter()
        .filter(|b| !b.table)
        .map(|b| {
            format!(
                "{:>3}{} {}",
                b.words.len(),
                if b.chrome { " (chrome)" } else { "" },
                b.words.join(" ")
            )
        })
        .collect()
}

/// Whether a built path is a transaction page (rule 6).
pub fn is_transaction_page(path: &str) -> bool {
    path.strip_prefix("transactions/0x")
        .and_then(|rest| rest.strip_suffix("/index.html"))
        .is_some_and(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
}

fn route(path: &str) -> String {
    match path.strip_suffix("index.html") {
        Some(dir) => format!("/{}", dir.trim_end_matches('/')),
        None => format!("/{path}"),
    }
}

/// Count a built site, given as (path, bytes) the way `crate::site` returns it.
pub fn count(files: &[(String, Vec<u8>)]) -> Count {
    let mut html: Vec<(&str, String)> = files
        .iter()
        .filter(|(path, _)| path.ends_with(".html"))
        .map(|(path, bytes)| (path.as_str(), String::from_utf8_lossy(bytes).into_owned()))
        .collect();
    html.sort_by(|a, b| a.0.cmp(b.0));
    let mut chrome_seen: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut data_seen: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut chrome = Page {
        path: CHROME_ENTRY.into(),
        words: 0,
        in_tables: 0,
    };
    let (mut pages, mut technical) = (Vec::new(), Vec::new());
    for (path, text) in &html {
        let route = route(path);
        let data = is_transaction_page(path);
        let mut page = Page {
            path: route.clone(),
            words: 0,
            in_tables: 0,
        };
        if TECHNICAL_DOCUMENTS
            .iter()
            .any(|d| route.trim_start_matches('/') == *d)
        {
            let blocks = blocks(text);
            page.words = blocks
                .iter()
                .filter(|b| !b.chrome && !b.table)
                .map(|b| b.words.len())
                .sum();
            page.in_tables = blocks
                .iter()
                .filter(|b| !b.chrome && b.table)
                .map(|b| b.words.len())
                .sum();
            technical.push(page);
            continue;
        }
        for block in blocks(text) {
            let n = block.words.len();
            if block.chrome {
                if chrome_seen.insert(block.words) {
                    chrome.words += n;
                }
            } else if block.table {
                page.in_tables += n;
            } else if !data || data_seen.insert(block.words) {
                page.words += n;
            }
        }
        pages.push(page);
    }
    pages.push(chrome);
    Count {
        total: pages.iter().map(|p| p.words).sum(),
        pages,
        technical,
    }
}

impl Count {
    /// The count as text: total, then the pages by words, largest first.
    pub fn report(&self) -> String {
        let mut pages: Vec<&Page> = self.pages.iter().collect();
        pages.sort_by(|a, b| b.words.cmp(&a.words).then(a.path.cmp(&b.path)));
        let mut out = format!(
            "{} counted words (limit {LIMIT}) on {} pages\n words  in tables  page\n",
            self.total,
            self.pages.len() - 1
        );
        for p in pages {
            out.push_str(&format!("{:>6}  {:>9}  {}\n", p.words, p.in_tables, p.path));
        }
        for p in &self.technical {
            out.push_str(&format!(
                "not counted, technical document: {} ({} words, {} in tables)\n",
                p.path, p.words, p.in_tables
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(body: &str) -> String {
        format!(
            "<!doctype html><html><head><title>Not counted</title></head><body><a class=\"skip\" href=\"#main\">Skip to content</a><header><p>Q.E.D.</p><nav><ol><li><a href=\"/x\">Ledger</a></li></ol></nav></header><main>{body}</main><footer><p>MIT licence.</p></footer></body></html>"
        )
    }

    #[test]
    fn code_and_tables_are_not_counted_and_term_lists_and_details_are() {
        let html = page(
            "<h1>Two words</h1><p>One <code>cargo run --release</code> two.</p><pre>curl -s https://x</pre><table><caption>Values</caption><tr><td>a b c</td></tr></table><dl><dt>Vault</dt><dd>its deposit 0xabc</dd></dl><details><summary>More here</summary><p>Three more words.</p></details><script>let a = 1;</script>",
        );
        // Two words + One two + Vault + its deposit + More here + Three more
        // words, plus the chrome: Skip to content, Q.E.D., Ledger, MIT licence.
        assert_eq!(page_words(&html), 2 + 2 + 1 + 2 + 2 + 3 + (3 + 1 + 1 + 2));
        let files = vec![("protocol/index.html".to_owned(), html.into_bytes())];
        let count = count(&files);
        // Values + a b c are reported, not counted.
        assert_eq!(count.pages[0].in_tables, 4);
        assert_eq!(count.total, 12 + 7);
    }

    #[test]
    fn technical_tokens_are_not_words() {
        for token in [
            "0x952c…ab3c",
            "0xffb5481f",
            "https://qed.coproduct.dev",
            "704bdf3b…42ed",
            "sha256:76c03c0300be9d326593f99c64a5fed5b2f8f5177ef1c0f255e436f563294a9f",
            "(0x60a3ef1db6b9c9cf462165fe43bae6f52de3ca8cbc51bd124ff517b6b1a85611).",
            "25",
            "—",
            "&",
        ] {
            assert!(!is_word(token), "{token}");
        }
        for token in ["seller", "v0.2.2", "USDC,", "don't", "deadbeef", "x402"] {
            assert!(is_word(token), "{token}");
        }
    }

    #[test]
    fn chrome_counts_once_transaction_templates_once_and_the_specification_not_at_all() {
        let a = "transactions/0x".to_owned() + &"a".repeat(64) + "/index.html";
        let b = "transactions/0x".to_owned() + &"b".repeat(64) + "/index.html";
        let files = vec![
            (
                "index.html".to_owned(),
                page("<p>Home has four words.</p><p>Home has four words.</p>").into_bytes(),
            ),
            (
                format!("{}/index.html", crate::SPEC_PATH),
                page("<p>Normative text of five words.</p>").into_bytes(),
            ),
            (
                a,
                page("<p>Settled 2026-11-12 for 25 USDC.</p><p>A note for this one.</p>")
                    .into_bytes(),
            ),
            (
                b,
                page("<p>Settled 2026-11-13 for 1 USDC.</p><p>Another note.</p>").into_bytes(),
            ),
        ];
        let count = count(&files);
        let words: Vec<usize> = count.pages.iter().map(|p| p.words).collect();
        // Home repeats its sentence and counts it twice; the second
        // transaction page shares only the template sentence; the chrome
        // (3 + 1 + 1 + 2) counts once.
        assert_eq!(words, vec![8, 3 + 5, 2, 7]);
        assert_eq!(count.total, 8 + 8 + 2 + 7);
        assert_eq!(count.technical.len(), 1);
        assert_eq!(count.technical[0].words, 5);
    }
}
