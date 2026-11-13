//! Visible prose words per document page of a built site.
//!
//!   cargo run --example words -- BUILT_SITE_DIR
//!
//! Counts the text a reader sees in each `index.html`, excluding `<pre>`,
//! `<code>`, `<script>`, `<style>`, `<table>` and `<select>` (code, hashes,
//! addresses and transaction data, including the checker's list of
//! settlements), and the audit prompt (which is a `<pre>`).
use std::{error::Error, fs, path::Path};

fn visible_words(html: &str) -> usize {
    let mut words = 0usize;
    let mut skip: Vec<String> = Vec::new();
    let mut rest = html;
    let body = rest.find("<body").map(|i| &rest[i..]).unwrap_or(rest);
    rest = body;
    while !rest.is_empty() {
        if let Some(lt) = rest.find('<') {
            let text = &rest[..lt];
            if skip.is_empty() {
                words += text
                    .split_whitespace()
                    .filter(|w| w.chars().any(char::is_alphanumeric))
                    .count();
            }
            let Some(gt) = rest[lt..].find('>') else {
                break;
            };
            let tag = &rest[lt + 1..lt + gt];
            let closing = tag.starts_with('/');
            let name: String = tag
                .trim_start_matches('/')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            if ["pre", "code", "script", "style", "table", "select"].contains(&name.as_str()) {
                if closing {
                    if skip.last() == Some(&name) {
                        skip.pop();
                    }
                } else if !tag.ends_with('/') {
                    skip.push(name);
                }
            }
            rest = &rest[lt + gt + 1..];
        } else {
            if skip.is_empty() {
                words += rest.split_whitespace().count();
            }
            break;
        }
    }
    words
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, usize)>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, root, out)?;
        } else if path.file_name().is_some_and(|n| n == "index.html") {
            let rel = path
                .parent()
                .and_then(|p| p.strip_prefix(root).ok())
                .map(|p| format!("/{}", p.display()))
                .unwrap_or_default();
            out.push((rel, visible_words(&fs::read_to_string(&path)?)));
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: words BUILT_SITE_DIR")?;
    let root = Path::new(&dir);
    let mut pages = Vec::new();
    walk(root, root, &mut pages)?;
    pages.sort();
    let mut total = 0;
    for (page, words) in &pages {
        println!("{words:>6}  {page}");
        total += words;
    }
    println!("{total:>6}  total ({} pages)", pages.len());
    Ok(())
}
