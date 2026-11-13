//! How the built files are to be served: routes, media types, content
//! negotiation and response headers. One table, read by the local preview,
//! by the Caddy fragment generator and by the post-upload check, so the
//! three agree by construction. The host's own tooling (contracts/host)
//! takes the Caddy block this module writes.
//!
//! Routes. A document is a directory with `index.html` and `index.md`;
//! `/protocol` and `/protocol/` both answer with `protocol/index.html`, or
//! with `protocol/index.md` when the request's `Accept` names
//! `text/markdown`. Every other path is a file served as its exact bytes,
//! never converted. Every response carries `Vary: Accept`.
use crate::{CARD_PATH, JWKS_PATH, SELLER_CARD_PATH, SPEC_PATH};

/// Files read by agents from other origins. A2A 1.0.1 says nothing about
/// CORS; browsers enforce it, and a web-based client fetching a card,
/// receipt or artifact from another origin needs
/// `Access-Control-Allow-Origin`. Nothing else on the site is given it.
pub const CROSS_ORIGIN: [&str; 6] = [
    CARD_PATH,
    "agent-card.json",
    JWKS_PATH,
    SELLER_CARD_PATH,
    "deployment.json",
    "receipts/index.json",
];
/// Directories whose every file is read cross-origin too.
pub const CROSS_ORIGIN_DIRS: [&str; 3] = ["receipts/", "artifacts/", "statements/"];
/// Directories whose files are named by their own hash and never change.
pub const IMMUTABLE_DIRS: [&str; 2] = ["artifacts/", "statements/"];
/// Request paths of the one page that instantiates the WebAssembly checker
/// (crate::CHECKER_PAGE). The host gives these, and only these, a
/// Content-Security-Policy with `'wasm-unsafe-eval'` and same-origin fetch.
pub const CHECKER_PAGE_PATHS: [&str; 4] = [
    "/verify",
    "/verify/",
    "/verify/index.html",
    "/verify/index.md",
];

/// Strict-Transport-Security. The whole `.dev` top-level domain is on
/// browsers' preload list already, so `preload` adds nothing here.
pub const HSTS: &str = "max-age=63072000; includeSubDomains";

/// The media type of a file, as the host must send it.
pub fn media_type(path: &str) -> &'static str {
    let path = path.trim_start_matches('/');
    let ext = path.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if path.is_empty() || path.ends_with('/') {
        return "text/html; charset=utf-8";
    }
    match ext {
        "html" => "text/html; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "json" => "application/json",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "wasm" => "application/wasm",
        "ndjson" => "application/x-ndjson",
        _ => "application/octet-stream",
    }
}

/// Whether `Accept` asks for Markdown.
pub fn wants_markdown(accept: &str) -> bool {
    accept.split(',').any(|part| {
        part.trim()
            .to_ascii_lowercase()
            .starts_with("text/markdown")
    })
}

/// The files a request path may be answered with, in order: the path
/// itself, then the document's representation.
pub fn candidates(request: &str, markdown: bool) -> Vec<String> {
    let path = request.split(['?', '#']).next().unwrap_or("");
    let path = path.trim_start_matches('/');
    let dir = path.trim_end_matches('/');
    let index = |name: &str| {
        if dir.is_empty() {
            name.to_owned()
        } else {
            format!("{dir}/{name}")
        }
    };
    let mut out = Vec::new();
    if markdown {
        out.push(index("index.md"));
    }
    if !path.is_empty() && !path.ends_with('/') {
        out.push(path.to_owned());
    }
    out.push(index("index.html"));
    out
}

/// `Cache-Control` for a file. A2A 1.0.1 §8.6.1: card endpoints SHOULD send
/// `Cache-Control` with `max-age`, and SHOULD send an `ETag`. Artifacts are
/// named by their own hash and never change.
pub fn cache_control(path: &str) -> &'static str {
    let path = path.trim_start_matches('/');
    if IMMUTABLE_DIRS.iter().any(|d| path.starts_with(d)) {
        "public, max-age=31536000, immutable"
    } else if path.starts_with("abi/") {
        "public, max-age=3600"
    } else {
        "public, max-age=300"
    }
}

pub fn cross_origin(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    CROSS_ORIGIN.contains(&path) || CROSS_ORIGIN_DIRS.iter().any(|d| path.starts_with(d))
}

/// The headers every response for the file at `path` carries, apart from
/// content type, length and `ETag` (the host computes those). `https` is
/// whether the response is served over TLS; HSTS means nothing otherwise.
pub fn headers(path: &str, https: bool) -> Vec<(&'static str, &'static str)> {
    let mut out = vec![
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", cache_control(path)),
        ("vary", "Accept"),
    ];
    if https {
        out.push(("strict-transport-security", HSTS));
    }
    if cross_origin(path) {
        out.push(("access-control-allow-origin", "*"));
    }
    out
}

/// A Caddyfile site block that serves `root` for `host` and nothing else: no
/// proxy, no templates, no directory listing. `host` may be a literal name or
/// a Caddy placeholder. The `route` keeps the two rewrites in the order
/// written: Markdown first when asked for, then the document's HTML.
pub fn caddy(host: &str, root: &str) -> String {
    let cross: Vec<String> = CROSS_ORIGIN.iter().map(|p| format!("/{p}")).collect();
    let cross_dirs: Vec<String> = CROSS_ORIGIN_DIRS.iter().map(|d| format!("/{d}*")).collect();
    format!(
        "# The qed site: files only, no proxy. Generated by `nucleus-site caddy`\n\
# from contracts/site/src/serving.rs; the local preview and\n\
# `nucleus-site check-live` read the same table.\n\
{host} {{\n\
\troot * {root}\n\
\troute {{\n\
\t\t@markdown {{\n\
\t\t\theader_regexp Accept (?i)text/markdown\n\
\t\t\tfile {{path}}/index.md\n\
\t\t}}\n\
\t\trewrite @markdown {{file_match.relative}}\n\
\t\ttry_files {{path}} {{path}}/index.html\n\
\t}}\n\
\tfile_server\n\
\theader {{\n\
\t\tStrict-Transport-Security \"{HSTS}\"\n\
\t\tX-Content-Type-Options \"nosniff\"\n\
\t\tReferrer-Policy \"no-referrer\"\n\
\t\tVary \"Accept\"\n\
\t}}\n\
\t# Caddy applies a header directive without a matcher after those with\n\
\t# one, so a per-path value is never also set unconditionally: each\n\
\t# Cache-Control below has a matcher, and the three are disjoint.\n\
\t@cache_short not path /abi/* {immutable}\n\
\theader @cache_short Cache-Control \"public, max-age=300\"\n\
\t@abi path /abi/*\n\
\theader @abi Cache-Control \"public, max-age=3600\"\n\
\t@artifacts path {immutable}\n\
\theader @artifacts Cache-Control \"public, max-age=31536000, immutable\"\n\
\t@md path *.md\n\
\theader @md Content-Type \"text/markdown; charset=utf-8\"\n\
\t@ndjson path *.ndjson\n\
\theader @ndjson Content-Type \"application/x-ndjson\"\n\
\t@wasm path *.wasm\n\
\theader @wasm Content-Type \"application/wasm\"\n\
\t@v2 path *.v2\n\
\theader @v2 Content-Type \"application/octet-stream\"\n\
\t@cross path {cross} {cross_dirs}\n\
\theader @cross Access-Control-Allow-Origin \"*\"\n\
\t# Pages that run the WebAssembly checker; the host sets their CSP.\n\
\t@checker path {checker}\n\
\tlog {{\n\
\t\toutput stderr\n\
\t\tformat console\n\
\t}}\n\
}}\n",
        cross = cross.join(" "),
        cross_dirs = cross_dirs.join(" "),
        immutable = IMMUTABLE_DIRS
            .iter()
            .map(|d| format!("/{d}*"))
            .collect::<Vec<_>>()
            .join(" "),
        checker = CHECKER_PAGE_PATHS.join(" "),
    )
}

/// Paths the post-upload check fetches, with whether each is an Agent Card.
/// The document paths are fetched as HTML; `check-live` also fetches each
/// with `Accept: text/markdown`.
pub fn checked_paths() -> [(&'static str, bool); 10] {
    [
        (CARD_PATH, true),
        ("agent-card.json", true),
        (SELLER_CARD_PATH, true),
        (JWKS_PATH, false),
        ("deployment.json", false),
        ("receipts/index.json", false),
        ("", false),
        ("protocol", false),
        ("transactions", false),
        (SPEC_PATH, false),
    ]
}

/// Whether a request path names a document (answered by `index.html` or
/// `index.md`) rather than a file.
pub fn is_document(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    path.is_empty() || !path.rsplit('/').next().unwrap_or("").contains('.')
}

/// Attribute values and constructs in an HTML file that make a browser
/// fetch from another origin. Same-origin paths (`/…`, not `//…`) and the
/// empty inline icon (`data:,`) are allowed.
pub fn fetching_markers(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out: Vec<String> = [
        "@import", "<img", "<iframe", "<object", "<embed", "<video", "<audio", "<source",
        "url(http", "url(//", "srcset",
    ]
    .into_iter()
    .filter(|marker| lower.contains(marker))
    .map(str::to_owned)
    .collect();
    for (open, attribute) in [("<script", "src=\""), ("<link", "href=\"")] {
        let mut rest = lower.as_str();
        while let Some(start) = rest.find(open) {
            let after = &rest[start..];
            let end = after.find('>').unwrap_or(after.len());
            let element = &after[..end];
            // Only loading links fetch: stylesheets, icons, preloads, scripts.
            let loads = open == "<script"
                || ["stylesheet", "icon", "preload", "modulepreload", "prefetch"]
                    .iter()
                    .any(|r| element.contains(&format!("rel=\"{r}\"")));
            if loads && let Some(at) = element.find(attribute) {
                let value = &element[at + attribute.len()..];
                let value = value.split('"').next().unwrap_or("");
                let same_origin = value.starts_with('/') && !value.starts_with("//");
                if !same_origin && value != "data:," {
                    out.push(format!("{open} {attribute}{value}"));
                }
            }
            rest = &after[end.max(1)..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_route_resolves_to_html_or_markdown() {
        assert_eq!(candidates("/", false), ["index.html"]);
        assert_eq!(candidates("/", true), ["index.md", "index.html"]);
        assert_eq!(
            candidates("/protocol", true),
            ["protocol/index.md", "protocol", "protocol/index.html"]
        );
        assert_eq!(candidates("/protocol/", false), ["protocol/index.html"]);
        assert_eq!(candidates("/deployment.json?x", true)[1], "deployment.json");
        assert!(wants_markdown("text/markdown, text/html;q=0.9"));
        assert!(!wants_markdown("text/html,application/xhtml+xml,*/*;q=0.8"));
    }

    #[test]
    fn same_origin_files_are_not_outside_fetches() {
        let page = "<link rel=\"stylesheet\" href=\"/qed.css\"><script src=\"/qed.js\" defer></script><link rel=\"icon\" href=\"data:,\"><link rel=\"canonical\" href=\"https://x.test/\">";
        assert!(
            fetching_markers(page).is_empty(),
            "{:?}",
            fetching_markers(page)
        );
        let bad = "<script src=\"https://cdn.test/x.js\"></script><link rel=\"stylesheet\" href=\"//cdn.test/x.css\">";
        assert_eq!(fetching_markers(bad).len(), 2);
    }
}
