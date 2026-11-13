//! Text pages: the A2A-over-iroh specification rendered from its Markdown
//! source, and the documents the extension identifiers dereference to. Each
//! is one self-contained HTML file that loads nothing else.
use crate::{
    BINDING, POSSESSION_EXTENSION, Res, SELLER_CARD_PATH, SETTLEMENT_EXTENSION, SPEC_PATH,
    SUPERSEDED, html::esc,
};
use pulldown_cmark::{Options, Parser, html};
use serde_json::Value;

const STYLE: &str = "\
:root{color-scheme:light dark;--fg:#1d1d1f;--bg:#fff;--muted:#5f6368;--rule:#d9d9de;--code:#f3f3f6}
@media (prefers-color-scheme:dark){:root{--fg:#e8e8ea;--bg:#121214;--muted:#a3a3aa;--rule:#33333a;--code:#1e1e22}}
html,body{background:var(--bg);color:var(--fg)}
body{font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;margin:0}
main{max-width:46rem;margin:0 auto;padding:1.5rem 16px 4rem}
h1{font-size:1.6rem;line-height:1.25}h2{margin-top:2.2rem;font-size:1.25rem}h3{font-size:1.05rem}
code,pre{font:0.9em/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);border-radius:4px}
code{padding:0 .25em;overflow-wrap:anywhere}pre{padding:.75rem;overflow-x:auto}pre code{padding:0;background:none}
table{border-collapse:collapse;display:block;overflow-x:auto;margin:1rem 0}
th,td{border:1px solid var(--rule);padding:.35rem .5rem;text-align:left;vertical-align:top}
a{color:inherit}.muted{color:var(--muted)}
";

/// One page around a body of HTML.
fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"color-scheme\" content=\"light dark\">\n<link rel=\"icon\" href=\"data:,\">\n<title>{}</title>\n<style>\n{STYLE}</style></head><body><main>\n{body}\n</main></body></html>\n",
        esc(title)
    )
}

/// Markdown to HTML. Raw HTML in the source is shown as text, not passed
/// through, so the source cannot add a script or a resource.
fn markdown(source: &str) -> String {
    use pulldown_cmark::Event;
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    let events = Parser::new_ext(source, options).map(|event| match event {
        Event::Html(text) | Event::InlineHtml(text) => Event::Text(text),
        other => other,
    });
    let mut out = String::new();
    html::push_html(&mut out, events);
    out
}

/// The specification as a page.
pub fn spec_page(source: &str, title: &str) -> Res<String> {
    if !source.starts_with("# ") {
        return Err("the specification should start with its title".into());
    }
    Ok(page(title, &markdown(source)))
}

fn site_link(site: Option<&str>, path: &str, text: &str) -> String {
    match site {
        Some(site) => format!("<a href=\"{}/{path}\">{}</a>", esc(site), esc(text)),
        None => format!("<code>{}</code>", esc(path)),
    }
}

fn superseded(kind: &str) -> String {
    SUPERSEDED
        .iter()
        .filter(|(k, _)| *k == kind)
        .map(|(_, id)| format!("<code>{}</code>", esc(id)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What `https://coproduct.one/a2a/ext/iroh-possession/v1` names.
pub fn possession_page(site: Option<&str>) -> Res<String> {
    let body = format!(
        "<h1>A2A extension: per-request proof of possession over iroh</h1>\
<p class=\"muted\">Identifier: <code>{POSSESSION_EXTENSION}</code>. Status: draft. Superseded identifier: {old}.</p>\
<p>An agent that declares this extension with <code>required: true</code> answers a request on the A2A-over-iroh binding (<code>{BINDING}</code>) only if the request carries a fresh proof of possession. The proof is an ES256 JWS of <code>typ</code> <code>a2a-iroh-pop+jwt</code> whose header embeds the caller's public key and whose claims name the A2A method (<code>htm</code>), the target <code>iroh://&lt;agent node ID&gt;/&lt;ALPN&gt;</code> (<code>htu</code>), the time (<code>iat</code>), a one-time identifier (<code>jti</code>), the caller's own node ID as iroh authenticated it (<code>nid</code>), and the SHA-256 of the request frame (<code>rqh</code>).</p>\
<h2>Parameters</h2><table><tr><th>name</th><th>meaning</th></tr>\
<tr><td><code>alg</code></td><td>Signature algorithms the agent accepts. Version 1 defines only <code>ES256</code>.</td></tr>\
<tr><td><code>typ</code></td><td>The JWS <code>typ</code> the agent accepts: <code>a2a-iroh-pop+jwt</code>.</td></tr>\
<tr><td><code>maximumSkewSeconds</code></td><td>How far <code>iat</code> may be from the agent's clock, in seconds.</td></tr></table>\
<p>The complete rules (where the proof travels, verification order, the replay store and the errors) are section 7 of the binding's specification: {spec}.</p>",
        old = superseded("possession"),
        spec = site_link(site, SPEC_PATH, "A2A over iroh"),
    );
    Ok(page("A2A extension: iroh proof of possession", &body))
}

/// What `https://coproduct.one/a2a/ext/proof-settlement/v1` names.
pub fn settlement_page(extension: &Value, site: Option<&str>) -> Res<String> {
    let mut rows = String::new();
    for (name, meaning) in extension["params"].as_object().ok_or("extension params")? {
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td></tr>",
            esc(name),
            esc(meaning.as_str().unwrap_or_default())
        ));
    }
    let body = format!(
        "<h1>A2A extension: proof-gated settlement deployment</h1>\
<p class=\"muted\">Identifier: <code>{SETTLEMENT_EXTENSION}</code>. Status: draft. Superseded identifier: {old}. A machine-readable copy of this description is at <a href=\"extension.json\"><code>extension.json</code></a>.</p>\
<p>{summary}</p>\
<p>It is data only: declaring it changes no A2A operation, and an agent never marks it <code>required</code>.</p>\
<h2>Parameters</h2><table><tr><th>name</th><th>meaning</th></tr>{rows}</table>\
<p>A deployment that carries it: {deployment}. Sellers are reached on their own nodes; an example of a seller's card: {seller}.</p>",
        old = superseded("settlement"),
        summary = esc(extension["summary"].as_str().unwrap_or_default()),
        deployment = site_link(site, "", "the deployment's page"),
        seller = site_link(site, SELLER_CARD_PATH, SELLER_CARD_PATH),
    );
    Ok(page("A2A extension: proof-gated settlement", &body))
}
