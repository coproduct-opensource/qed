//! Agent-readability checks over a served site: what an agent with only
//! the root URL must be able to do. Each check returns findings, empty when
//! it passes, so the same checks run against the local preview, against
//! deliberately broken copies (the tests), and against the live host.
use crate::{CARD_PATH, JWKS_PATH, Res, hex, serving, signing};
use alloy_primitives::keccak256;
use serde_json::Value;

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub vary: String,
    pub body: Vec<u8>,
}

/// GET `base` + `path`, with `Accept` if given.
pub fn get(base: &str, path: &str, accept: Option<&str>) -> Res<Response> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let mut request = agent.get(format!("{}{path}", base.trim_end_matches('/')));
    if let Some(accept) = accept {
        request = request.header("accept", accept);
    }
    let mut response = request.call()?;
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let (content_type, vary) = (header("content-type"), header("vary"));
    Ok(Response {
        status: response.status().as_u16(),
        content_type,
        vary,
        body: response.body_mut().read_to_vec()?,
    })
}

fn text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

/// The text a reader sees with scripts off: tags, script and style bodies,
/// and elements marked `hidden` removed.
pub fn visible_text(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        out.push_str(&rest[..lt]);
        let after = &rest[lt..];
        let end = after.find('>').map_or(after.len(), |e| e + 1);
        let tag = &after[..end];
        let name: String = tag
            .trim_start_matches('<')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        let hidden = tag.contains(" hidden") && !tag.starts_with("</");
        if name == "script" || name == "style" || hidden {
            let close = format!("</{name}>");
            // Skip to the matching close (nested same-name elements counted).
            let mut depth = 1;
            let mut scan = &after[end..];
            let mut consumed = end;
            while depth > 0 {
                let next_open = scan.find(&format!("<{name}"));
                let next_close = scan.find(&close);
                match (next_open, next_close) {
                    (Some(o), Some(c)) if o < c => {
                        depth += 1;
                        consumed += o + 1;
                        scan = &scan[o + 1..];
                    }
                    (_, Some(c)) => {
                        depth -= 1;
                        consumed += c + close.len();
                        scan = &scan[c + close.len()..];
                    }
                    _ => {
                        consumed = after.len();
                        break;
                    }
                }
            }
            rest = &after[consumed..];
        } else {
            out.push(' ');
            rest = &after[end..];
        }
    }
    out.push_str(rest);
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// `href` and `src` values in an HTML document.
pub fn references(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for attr in ["href=\"", "src=\""] {
        for piece in html.split(attr).skip(1) {
            if let Some(value) = piece.split('"').next() {
                out.push(value.replace("&amp;", "&"));
            }
        }
    }
    out
}

fn has_id(html: &str, id: &str) -> bool {
    html.contains(&format!("id=\"{id}\""))
}

/// 1. The root page is complete without scripts: the facts a careful agent
///    asks first are in its visible text.
pub fn homepage_complete_without_script(base: &str, facts: &[&str]) -> Res<Vec<String>> {
    let r = get(base, "/", Some("text/html"))?;
    let seen = visible_text(&text(&r));
    Ok(facts
        .iter()
        .filter(|f| !seen.contains(*f))
        .map(|f| format!("root page does not show: {f}"))
        .collect())
}

/// 2. The card is linked from the root page and served at the well-known path.
pub fn card_discoverable(base: &str) -> Res<Vec<String>> {
    let mut out = Vec::new();
    let home = text(&get(base, "/", None)?);
    let well_known = format!("/{CARD_PATH}");
    if !home.contains(&format!(
        "rel=\"alternate\" type=\"application/json\" title=\"A2A Agent Card\" href=\"{well_known}\""
    )) {
        out.push("no <link rel=alternate> to the card in the root page's head".into());
    }
    if !references(&home).contains(&well_known) {
        out.push("no link to the card in the root page".into());
    }
    let card = get(base, &well_known, None)?;
    if card.status != 200 || !card.content_type.starts_with("application/json") {
        out.push(format!(
            "card: status {} type {}",
            card.status, card.content_type
        ));
    } else if serde_json::from_slice::<Value>(&card.body).is_err() {
        out.push("card is not JSON".into());
    }
    Ok(out)
}

/// 3. The card's signature verifies against the served JWKS.
pub fn card_signature_valid(base: &str) -> Res<Vec<String>> {
    let card: Value = serde_json::from_slice(&get(base, &format!("/{CARD_PATH}"), None)?.body)?;
    let jwks = get(base, &format!("/{JWKS_PATH}"), None)?;
    if jwks.status != 200 {
        return Ok(vec![format!("JWKS status {}", jwks.status)]);
    }
    let jwks: Value = serde_json::from_slice(&jwks.body)?;
    Ok(match signing::verify(&card, &jwks) {
        Ok(_) => vec![],
        Err(e) => vec![format!("card signature: {e}")],
    })
}

/// 4. Transactions are enumerable in a stable structured form: the receipt
///    index lists canonical receipts, each saying what is asserted.
pub fn transactions_enumerable(base: &str) -> Res<Vec<String>> {
    let mut out = Vec::new();
    let index: Value = serde_json::from_slice(&get(base, "/receipts/index.json", None)?.body)?;
    let entries = index["receipts"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        out.push("receipt index lists nothing".into());
    }
    for entry in entries {
        let url = entry["url"].as_str().unwrap_or_default();
        let r = get(base, url, None)?;
        let value: Value = match serde_json::from_slice(&r.body) {
            Ok(v) => v,
            Err(_) => {
                out.push(format!("{url}: not JSON"));
                continue;
            }
        };
        let canonical = format!("{}\n", signing::jcs(&value)?);
        if canonical.as_bytes() != r.body.as_slice() {
            out.push(format!("{url}: not RFC 8785 canonical"));
        }
        if value["asserted"]["assertedBy"] != "authors" {
            out.push(format!("{url}: assertions not marked"));
        }
        if value["id"] != entry["id"] {
            out.push(format!("{url}: id differs from the index"));
        }
    }
    Ok(out)
}

/// 5. A settlement's evidence is within two links of the ledger page, and
///    the artifact served is the one the vault recorded.
pub fn evidence_within_two_links(base: &str) -> Res<Vec<String>> {
    let mut out = Vec::new();
    let ledger = text(&get(base, "/transactions", None)?);
    let pages: Vec<String> = references(&ledger)
        .into_iter()
        .filter(|r| r.starts_with("/transactions/0x"))
        .collect();
    if pages.is_empty() {
        out.push("ledger page links to no transaction".into());
    }
    for page in pages {
        let html = text(&get(base, &page, None)?);
        let refs = references(&html);
        let receipt = refs.iter().find(|r| r.starts_with("/receipts/"));
        let artifact = refs.iter().find(|r| r.starts_with("/artifacts/"));
        match (receipt, artifact) {
            (Some(receipt), Some(artifact)) => {
                let value: Value = serde_json::from_slice(&get(base, receipt, None)?.body)?;
                let bytes = get(base, artifact, None)?.body;
                let k = format!("0x{}", hex(keccak256(&bytes).as_slice()));
                if value["artifact"]["keccak256"] != k.as_str()
                    || value["artifact"]["recordedByVault"] != k.as_str()
                {
                    out.push(format!(
                        "{page}: artifact does not hash to the vault's record"
                    ));
                }
            }
            _ => out.push(format!("{page}: no receipt or artifact link")),
        }
    }
    Ok(out)
}

/// 6. /verify gives a way to check each claim.
pub fn verify_covers_each_claim(base: &str) -> Res<Vec<String>> {
    let html = text(&get(base, "/verify", None)?);
    let mut out = Vec::new();
    for (id, needle) in [
        ("code", "eth_getCode"),
        ("fixed", "eth_call"),
        ("control", "owner"),
        ("programs", "image ID"),
        ("settlement", "artifactOf"),
        ("card", "RFC 8785"),
        ("dns", "dig +dnssec"),
    ] {
        if !has_id(&html, id) {
            out.push(format!("/verify has no section {id}"));
        } else if !html.contains(needle) {
            out.push(format!("/verify section {id} lacks {needle}"));
        }
    }
    Ok(out)
}

/// 7. The threat model says which claims are proved, tested and assumed.
pub fn threat_model_distinguishes(base: &str) -> Res<Vec<String>> {
    let seen = visible_text(&text(&get(base, "/protocol/threat-model", None)?));
    Ok(["Proven", "Tested", "Assumed"]
        .iter()
        .filter(|w| !seen.contains(*w))
        .map(|w| format!("threat model never says {w}"))
        .collect())
}

/// 7b. Every review finding on the threat model has a state (open, fixed in
///     the current deployment, or applies only to historical deployments)
///     and the date it took it.
pub fn threat_findings_have_states(base: &str) -> Res<Vec<String>> {
    let html = text(&get(base, "/protocol/threat-model", None)?);
    let caption = format!(
        "<caption>{}</caption>",
        crate::html::esc(crate::pages::FINDINGS_CAPTION)
    );
    let Some(table) = html
        .split(&caption)
        .nth(1)
        .and_then(|rest| rest.split("</table>").next())
    else {
        return Ok(vec!["threat model has no findings table".into()]);
    };
    let labels: Vec<&str> = crate::pages::FindingState::ALL
        .iter()
        .map(|s| s.label())
        .collect();
    let body = table.split("<tbody>").nth(1).unwrap_or("");
    let mut out = Vec::new();
    let mut rows = 0;
    for row in body.split("<tr>").skip(1) {
        rows += 1;
        let cells: Vec<String> = row
            .split("</th>")
            .flat_map(|part| part.split("</td>"))
            .map(|cell| visible_text(cell).trim().to_owned())
            .collect();
        let what = cells.first().cloned().unwrap_or_default();
        let state = cells.get(1).cloned().unwrap_or_default();
        let since = cells.get(2).cloned().unwrap_or_default();
        if !labels.contains(&state.as_str()) {
            out.push(format!("finding {what:?} has no state ({state:?})"));
        }
        let dated = since.len() == 10
            && since.chars().enumerate().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == '-'
                } else {
                    c.is_ascii_digit()
                }
            });
        if !dated {
            out.push(format!("finding {what:?} has no date ({since:?})"));
        }
    }
    if rows == 0 {
        out.push("the findings table has no rows".into());
    }
    Ok(out)
}

/// 13. The card links a protocol manifest and a seller's instructions; both
///     are served, the manifest names the same contracts as
///     `deployment.json`, the instructions carry the steps, and the card
///     itself no longer carries them.
pub fn card_documents(base: &str) -> Res<Vec<String>> {
    let mut out = Vec::new();
    let card_text = text(&get(base, &format!("/{CARD_PATH}"), None)?);
    let card: Value = serde_json::from_str(&card_text)?;
    // The card's links are absolute on the site it names; the path is what
    // this host serves.
    let path_of = |url: &str| -> String {
        match url.split_once("://") {
            Some((_, rest)) => rest.find('/').map_or("/".into(), |i| rest[i..].to_owned()),
            None => url.to_owned(),
        }
    };
    let params = &card["capabilities"]["extensions"][0]["params"];
    let (Some(manifest_url), Some(skill_url)) =
        (params["manifest"].as_str(), params["sellerSkill"].as_str())
    else {
        return Ok(vec![
            "the card's extension names no manifest or seller skill".into(),
        ]);
    };
    if !card["description"]
        .as_str()
        .is_some_and(|d| d.contains(manifest_url))
    {
        out.push("the card's description does not name the manifest".into());
    }
    let sell = card["skills"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["id"] == "sell-proof");
    if !sell
        .and_then(|s| s["description"].as_str())
        .is_some_and(|d| d.contains(skill_url))
    {
        out.push("the card's sell-proof skill does not link the seller skill".into());
    }
    if card_text.contains("container system start") {
        out.push("the card still carries the seller's shell steps".into());
    }
    let manifest = get(base, &path_of(manifest_url), None)?;
    if manifest.status != 200 || !manifest.content_type.starts_with("application/json") {
        out.push(format!(
            "{manifest_url}: status {} type {}",
            manifest.status, manifest.content_type
        ));
    } else {
        let m: Value = serde_json::from_slice(&manifest.body)?;
        let deployment: Value = serde_json::from_slice(&get(base, "/deployment.json", None)?.body)?;
        if m["deployment"] != deployment {
            out.push("the manifest's deployment is not deployment.json".into());
        }
        for abi in m["interfaces"]["contracts"]["abis"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(_, url)| url.as_str())
        {
            if get(base, &path_of(abi), None)?.status != 200 {
                out.push(format!("the manifest names {abi}, which is not served"));
            }
        }
        if m["interfaces"]["iroh"]["alpn"].as_str().is_none() {
            out.push("the manifest names no iroh ALPN".into());
        }
    }
    let skill = get(base, &path_of(skill_url), None)?;
    if skill.status != 200 || !skill.content_type.starts_with("text/markdown") {
        out.push(format!(
            "{skill_url}: status {} type {}",
            skill.status, skill.content_type
        ));
    } else if !text(&skill).contains("container system start") {
        out.push(format!("{skill_url} carries no steps"));
    }
    Ok(out)
}

/// 8. No page asks for an account, a wallet or a login, and every page's
///    heading is in its visible text.
pub fn no_account_or_script_needed(base: &str, paths: &[String]) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for path in paths {
        let html = text(&get(base, path, None)?);
        let seen = visible_text(&html).to_lowercase();
        for asks in [
            "sign in",
            "log in",
            "login",
            "connect wallet",
            "sign up",
            "password",
        ] {
            if seen.contains(asks) {
                out.push(format!("{path} asks: {asks}"));
            }
        }
        let heading = html
            .split("<h1>")
            .nth(1)
            .and_then(|s| s.split("</h1>").next())
            .unwrap_or("");
        if heading.is_empty() {
            out.push(format!("{path} has no visible heading"));
        }
        if html.contains("<input type=\"password\"") {
            out.push(format!("{path} has a password field"));
        }
    }
    Ok(out)
}

/// 9. Every document answers `Accept: text/markdown` with its Markdown, and
///    every response varies on Accept.
pub fn markdown_negotiation(
    base: &str,
    paths: &[String],
    built: &std::path::Path,
) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for path in paths {
        let md = get(base, path, Some("text/markdown"))?;
        let rel = serving::candidates(path, true)[0].clone();
        let want = std::fs::read(built.join(&rel)).unwrap_or_default();
        if !md.content_type.starts_with("text/markdown") || md.body != want {
            out.push(format!(
                "{path}: Accept text/markdown gave {} ({} bytes)",
                md.content_type,
                md.body.len()
            ));
        }
        if !crate::serving::varies_on_accept(&md.vary) {
            out.push(format!("{path}: no Vary: Accept"));
        }
        let html = get(base, path, Some("text/html"))?;
        if !html.content_type.starts_with("text/html") {
            out.push(format!(
                "{path}: Accept text/html gave {}",
                html.content_type
            ));
        }
    }
    Ok(out)
}

/// 10. Every same-site link resolves, fragments included.
pub fn internal_links_resolve(base: &str, paths: &[String]) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for path in paths {
        let html = text(&get(base, path, None)?);
        for reference in references(&html) {
            if !reference.starts_with('/') || reference.starts_with("//") {
                continue;
            }
            if crate::serving::COLLECTOR_PATHS.contains(&reference.as_str()) {
                continue;
            }
            let (target, fragment) = match reference.split_once('#') {
                Some((t, f)) => (t.to_owned(), Some(f.to_owned())),
                None => (reference.clone(), None),
            };
            let r = get(base, &target, None)?;
            if r.status != 200 {
                out.push(format!("{path} → {reference}: {}", r.status));
            } else if let Some(fragment) = fragment
                && !has_id(&text(&r), &fragment)
            {
                out.push(format!("{path} → {reference}: no such anchor"));
            }
        }
    }
    Ok(out)
}

/// The element and attribute a `.wasm` reference at byte `at` sits in.
fn wasm_reference_site(html: &str, at: usize) -> (String, String) {
    let before = &html[..at];
    let tag_start = before.rfind('<').unwrap_or(0);
    if before.rfind('>').is_some_and(|gt| gt > tag_start) {
        // Text between tags, which loads nothing.
        return ("#text".into(), String::new());
    }
    let tag: String = before[tag_start + 1..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    let attribute = before
        .rfind("=\"")
        .filter(|q| *q > tag_start)
        .and_then(|q| {
            let name_start = before[..q].rfind([' ', '\n', '\t'])? + 1;
            Some(before[name_start..q].to_owned())
        })
        .unwrap_or_default();
    (tag, attribute)
}

/// 12. The WebAssembly checker is fetched only when asked for, is the
///     module this build names, and the page still says what to do without
///     scripts. Statically: no page names a `.wasm` file except as a link
///     (`<a href>`) or as the checker's `data-wasm`, and the script compiles
///     a module only inside the button's click handler. Then the served
///     module's SHA-256 and size equal what `/verify` states, and each
///     selectable order's statement hashes to its receipt's record.
///     Whether a browser really fetches nothing is observed in a browser
///     (the RFC records it); this check is what a non-browser agent can do.
pub fn checker_on_demand(base: &str, paths: &[String]) -> Res<Vec<String>> {
    use sha2::Digest as _;
    let mut out = Vec::new();
    for path in paths {
        let html = text(&get(base, path, None)?);
        for (at, _) in html.match_indices(".wasm") {
            let (tag, attribute) = wasm_reference_site(&html, at);
            let fine = tag == "#text"
                || (tag == "a" && attribute == "href")
                || (tag == "div" && attribute == "data-wasm");
            if !fine {
                out.push(format!("{path} names the checker in <{tag} {attribute}>"));
            }
        }
    }
    let js = text(&get(base, "/qed.js", None)?);
    match (
        js.find("run.addEventListener(\"click\""),
        js.find("WebAssembly.compile("),
    ) {
        (Some(click), Some(compile)) if compile > click => {}
        _ => out.push("qed.js compiles a module outside the checker's click handler".into()),
    }
    // The module's hash is checked before it is compiled, and nothing
    // compiles straight from the network past that check.
    let hashed_first = matches!(
        (js.find("crypto.subtle.digest("), js.find("WebAssembly.compile(")),
        (Some(h), Some(c)) if h < c
    );
    if !hashed_first || js.contains("Streaming(") {
        out.push("qed.js compiles the checker without first checking its SHA-256".into());
    }
    let verify = text(&get(base, "/verify", None)?);
    let attribute = |name: &str| {
        verify
            .split(&format!("{name}=\""))
            .nth(1)
            .and_then(|r| r.split('"').next())
            .map(str::to_owned)
    };
    let (Some(wasm), Some(sha), Some(bytes)) = (
        attribute("data-wasm"),
        attribute("data-sha256"),
        attribute("data-bytes"),
    ) else {
        out.push("/verify has no checker".into());
        return Ok(out);
    };
    let module = get(base, &wasm, None)?;
    if module.status != 200 || module.content_type != "application/wasm" {
        out.push(format!(
            "{wasm}: HTTP {} {}",
            module.status, module.content_type
        ));
    }
    if hex(sha2::Sha256::digest(&module.body).as_slice()) != sha
        || module.body.len().to_string() != bytes
    {
        out.push(format!("{wasm} is not the module /verify names"));
    }
    // Without scripts: the controls stay hidden and the fallback is there.
    let checker_div = verify.split("id=\"checker\"").nth(1).unwrap_or("");
    if !checker_div
        .split('>')
        .next()
        .is_some_and(|attrs| attrs.contains(" hidden"))
    {
        out.push("/verify shows the checker's controls before the script runs".into());
    }
    let in_box = verify
        .split("id=\"checker-box\"")
        .nth(1)
        .and_then(|r| r.split("</details>").next())
        .unwrap_or("");
    if !in_box.contains("<noscript>") {
        out.push("/verify's checker has no text for readers without scripts".into());
    }
    for receipt_path in verify
        .split("<option value=\"")
        .skip(1)
        .filter_map(|r| r.split('"').next())
    {
        let receipt: Value = serde_json::from_slice(&get(base, receipt_path, None)?.body)?;
        let statement = &receipt["acceptance"]["statement"];
        let url = statement["url"].as_str().unwrap_or("");
        let body = get(base, url, None)?.body;
        if hex(sha2::Sha256::digest(&body).as_slice()) != statement["sha256"].as_str().unwrap_or("")
            || receipt["acceptance"]["policyHashesTo"] != receipt["order"]["policyHash"]
        {
            out.push(format!(
                "{receipt_path}: statement or policy does not match the order"
            ));
        }
    }
    Ok(out)
}

/// 11. Nothing is loaded from another site; links out go only to the
///     allowed bases (block explorers, specifications, the apex documents).
pub fn nothing_external(base: &str, paths: &[String], allowed: &[String]) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for path in paths {
        let html = text(&get(base, path, None)?);
        for marker in serving::fetching_markers(&html) {
            out.push(format!("{path} loads from elsewhere: {marker}"));
        }
        for reference in references(&html) {
            let outside = reference.contains("://") || reference.starts_with("//");
            if outside && !allowed.iter().any(|a| reference.starts_with(a.as_str())) {
                out.push(format!("{path} links out to {reference}"));
            }
        }
    }
    Ok(out)
}
