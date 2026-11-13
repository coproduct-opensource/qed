//! `nucleus-site check-live URL BUILT_DIR`: after upload, fetch what the
//! host serves and compare it with the built files and with the serving
//! table. Read-only: GET requests to one host, nothing else.
use crate::{Res, card_violations, hex, serving};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// One finding: the path and what is wrong with it.
pub type Finding = (String, String);

/// Fetch every checked path from `base` and compare with `built`. `https`
/// must be the scheme, except for a loopback preview (`http://127.0.0.1:…`),
/// where HSTS is not expected.
pub fn check(base: &str, built: &Path) -> Res<Vec<Finding>> {
    let base = base.trim_end_matches('/');
    let https = base.starts_with("https://");
    if !https && !base.starts_with("http://127.0.0.1:") {
        return Err("check-live takes an https URL, or http://127.0.0.1:PORT for a preview".into());
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let mut findings = Vec::new();
    // The fixed paths, then one file from each directory the table gives
    // its own headers (cache lifetime, media type, cross-origin), and the
    // checker module: a host rule that overrides them shows up here.
    let mut paths: Vec<(String, bool)> = serving::checked_paths()
        .iter()
        .map(|(p, card)| ((*p).to_owned(), *card))
        .collect();
    for dir in ["abi", "artifacts", "statements"] {
        let mut names: Vec<String> = fs::read_dir(built.join(dir))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        // Both statement formats when present.
        let mut seen_ext = std::collections::BTreeSet::new();
        for name in names {
            let ext = name.rsplit('.').next().unwrap_or("").to_owned();
            if seen_ext.insert(ext) {
                paths.push((format!("{dir}/{name}"), false));
            }
        }
    }
    if built.join(crate::CHECKER_PATH).is_file() {
        paths.push((crate::CHECKER_PATH.to_owned(), false));
    }
    for (path, is_card) in &paths {
        let (path, is_card) = (path.as_str(), *is_card);
        let mut fail = |what: String| findings.push((format!("/{path}"), what));
        let mut response = match agent.get(format!("{base}/{path}")).call() {
            Ok(response) => response,
            Err(error) => {
                fail(format!("no response: {error}"));
                continue;
            }
        };
        if response.status() != 200 {
            fail(format!("status {}", response.status()));
            continue;
        }
        let header = |name: &str| -> Option<String> {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let (media, cors, hsts, cache, etag) = (
            header("content-type"),
            header("access-control-allow-origin"),
            header("strict-transport-security"),
            header("cache-control"),
            header("etag"),
        );
        let body = response.body_mut().read_to_vec()?;
        let file = serving::candidates(path, false)
            .into_iter()
            .find(|c| built.join(c).is_file())
            .ok_or_else(|| format!("{path}: no built file answers it"))?;
        let file = file.as_str();
        let wanted = fs::read(built.join(file)).map_err(|e| format!("{file}: {e}"))?;
        if Sha256::digest(&body) != Sha256::digest(&wanted) {
            fail(format!(
                "served bytes (sha256 {}) differ from the built file (sha256 {})",
                hex(&Sha256::digest(&body)),
                hex(&Sha256::digest(&wanted))
            ));
        }
        let expected = serving::media_type(file);
        let base_type = |t: &str| {
            t.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        };
        if media.as_deref().map(base_type) != Some(base_type(expected)) {
            fail(format!("content-type {media:?}, expected {expected}"));
        }
        match (serving::cross_origin(path), cors.as_deref()) {
            (true, Some("*")) | (false, None) => {}
            (want, got) => fail(format!(
                "access-control-allow-origin {got:?}, expected {}",
                if want { "*" } else { "none" }
            )),
        }
        if https && hsts.as_deref() != Some(serving::HSTS) {
            fail(format!("strict-transport-security {hsts:?}"));
        }
        if cache.as_deref() != Some(serving::cache_control(file)) {
            fail(format!("cache-control {cache:?}"));
        }
        if serving::is_document(path) {
            // The same route asked for as Markdown.
            let wanted = serving::candidates(path, true)[0].clone();
            match agent
                .get(format!("{base}/{path}"))
                .header("accept", "text/markdown")
                .call()
            {
                Ok(mut md) => {
                    let media = md
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let vary = md
                        .headers()
                        .get("vary")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let got = md.body_mut().read_to_vec()?;
                    let want = fs::read(built.join(&wanted)).unwrap_or_default();
                    if !media.starts_with("text/markdown") || got != want {
                        fail(format!("Accept: text/markdown gave {media}, not {wanted}"));
                    }
                    if !vary.contains("accept") {
                        fail("no Vary: Accept on the Markdown response".into());
                    }
                }
                Err(error) => fail(format!("Markdown request failed: {error}")),
            }
        }
        if is_card {
            if etag.is_none() {
                fail("no ETag (A2A 1.0.1 §8.6.1 SHOULD)".into());
            }
            match serde_json::from_slice(&body) {
                Ok(card) => {
                    for violation in card_violations(&card) {
                        fail(format!("card: {violation}"));
                    }
                }
                Err(error) => fail(format!("not JSON: {error}")),
            }
        }
        if expected.starts_with("text/html") {
            let text = String::from_utf8_lossy(&body);
            for marker in serving::fetching_markers(&text) {
                fail(format!("loads an outside resource: {marker}"));
            }
        }
    }
    Ok(findings)
}
