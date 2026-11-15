//! The site paths a beacon may name, and the beacon's wire format.
//!
//! A beacon is a `POST /analytics/beacon` whose body is the page's label from
//! [`ALLOWED`], a newline, and `1` if the browser had not sent a beacon yet
//! that UTC day or `0` otherwise: `/status\n1`. At most [`MAX_BODY`] bytes.
//! The site's script sends it (`contracts/site/assets/qed.js`); the page
//! carries its label in `<meta name="qed-beacon">`.
use crate::core::PATHS;

/// Every page label the collector counts. Transaction pages share one label.
/// The order is the cell order (`core::cell`); appending is the only safe
/// change, since published days name cells by label.
pub const ALLOWED: [&str; PATHS] = [
    "/",
    "/protocol",
    "/protocol/specification",
    "/protocol/threat-model",
    "/protocol/a2a-iroh-binding",
    "/agent-card",
    "/participate",
    "/transactions",
    "/transactions/*",
    "/verify",
    "/verification/test-vectors",
    "/verification/source",
    "/sellers/run",
    "/bounty",
    "/status",
    "/visits",
];

/// The longest body read. The longest valid body is 29 bytes.
pub const MAX_BODY: usize = 64;

/// The cell label of a site path, as the page's `<meta name="qed-beacon">`
/// gives it: the path itself if it is on the list, `/transactions/*` for a
/// transaction page, nothing otherwise.
pub fn label(path: &str) -> Option<&'static str> {
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    if let Some(found) = ALLOWED.iter().find(|p| **p == path) {
        return Some(found);
    }
    let id = path.strip_prefix("/transactions/")?;
    (id.len() == 66 && id.starts_with("0x") && id[2..].bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some("/transactions/*")
}

/// Parse a body into `(path index, first)`. Anything that is not exactly an
/// allowed label, a newline and `0` or `1` is malformed: index `PATHS`
/// (the core counts it in the malformed cell).
pub fn parse(body: &[u8]) -> (usize, bool) {
    const MALFORMED: (usize, bool) = (PATHS, false);
    if body.len() > MAX_BODY {
        return MALFORMED;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return MALFORMED;
    };
    let Some((path, bit)) = text.split_once('\n') else {
        return MALFORMED;
    };
    let first = match bit {
        "1" => true,
        "0" => false,
        _ => return MALFORMED,
    };
    match ALLOWED.iter().position(|p| *p == path) {
        Some(index) => (index, first),
        None => MALFORMED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bodies_parse_and_everything_else_is_malformed() {
        assert_eq!(parse(b"/status\n1"), (14, true));
        assert_eq!(parse(b"/\n0"), (0, false));
        assert_eq!(parse(b"/transactions/*\n0"), (8, false));
        for bad in [
            &b"/status\n2"[..],
            b"/status",
            b"/status\n1\n",
            b"/status \n1",
            b"/nowhere\n1",
            b"/status\n1extra",
            b"\xff\n1",
            b"",
        ] {
            assert_eq!(parse(bad), (PATHS, false), "{bad:?}");
        }
        let long = format!("/status\n1{}", " ".repeat(MAX_BODY));
        assert_eq!(parse(long.as_bytes()), (PATHS, false));
    }

    #[test]
    fn labels_cover_the_pages_and_transaction_pages_share_one() {
        assert_eq!(label("/"), Some("/"));
        assert_eq!(label("/status/"), Some("/status"));
        let tx = format!("/transactions/0x{}", "ab".repeat(32));
        assert_eq!(label(&tx), Some("/transactions/*"));
        assert_eq!(label("/transactions/0x12"), None);
        assert_eq!(label("/elsewhere"), None);
        assert!(ALLOWED.iter().all(|p| p.len() + 2 <= MAX_BODY));
        let unique: std::collections::BTreeSet<_> = ALLOWED.iter().collect();
        assert_eq!(unique.len(), PATHS);
    }
}
