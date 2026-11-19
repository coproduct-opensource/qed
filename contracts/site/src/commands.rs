//! Commands a page offers to copy must run as they are (owner review,
//! 2026-11-14: "Anything labeled copy/run must run as is"). A command that
//! needs the reader's own value is a template: it is shown under a label
//! saying what to fill in, and it has no copy control.
//!
//! [`placeholders`] finds what a reader would have to replace before a
//! command runs. It is a reviewer's rule written down, not a parser of
//! shell: it looks for the two shapes the site has used for placeholders.
//!
//! 1. A `0x` value with characters that are not hexadecimal in it
//!    (`0x…0PAYEE`, `0xYOUR_WALLET`).
//! 2. An upper-case name of four or more characters (`PAYEE`, `TARGET`,
//!    `BUYER_ADDRESS`), unless the same command assigns it (`NAME=`), reads it
//!    as a variable (`$NAME`, `${NAME}`), or it is one of [`LITERALS`], the
//!    upper-case words that are real names in the commands the site prints.

/// Upper-case words that are real in a command: a git revision, a file name
/// a release publishes, and an HTTP method.
pub const LITERALS: [&str; 3] = ["HEAD", "SHA256SUMS", "POST"];

fn is_name_char(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
}

/// What must be replaced before `command` runs; empty when it runs as is.
pub fn placeholders(command: &str) -> Vec<String> {
    let mut found = Vec::new();
    // 1. 0x values that are not hexadecimal.
    for (at, _) in command.match_indices("0x") {
        let before = command[..at].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let value: String = command[at + 2..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !value.is_empty() && !value.chars().all(|c| c.is_ascii_hexdigit()) {
            found.push(format!("0x{value}"));
        }
    }
    // 2. Upper-case names nobody assigned.
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if !is_name_char(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_name_char(chars[i]) {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        let joined_to_lower = (start > 0 && chars[start - 1].is_ascii_alphanumeric())
            || chars.get(i).is_some_and(|c| c.is_ascii_lowercase());
        let letters = name.chars().filter(char::is_ascii_uppercase).count();
        if joined_to_lower || name.len() < 4 || letters < 3 {
            continue;
        }
        let variable = command.contains(&format!("{name}="))
            || command.contains(&format!("${name}"))
            || command.contains(&format!("${{{name}}}"));
        if !variable && !LITERALS.contains(&name.as_str()) {
            found.push(name);
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The copyable commands in a built HTML page: (element id, text). A copy
/// control is a `button[data-copy]` naming a `pre` by id (`doc::block_html`).
pub fn copyable(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for piece in html.split("data-copy=\"").skip(1) {
        let Some(id) = piece.split('"').next() else {
            continue;
        };
        let open = format!("<pre id=\"{id}\">");
        let Some(text) = html
            .split(&open)
            .nth(1)
            .and_then(|rest| rest.split("</pre>").next())
        else {
            out.push((id.to_owned(), String::new()));
            continue;
        };
        out.push((
            id.to_owned(),
            text.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&amp;", "&"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shapes_the_site_used_are_found_and_real_commands_pass() {
        for (command, expect) in [
            (
                r#"{"topics":["0xddf252ad","0x000000000000000000000000000000000000000000000000000000000000PAYEE"]}"#,
                vec!["0x000000000000000000000000000000000000000000000000000000000000PAYEE"],
            ),
            (
                "nucleus-seller sweep seller.json 0xYOUR_WALLET",
                vec!["0xYOUR_WALLET"],
            ),
            (
                "gh release download v0.2.3 -p 'qed-TARGET.tar.gz' -p SHA256SUMS",
                vec!["TARGET"],
            ),
            (
                r#"{"params":["BUYER_ADDRESS","latest"]}"#,
                vec!["BUYER_ADDRESS"],
            ),
        ] {
            assert_eq!(placeholders(command), expect, "{command}");
        }
        for command in [
            "curl -s https://mainnet.base.org -d '{\"params\":[\"0xd15c105ed0d15c105ed0d15c105ed0d15c105ed0\",\"0x36a1d6c\"]}'",
            "IMAGE=ghcr.io/x@sha256:ab\ncontainer image pull \"$IMAGE\"",
            "verify-programs --runtime docker --commit HEAD",
            "curl -s -o /dev/null -w '%{http_code}\\n' -X POST https://relay.example/relay",
            "sha256sum -c --ignore-missing SHA256SUMS",
            "dig +dnssec qed.coproduct.dev A @1.1.1.1",
        ] {
            assert_eq!(placeholders(command), Vec::<String>::new(), "{command}");
        }
    }
}
