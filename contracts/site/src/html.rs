//! HTML with escaping by construction. An `Html` value is made only from
//! escaped text, from elements whose attribute values are escaped, or by
//! joining other `Html` values; nothing outside this module can put raw
//! markup into one. The one exception, `Html::trusted`, takes a `&'static
//! str`, so it can only hold text written in this crate's source.

/// Escape text for an HTML text node or a double-quoted attribute value.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Html(String);

impl Html {
    pub fn text(text: &str) -> Self {
        Self(esc(text))
    }
    /// Markup written in this crate's source.
    pub fn trusted(markup: &'static str) -> Self {
        Self(markup.to_owned())
    }
    pub fn join(parts: impl IntoIterator<Item = Html>) -> Self {
        Self(parts.into_iter().map(|h| h.0).collect())
    }
    /// Markdown rendered by pulldown-cmark, which escapes text. Raw HTML in
    /// the source is shown as text, not passed through, so the source cannot
    /// add a script, a style or a resource.
    pub fn from_markdown(source: &str) -> Self {
        use pulldown_cmark::{Event, Options, Parser, html};
        let mut options = Options::empty();
        options.insert(Options::ENABLE_TABLES);
        let events = Parser::new_ext(source, options).map(|event| match event {
            Event::Html(text) | Event::InlineHtml(text) => Event::Text(text),
            other => other,
        });
        let mut out = String::new();
        html::push_html(&mut out, events);
        Self(out)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn open(tag: &str, attributes: &[(&str, &str)]) -> String {
    debug_assert!(valid_name(tag), "tag {tag}");
    let mut out = format!("<{tag}");
    for (name, value) in attributes {
        debug_assert!(valid_name(name), "attribute {name}");
        if value.is_empty() && matches!(*name, "hidden" | "open" | "defer") {
            out.push_str(&format!(" {name}"));
        } else {
            out.push_str(&format!(" {name}=\"{}\"", esc(value)));
        }
    }
    out.push('>');
    out
}

/// An element with children.
pub fn el(
    tag: &str,
    attributes: &[(&str, &str)],
    children: impl IntoIterator<Item = Html>,
) -> Html {
    let inner = Html::join(children);
    Html(format!("{}{}</{tag}>", open(tag, attributes), inner.0))
}

/// An element with one text child.
pub fn tx(tag: &str, attributes: &[(&str, &str)], text: &str) -> Html {
    el(tag, attributes, [Html::text(text)])
}

/// An element with no end tag.
pub fn void(tag: &str, attributes: &[(&str, &str)]) -> Html {
    Html(open(tag, attributes))
}

/// A `<script type="application/json">` data block. `</` cannot appear in a
/// script element's text, so it is written `<\/`, which JSON reads the same.
pub fn data_block(id: &str, json: &str) -> Html {
    Html(format!(
        "{}{}</script>",
        open("script", &[("type", "application/json"), ("id", id)]),
        json.replace("</", "<\\/")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_attributes_are_escaped() {
        let h = el(
            "a",
            &[("href", "/x?a=1&b=\"2\"")],
            [Html::text("<script>alert(1)</script>")],
        );
        assert_eq!(
            h.as_str(),
            "<a href=\"/x?a=1&amp;b=&quot;2&quot;\">&lt;script&gt;alert(1)&lt;/script&gt;</a>"
        );
    }

    #[test]
    fn a_data_block_cannot_close_its_script_early() {
        let h = data_block("d", "{\"x\":\"</script><b>\"}");
        assert!(!h.as_str()[..h.as_str().len() - 9].contains("</script>"));
    }
}
