//! The document model. Every page is a `Doc`: typed blocks of typed inline
//! content. The HTML page and the Markdown representation an agent gets
//! with `Accept: text/markdown` are two renderings of the same `Doc`, so
//! they cannot say different things.
use crate::CARD_PATH;
use crate::html::{Html, data_block, el, tx, void};

#[derive(Clone, Debug)]
pub enum Inline {
    Text(String),
    Strong(String),
    Code(String),
    Link {
        href: String,
        text: String,
    },
    /// A link whose text is code: a path, an address, a hash.
    CodeLink {
        href: String,
        text: String,
    },
}

pub fn t(s: impl Into<String>) -> Inline {
    Inline::Text(s.into())
}
pub fn strong(s: impl Into<String>) -> Inline {
    Inline::Strong(s.into())
}
pub fn code(s: impl Into<String>) -> Inline {
    Inline::Code(s.into())
}
pub fn link(href: impl Into<String>, text: impl Into<String>) -> Inline {
    Inline::Link {
        href: href.into(),
        text: text.into(),
    }
}
pub fn code_link(href: impl Into<String>, text: impl Into<String>) -> Inline {
    Inline::CodeLink {
        href: href.into(),
        text: text.into(),
    }
}

pub type Line = Vec<Inline>;

#[derive(Clone, Debug)]
pub enum Block {
    /// A section heading, level 2 or 3, with an anchor.
    Heading {
        level: u8,
        id: String,
        text: String,
    },
    P(Line),
    Ul(Vec<Line>),
    Ol(Vec<Line>),
    Table {
        caption: String,
        head: Vec<String>,
        rows: Vec<Vec<Line>>,
    },
    /// Term and description pairs.
    Dl(Vec<(String, Line)>),
    /// Preformatted text. With `copy`, a button (hidden until the script
    /// runs) copies it; the text is readable and selectable without it.
    Pre {
        id: String,
        text: String,
        copy: Option<String>,
    },
    /// A native disclosure for technical detail.
    Details {
        summary: String,
        blocks: Vec<Block>,
    },
    /// A boxed note.
    Note {
        title: String,
        blocks: Vec<Block>,
    },
    /// HTML made elsewhere in this crate (the live board's markup, which only
    /// makes sense with the page's script; the specification rendered from
    /// its Markdown source), and what an agent reading Markdown gets instead.
    Rendered {
        html: Html,
        markdown: String,
    },
}

pub fn h2(id: &str, text: &str) -> Block {
    Block::Heading {
        level: 2,
        id: id.into(),
        text: text.into(),
    }
}
pub fn h3(id: &str, text: &str) -> Block {
    Block::Heading {
        level: 3,
        id: id.into(),
        text: text.into(),
    }
}
pub fn p(line: Line) -> Block {
    Block::P(line)
}
pub fn para(text: &str) -> Block {
    Block::P(vec![t(text)])
}

#[derive(Clone, Debug)]
pub struct Doc {
    /// Route without the leading slash: "" for the root, "protocol", …
    pub path: String,
    pub title: String,
    pub description: String,
    /// The page's own heading. The root page sets its own masthead.
    pub heading: String,
    pub blocks: Vec<Block>,
    /// Whether the page loads `/qed.js` (copy buttons, the live board).
    pub script: bool,
    /// A JSON data block for the script, with its element id.
    pub data: Option<(String, String)>,
}

impl Doc {
    pub fn url(&self) -> String {
        if self.path.is_empty() {
            "/".into()
        } else {
            format!("/{}", self.path)
        }
    }
    pub fn html_file(&self) -> String {
        if self.path.is_empty() {
            "index.html".into()
        } else {
            format!("{}/index.html", self.path)
        }
    }
    pub fn markdown_file(&self) -> String {
        if self.path.is_empty() {
            "index.md".into()
        } else {
            format!("{}/index.md", self.path)
        }
    }
}

/// The numbered index every page carries, as in the brief's mock.
pub const INDEX: [(&str, &str); 6] = [
    ("protocol/specification", "Specification"),
    ("transactions", "Ledger"),
    ("verify", "Verify"),
    ("protocol/threat-model", "Threat model"),
    ("sellers/run", "Run a seller"),
    ("verification/source", "Source"),
];

fn inline_html(line: &[Inline]) -> Html {
    Html::join(line.iter().map(|i| match i {
        Inline::Text(s) => Html::text(s),
        Inline::Strong(s) => tx("strong", &[], s),
        Inline::Code(s) => tx("code", &[], s),
        Inline::Link { href, text } => tx("a", &[("href", href)], text),
        Inline::CodeLink { href, text } => el("a", &[("href", href)], [tx("code", &[], text)]),
    }))
}

fn block_html(block: &Block) -> Html {
    match block {
        Block::Heading { level, id, text } => {
            tx(if *level == 3 { "h3" } else { "h2" }, &[("id", id)], text)
        }
        Block::P(line) => el("p", &[], [inline_html(line)]),
        Block::Ul(items) => el(
            "ul",
            &[],
            items.iter().map(|l| el("li", &[], [inline_html(l)])),
        ),
        Block::Ol(items) => el(
            "ol",
            &[],
            items.iter().map(|l| el("li", &[], [inline_html(l)])),
        ),
        Block::Table {
            caption,
            head,
            rows,
        } => el(
            "div",
            &[("class", "scroll")],
            [el(
                "table",
                &[],
                [
                    tx("caption", &[], caption),
                    el(
                        "thead",
                        &[],
                        [el(
                            "tr",
                            &[],
                            head.iter().map(|h| tx("th", &[("scope", "col")], h)),
                        )],
                    ),
                    el(
                        "tbody",
                        &[],
                        rows.iter().map(|row| {
                            el(
                                "tr",
                                &[],
                                row.iter().enumerate().map(|(n, cell)| {
                                    if n == 0 {
                                        el("th", &[("scope", "row")], [inline_html(cell)])
                                    } else {
                                        el("td", &[], [inline_html(cell)])
                                    }
                                }),
                            )
                        }),
                    ),
                ],
            )],
        ),
        Block::Dl(pairs) => el(
            "dl",
            &[],
            pairs
                .iter()
                .flat_map(|(term, desc)| [tx("dt", &[], term), el("dd", &[], [inline_html(desc)])]),
        ),
        Block::Pre { id, text, copy } => {
            let pre = el("pre", &[("id", id)], [Html::text(text)]);
            match copy {
                None => pre,
                Some(label) => el(
                    "div",
                    &[("class", "copyable")],
                    [
                        pre,
                        tx(
                            "button",
                            &[("type", "button"), ("data-copy", id), ("hidden", "")],
                            label,
                        ),
                    ],
                ),
            }
        }
        Block::Details { summary, blocks } => el(
            "details",
            &[],
            std::iter::once(tx("summary", &[], summary)).chain(blocks.iter().map(block_html)),
        ),
        Block::Note { title, blocks } => el(
            "aside",
            &[("class", "note"), ("aria-label", title)],
            std::iter::once(tx("p", &[("class", "note-title")], title))
                .chain(blocks.iter().map(block_html)),
        ),
        Block::Rendered { html, .. } => html.clone(),
    }
}

/// Characters that Markdown would read as syntax in running text.
fn md_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn md_code(s: &str) -> String {
    let fence = if s.contains('`') { "``" } else { "`" };
    let pad = if s.starts_with('`') || s.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{s}{pad}{fence}")
}

fn inline_md(line: &[Inline]) -> String {
    line.iter()
        .map(|i| match i {
            Inline::Text(s) => md_text(s),
            Inline::Strong(s) => format!("**{}**", md_text(s)),
            Inline::Code(s) => md_code(s),
            Inline::Link { href, text } => format!("[{}]({})", md_text(text), href),
            Inline::CodeLink { href, text } => format!("[{}]({})", md_code(text), href),
        })
        .collect()
}

fn block_md(block: &Block, out: &mut String) {
    match block {
        Block::Heading { level, text, .. } => {
            out.push_str(&format!(
                "{} {}\n\n",
                "#".repeat(*level as usize),
                md_text(text)
            ));
        }
        Block::P(line) => out.push_str(&format!("{}\n\n", inline_md(line))),
        Block::Ul(items) => {
            for item in items {
                out.push_str(&format!("- {}\n", inline_md(item)));
            }
            out.push('\n');
        }
        Block::Ol(items) => {
            for (n, item) in items.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", n + 1, inline_md(item)));
            }
            out.push('\n');
        }
        Block::Table {
            caption,
            head,
            rows,
        } => {
            out.push_str(&format!("{}\n\n", md_text(caption)));
            out.push_str(&format!(
                "| {} |\n",
                head.iter()
                    .map(|h| md_text(h))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
            out.push_str(&format!("|{}\n", "---|".repeat(head.len())));
            for row in rows {
                out.push_str(&format!(
                    "| {} |\n",
                    row.iter()
                        .map(|c| inline_md(c))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            }
            out.push('\n');
        }
        Block::Dl(pairs) => {
            for (term, desc) in pairs {
                out.push_str(&format!("- **{}**: {}\n", md_text(term), inline_md(desc)));
            }
            out.push('\n');
        }
        Block::Pre { text, .. } => {
            let fence = if text.contains("```") { "~~~~" } else { "```" };
            out.push_str(&format!("{fence}\n{text}\n{fence}\n\n"));
        }
        Block::Details { summary, blocks }
        | Block::Note {
            title: summary,
            blocks,
        } => {
            out.push_str(&format!("**{}**\n\n", md_text(summary)));
            for b in blocks {
                block_md(b, out);
            }
        }
        Block::Rendered { markdown, .. } => out.push_str(&format!("{markdown}\n\n")),
    }
}

/// The Markdown representation of a page.
pub fn markdown(doc: &Doc, site: Option<&str>) -> String {
    let mut out = format!("# {}\n\n", md_text(&doc.heading));
    out.push_str(&format!("{}\n\n", md_text(&doc.description)));
    for block in &doc.blocks {
        block_md(block, &mut out);
    }
    out.push_str("---\n\n");
    out.push_str(&format!(
        "Index: {}. Agent Card: `/{CARD_PATH}`.",
        INDEX
            .iter()
            .enumerate()
            .map(|(n, (path, name))| format!("{:02} [{}](/{path})", n + 1, md_text(name)))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Some(site) = site {
        out.push_str(&format!(
            " This document: {}{}.",
            site.trim_end_matches('/'),
            doc.url()
        ));
    }
    out.push('\n');
    out
}

/// The masthead and the numbered index, on every page.
fn header(current: &str) -> Html {
    el(
        "header",
        &[],
        [
            el(
                "p",
                &[("class", "masthead")],
                [
                    tx("a", &[("href", "/")], "Q.E.D."),
                    Html::text(" · COPRODUCT / NUCLEUS"),
                ],
            ),
            el(
                "nav",
                &[("aria-label", "Index")],
                [el(
                    "ol",
                    &[("class", "index")],
                    INDEX.iter().map(|(path, name)| {
                        let href = format!("/{path}");
                        let attrs: Vec<(&str, &str)> = if *path == current {
                            vec![("href", href.as_str()), ("aria-current", "page")]
                        } else {
                            vec![("href", href.as_str())]
                        };
                        el("li", &[], [tx("a", &attrs, name)])
                    }),
                )],
            ),
        ],
    )
}

/// The page sent with every 404 (`crate::NOT_FOUND_PATH`): the masthead,
/// one sentence and a link home. No script and no Markdown twin. Without it
/// the host answered a missing path with an empty body and no media type,
/// which iPhone Safari offered to download.
pub fn not_found() -> String {
    let head = [
        void("meta", &[("charset", "utf-8")]),
        void(
            "meta",
            &[
                ("name", "viewport"),
                ("content", "width=device-width, initial-scale=1"),
            ],
        ),
        void(
            "meta",
            &[("name", "color-scheme"), ("content", "light dark")],
        ),
        tx("title", &[], "Not found · Q.E.D."),
        void("meta", &[("name", "robots"), ("content", "noindex")]),
        void("link", &[("rel", "icon"), ("href", "data:,")]),
        void("link", &[("rel", "stylesheet"), ("href", "/qed.css")]),
    ];
    let main = [
        tx("h1", &[], "Not found"),
        tx("p", &[], "Nothing is served at this address."),
        el("p", &[], [tx("a", &[("href", "/")], "Go to the home page")]),
    ];
    format!(
        "<!doctype html>\n{}\n",
        el(
            "html",
            &[("lang", "en")],
            [
                el("head", &[], head),
                el(
                    "body",
                    &[],
                    [header("404"), el("main", &[("id", "main")], main)]
                )
            ]
        )
        .as_str()
    )
}

/// The whole HTML page for a `Doc`.
pub fn page(doc: &Doc, site: Option<&str>, footer: &[Block]) -> String {
    let mut head = vec![
        void("meta", &[("charset", "utf-8")]),
        void(
            "meta",
            &[
                ("name", "viewport"),
                ("content", "width=device-width, initial-scale=1"),
            ],
        ),
        void(
            "meta",
            &[("name", "color-scheme"), ("content", "light dark")],
        ),
        tx("title", &[], &doc.title),
        void(
            "meta",
            &[("name", "description"), ("content", &doc.description)],
        ),
    ];
    if let Some(site) = site {
        let canonical = format!("{}{}", site.trim_end_matches('/'), doc.url());
        head.push(void("link", &[("rel", "canonical"), ("href", &canonical)]));
        // The sitemap exists only when the site's address is known.
        head.push(void(
            "link",
            &[
                ("rel", "sitemap"),
                ("type", "application/xml"),
                ("href", "/sitemap.xml"),
            ],
        ));
    }
    let md = format!("/{}", doc.markdown_file());
    let card = format!("/{CARD_PATH}");
    head.extend([
        void(
            "link",
            &[
                ("rel", "alternate"),
                ("type", "text/markdown"),
                ("href", &md),
            ],
        ),
        void(
            "link",
            &[
                ("rel", "alternate"),
                ("type", "application/json"),
                ("title", "A2A Agent Card"),
                ("href", &card),
            ],
        ),
        // An empty icon, so a browser does not ask for /favicon.ico.
        void("link", &[("rel", "icon"), ("href", "data:,")]),
        void("link", &[("rel", "stylesheet"), ("href", "/qed.css")]),
    ]);
    if doc.script {
        head.push(el("script", &[("src", "/qed.js"), ("defer", "")], []));
    }
    let mut main = vec![tx("h1", &[], &doc.heading)];
    main.extend(doc.blocks.iter().map(block_html));
    let mut body = vec![tx(
        "a",
        &[("class", "skip"), ("href", "#main")],
        "Skip to content",
    )];
    // The home page carries its own title, byline and numbered Index, so
    // the masthead and short navigation appear on the other pages only.
    if !doc.path.is_empty() {
        body.push(header(&doc.path));
    }
    body.extend([
        el("main", &[("id", "main")], main),
        el("footer", &[], footer.iter().map(block_html)),
    ]);
    if let Some((id, json)) = &doc.data {
        body.push(data_block(id, json));
    }
    format!(
        "<!doctype html>\n{}\n",
        el(
            "html",
            &[("lang", "en")],
            [el("head", &[], head), el("body", &[], body)]
        )
        .as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_escapes_syntax_in_text_and_keeps_code() {
        let doc = Doc {
            path: "x".into(),
            title: "T".into(),
            description: "d".into(),
            heading: "H".into(),
            blocks: vec![p(vec![t("a *b* [c]"), code("x*y")])],
            script: false,
            data: None,
        };
        let md = markdown(&doc, None);
        assert!(md.contains("a \\*b\\* \\[c\\]`x*y`"), "{md}");
    }
}
