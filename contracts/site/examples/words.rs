//! Counted prose words of a built site, by the rule in `src/words.rs`.
//!
//!   cargo run --example words -- BUILT_SITE_DIR [PAGE_FILE]
//!
//! With PAGE_FILE (a built path such as `bounty/index.html`), it prints that
//! page's counted blocks instead.
//!
//! The site test `the_whole_site_has_at_most_3000_counted_words` applies the
//! same function to the site built from the committed inputs; this reads a
//! built directory, such as the one a deploy uploaded.
use std::{error::Error, fs, path::Path};

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, root, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push((rel.display().to_string(), fs::read(&path)?));
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: words BUILT_SITE_DIR")?;
    let root = Path::new(&dir);
    if let Some(page) = std::env::args().nth(2) {
        for block in nucleus_site::words::counted_blocks(&fs::read_to_string(root.join(page))?) {
            println!("{block}");
        }
        return Ok(());
    }
    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    print!("{}", nucleus_site::words::count(&files).report());
    Ok(())
}
