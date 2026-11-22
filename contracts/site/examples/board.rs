//! Writes the Lean Proof Board's input (`input/board/`) from the page the
//! leaderboard tool wrote and the verdicts it links.
//!
//!   cargo run --example board -- BOARD_DIR OUT_DIR [HOST_WORK_DIR]
//!
//! BOARD_DIR holds the tool's `index.html` and the `work/verdicts/…` files
//! its rows link. OUT_DIR is `contracts/site/input/board`. HOST_WORK_DIR is
//! the checking host's work directory, when verdicts name it in build
//! errors: it is written `$SRC/` (`nucleus_site::proof_board::REDACTED_WORK_DIR`)
//! and the row keeps the original file's hash. It is passed here, never
//! written into the tree. Every value the page prints is checked against
//! its verdict first (`nucleus_site::proof_board::derive`).
use std::{error::Error, fs, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: board BOARD_DIR OUT_DIR [HOST_WORK_DIR]";
    let source = args.next().ok_or(usage)?;
    let out = args.next().ok_or(usage)?;
    let host_work_dir = args.next();
    let source = Path::new(&source);
    let index = fs::read_to_string(source.join("index.html"))?;
    let verdict = |href: &str| -> nucleus_site::Res<Vec<u8>> {
        if href.contains("..") || href.starts_with('/') {
            return Err(format!("{href}: not a path inside the board directory").into());
        }
        Ok(fs::read(source.join(href)).map_err(|e| format!("{href}: {e}"))?)
    };
    let (board, files) =
        nucleus_site::proof_board::derive(&index, &verdict, host_work_dir.as_deref())?;
    let out = Path::new(&out);
    for (path, bytes) in &files {
        let target = out.join(path);
        if let Some(dir) = target.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&target, bytes)?;
    }
    let redacted = board
        .rows
        .iter()
        .filter(|r| r.verdict_sha256 != r.source_verdict_sha256)
        .count();
    println!(
        "{} rows, {} files written, {redacted} verdicts redacted",
        board.rows.len(),
        files.len()
    );
    Ok(())
}
