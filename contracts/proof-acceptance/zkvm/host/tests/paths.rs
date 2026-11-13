//! A published program must not carry the paths or the login name of the
//! machine that built it. Rust records source paths in panic locations, and
//! those strings are loaded data, so they are part of the image and of what
//! anyone who downloads the binary reads.
//!
//! Two rules, on the user program inside every `program/*.bin`:
//!
//! * no occurrence of the login name, home directory or checkout path of
//!   whoever runs this test (which catches a binary the runner built without
//!   the remapping);
//! * every home-directory-shaped path (`/Users/...`, `/home/...`) is one of
//!   the paths RISC Zero's prebuilt guest standard library carries from the
//!   machine that built that toolchain. This holds on any machine, so it also
//!   catches a binary someone else built without the remapping.
//!
//! Not scanned:
//!
//! * the kernel half of each binary, which is RISC Zero's published kernel
//!   and carries RISC Zero's own build paths;
//! * `nucleus-vault-acceptance.bin`, the second-form program. It was built
//!   before this rule, it does contain such paths, and it cannot be rebuilt
//!   to the same image ID, which a live vault's settled order names. It stays
//!   in this tree and is left out of the public release.
use risc0_binfmt::ProgramBinary;
use std::{fs, path::Path};

const BUILT_BEFORE_THE_RULE: &str = "nucleus-vault-acceptance.bin";

/// Where the RISC Zero Rust toolchain 1.97.0 for guests was built, as its
/// prebuilt standard library records it. Not ours, and public in every
/// program built with that toolchain.
const TOOLCHAIN_BUILDER_PATHS: &[u8] = b"/Users/administrator/.cargo/registry/src/";

/// Home-directory-shaped paths in `bytes` that do not start with `allowed`.
fn foreign_home_paths(bytes: &[u8], allowed: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    for marker in [&b"/Users/"[..], &b"/home/"[..]] {
        for at in 0..bytes.len().saturating_sub(marker.len()) {
            if &bytes[at..at + marker.len()] != marker || bytes[at..].starts_with(allowed) {
                continue;
            }
            let end = bytes.len().min(at + 48);
            found.push(String::from_utf8_lossy(&bytes[at..end]).into_owned());
        }
    }
    found
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn published_programs_carry_no_local_paths_or_login_name() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../program");
    // Read at test time, never written down: who is running this, and where.
    let login = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .expect("the checkout root");
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("the login name", login.into_bytes()),
        ("the home directory", home.into_bytes()),
        (
            "the checkout path",
            checkout.to_string_lossy().into_owned().into_bytes(),
        ),
    ];
    let mut scanned = 0;
    let mut hits = Vec::new();
    for entry in fs::read_dir(&dir).expect("the program directory") {
        let path = entry.expect("a directory entry").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".bin") || name == BUILT_BEFORE_THE_RULE {
            continue;
        }
        let bytes = fs::read(&path).expect("a program binary");
        let program = ProgramBinary::decode(&bytes).expect("a RISC Zero program binary");
        scanned += 1;
        for (what, needle) in &needles {
            // A login of one or two letters would match by accident.
            if needle.len() < 3 {
                continue;
            }
            let count = occurrences(program.user_elf, needle);
            if count != 0 {
                hits.push(format!("{name}: {what}, {count} times"));
            }
        }
        let foreign = foreign_home_paths(program.user_elf, TOOLCHAIN_BUILDER_PATHS);
        if !foreign.is_empty() {
            hits.push(format!(
                "{name}: {} home-directory paths that are not the toolchain's",
                foreign.len()
            ));
        }
    }
    assert!(
        scanned >= 2,
        "expected at least the base and order programs"
    );
    assert!(hits.is_empty(), "{hits:#?}");
}
