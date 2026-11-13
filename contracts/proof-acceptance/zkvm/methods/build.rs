//! Builds the guests with source paths remapped, so a published program does
//! not carry the builder's login name, home directory or checkout path.
//!
//! risc0-build 3.0.7 takes guest compiler flags only from the guest's own
//! `Cargo.toml` (`package.metadata.risc0.rustc-flags`), where a prefix that
//! differs per machine cannot be written, and it sets
//! `CARGO_ENCODED_RUSTFLAGS` itself, which makes cargo ignore every other
//! source of flags. It does keep `RUSTC_WRAPPER` (it removes only `CARGO*`
//! and `RUSTUP_TOOLCHAIN` from the environment of the inner cargo). So this
//! script compiles `guest-rustc.rs`, a wrapper that adds the remappings, and
//! points the inner build at it.
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// `FROM=TO` lines. rustc applies the last one that matches, so the home
/// directory, the catch-all, comes first and the specific roots after it.
fn remappings(manifest_dir: &Path) -> String {
    let mut lines = Vec::new();
    let mut map = |from: PathBuf, to: &str| {
        if let Ok(from) = from.canonicalize() {
            lines.push(format!("{}={to}", from.display()));
        }
    };
    let home = env::var_os("HOME").map(PathBuf::from);
    if let Some(home) = &home {
        map(home.clone(), "/builder");
        map(home.join(".rustup"), "/rustup");
        map(home.join(".risc0"), "/risc0");
        map(home.join(".cargo"), "/cargo");
    }
    for (variable, to) in [("RUSTUP_HOME", "/rustup"), ("CARGO_HOME", "/cargo")] {
        if let Some(dir) = env::var_os(variable) {
            map(PathBuf::from(dir), to);
        }
    }
    // The repository root: this crate is contracts/proof-acceptance/zkvm/methods.
    map(manifest_dir.join("../../../.."), "/nucleus");
    lines.join("\n")
}

fn main() {
    println!("cargo:rerun-if-changed=guest-rustc.rs");
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    let wrapper = out_dir.join("guest-rustc");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let built = Command::new(rustc)
        .arg("--edition=2021")
        .arg("-O")
        .arg("-o")
        .arg(&wrapper)
        .arg(manifest_dir.join("guest-rustc.rs"))
        .status()
        .expect("the host compiler runs");
    assert!(built.success(), "guest-rustc.rs did not compile");
    guests_with(&wrapper, &remappings(&manifest_dir));
}

/// Build and embed the guests with the wrapper in force.
///
/// An exception to ADR 0007 H-1 (no `set_var`; pass a value to the process
/// that needs it), allowed here and nowhere else in this workspace. The
/// process that needs these two values is the cargo that risc0-build spawns,
/// and risc0-build 3.0.7 builds that command itself: it takes no environment
/// from its caller except by inheritance, and no compiler flags except from
/// the guest's static `Cargo.toml`. The variables are set in this build
/// script's own process, which exists to run that one build.
#[allow(clippy::disallowed_methods)]
fn guests_with(wrapper: &Path, mappings: &str) {
    env::set_var("RUSTC_WRAPPER", wrapper);
    env::set_var("NUCLEUS_GUEST_REMAP", mappings);
    risc0_build::embed_methods();
}
