//! Building the base guest and the base-aware third-form guest from source on
//! this machine gives the published binaries, and the order guest names the
//! base guest it was built beside. Guest builds are not yet reproducible
//! across machines, so a failure here on another machine is a finding about
//! the build, not about the programs.
//!
//! There is no such test for the second-form program
//! (`program/nucleus-vault-acceptance.bin`, source at commit c4f020370): the
//! crates it links have changed since, so a build at HEAD is a different
//! program. `program/README.md` says what that leaves.
use nucleus_acceptance_methods::{
    NUCLEUS_BASE_GUEST_ELF, NUCLEUS_BASE_GUEST_ID, NUCLEUS_VAULT3_GUEST_ELF,
    NUCLEUS_VAULT3_GUEST_ID,
};

fn hex(id: [u32; 8]) -> String {
    id.iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Since statement format v2 (docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md)
/// the source builds the `-fmt2` pair. The earlier pair,
/// `nucleus-base-check.bin` (`67bddd19…cd3a`) and
/// `nucleus-vault3-acceptance.bin` (`fc879ae4…40bb`), stays published because
/// testnet contracts and posted tasks name it; its source is commit
/// `37bc16b7d`, and a build at HEAD is a different program.
#[test]
fn the_source_builds_are_the_published_binaries() {
    let base: &[u8] = include_bytes!("../../../program/nucleus-base-check-fmt2.bin");
    let order: &[u8] = include_bytes!("../../../program/nucleus-order-fmt2.bin");
    assert_eq!(
        hex(NUCLEUS_BASE_GUEST_ID),
        include_str!("../../../program/IMAGE_ID_BASE_FMT2").trim()
    );
    assert_eq!(
        hex(NUCLEUS_VAULT3_GUEST_ID),
        include_str!("../../../program/IMAGE_ID_ORDER_FMT2").trim()
    );
    assert!(
        NUCLEUS_BASE_GUEST_ELF == base,
        "bytes of the base guest's source build"
    );
    assert!(
        NUCLEUS_VAULT3_GUEST_ELF == order,
        "bytes of the order guest's source build"
    );
}

/// The order guest verifies commitments of one base program, named by a
/// constant in its source. That constant is this build's base guest.
#[test]
fn the_order_guest_names_the_base_guest_built_beside_it() {
    let source = include_str!("../vault3/src/main.rs");
    let listed: String = source
        .split("const BASE_IMAGE_ID: [u8; 32] = [")
        .nth(1)
        .and_then(|rest| rest.split("];").next())
        .expect("BASE_IMAGE_ID in the order guest")
        .split(',')
        .filter_map(|byte| byte.trim().strip_prefix("0x").map(str::to_owned))
        .collect();
    assert_eq!(listed, hex(NUCLEUS_BASE_GUEST_ID));
}
