//! What a native build of the guests on this machine says about the published
//! programs, since the switch to the reproducible pair
//! (docs/rfcs/qed-reproducible-switch-2026-11-13.md).
//!
//! The published pair, `program/nucleus-base-check-fmt2r.bin` and
//! `program/nucleus-order-fmt2r.bin`, is built in RISC Zero's pinned builder
//! image and checked by `nucleus-acceptance-host verify-programs` (recipe
//! `program/REPRODUCIBLE`; public CI job `.github/workflows/verify-programs.yml`,
//! kept in `contracts/release/overlay-qed`), which
//! rebuilds both from source and requires the same image IDs and bytes. A
//! native build cannot give those bytes: the host compiler and its prebuilt
//! standard library differ (docs/rfcs/qed-reproducible-programs-2026-11-13.md).
//! So this file no longer compares a native build with a published binary.
//!
//! What is left here: the order guest's source names the published
//! reproducible base program (the host's test
//! `the_order_guest_source_names_the_published_reproducible_base_program`
//! checks the same constant against the embedded binary). Whether a native
//! build on some machine happens to equal the pinned one is not asserted
//! either way; it was measured to differ on macOS.

fn listed_base() -> String {
    let source = include_str!("../vault3/src/main.rs");
    source
        .split("const BASE_IMAGE_ID: [u8; 32] = [")
        .nth(1)
        .and_then(|rest| rest.split("];").next())
        .expect("BASE_IMAGE_ID in the order guest")
        .split(',')
        .filter_map(|byte| byte.trim().strip_prefix("0x").map(str::to_owned))
        .collect()
}

/// The order guest names the published reproducible base program.
#[test]
fn the_order_guest_names_the_published_base_program() {
    assert_eq!(
        listed_base(),
        include_str!("../../../program/IMAGE_ID_BASE_FMT2R").trim()
    );
}
