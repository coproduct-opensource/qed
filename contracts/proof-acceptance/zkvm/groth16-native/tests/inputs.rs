//! The circuit inputs this crate derives from an `identity_p254` seal are,
//! byte for byte, the ones RISC Zero's own code derived from the same seal.
//! The fixture pair was written by `r0vm` 3.1.0 into its Groth16 work
//! directory while proving the third-form fixture order on 2026-11-12.
#[test]
fn inputs_equal_risc_zeros_for_the_same_seal() {
    let seal = include_bytes!("fixtures/identity-p254.seal");
    let theirs = include_str!("fixtures/input.json");
    let ours = nucleus_groth16_native::inputs::from_seal(seal).expect("a seal of the right size");
    assert!(ours == theirs, "inputs differ from RISC Zero's");

    // One changed word changes the inputs.
    let mut other = seal.to_vec();
    other[0] ^= 1;
    assert!(nucleus_groth16_native::inputs::from_seal(&other).unwrap() != theirs);
}
