//! Host checks that wire-layout negate is involutive (agave fold needs
//! non-negated `a`; zolana wire stores negated `a`).

use groth16_solana::groth16::negate_g1_be;

#[test]
fn wire_a_negate_is_involutive() {
    // Non-zero fake G1 encoding (not on-curve); only checks byte involution of negate_g1_be.
    let mut a = [0u8; 64];
    a[31] = 1;
    a[63] = 2;
    let neg = negate_g1_be(&a);
    let back = negate_g1_be(&neg);
    assert_eq!(back, a);
}

#[test]
fn agave_reference_crate_links() {
    // Ensures the path shim pulls the agave fold into this package graph.
    let _ = core::mem::size_of::<solana_bn254_groth16_batch::Version>();
    let _ = core::mem::size_of::<solana_bn254_batch_syscall::Version>();
}
