//! Host conformance for the wire boundary: compressed wire proofs (negated `a`)
//! must verify through the agave fold, and the negate layout is involutive.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use groth16_solana::groth16::{negate_g1_be, Groth16Verifyingkey};
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use zolana_groth16_batch::{batch_verify_wire, WireProof};

fn g1_bytes(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
        out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    }
    out
}

fn g2_bytes(point: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
        out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
        out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
        out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
    }
    out
}

fn g1(scalar: Fr) -> G1Affine {
    (G1Projective::generator() * scalar).into_affine()
}

fn g2(scalar: Fr) -> G2Affine {
    (G2Projective::generator() * scalar).into_affine()
}

fn compress_g1(point: &G1Affine) -> [u8; 32] {
    alt_bn128_g1_compress_be(&g1_bytes(point))
        .expect("compress g1")
        .as_slice()
        .try_into()
        .expect("g1 size")
}

fn compress_g2(point: &G2Affine) -> [u8; 64] {
    alt_bn128_g2_compress_be(&g2_bytes(point))
        .expect("compress g2")
        .as_slice()
        .try_into()
        .expect("g2 size")
}

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

/// Trapdoor Groth16 over the full wire path: compress + negate `a` on the wire,
/// decompress + un-negate at the boundary, verify via the symlinked agave fold.
#[test]
fn wire_fold_round_trip() {
    let mut rng = StdRng::seed_from_u64(7);
    let (alpha, beta, gamma, delta) = (
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    );
    let (ic0, ic1) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let ic = [g1_bytes(&g1(ic0)), g1_bytes(&g1(ic1))];
    let vk = Groth16Verifyingkey {
        nr_pubinputs: 1,
        vk_alpha_g1: g1_bytes(&g1(alpha)),
        vk_beta_g2: g2_bytes(&g2(beta)),
        vk_gamma_g2: g2_bytes(&g2(gamma)),
        vk_delta_g2: g2_bytes(&g2(delta)),
        vk_ic: &ic,
        vk_commitment: None,
    };

    let x = Fr::rand(&mut rng);
    let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let l = ic0 + x * ic1;
    let c = (a * b - alpha * beta - l * gamma) * delta.inverse().expect("delta != 0");

    // Solo wire layout: `a` ships negated (curve negation here; the boundary's
    // byte-level un-negate must agree with it for the fold to verify).
    let wire = WireProof {
        a: compress_g1(&(-g1(a))),
        b: compress_g2(&g2(b)),
        c: compress_g1(&g1(c)),
    };
    let mut public_input = [0u8; 32];
    public_input.copy_from_slice(&x.into_bigint().to_bytes_be());

    assert_eq!(batch_verify_wire(&vk, &[(wire, public_input)]), Ok(true));

    let mut wrong = public_input;
    wrong[31] ^= 1;
    assert_eq!(batch_verify_wire(&vk, &[(wire, wrong)]), Ok(false));
}
