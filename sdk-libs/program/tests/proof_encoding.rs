//! Pins the SDK's own proof and verifying-key encoding to the bytes Xark's
//! `xark_groth16::solana` encoder produces, which the SDK used before.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_serialize::CanonicalSerialize;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use spr_program::proof::{compressed_proof, SolanaVerifyingKey};
use xark_groth16::{solana, Proof, VerifyingKey};

fn g1(scalar: u64) -> G1Affine {
    (G1Projective::generator() * Fr::from(scalar)).into_affine()
}

fn g2(scalar: u64) -> G2Affine {
    (G2Projective::generator() * Fr::from(scalar)).into_affine()
}

fn compressed<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// Xark's little-endian coordinates in the big-endian order Solana takes,
/// swapping the limbs of each G2 coordinate: the conversion the SDK used to
/// apply to `xark_groth16::solana`'s output.
fn le_to_be(le: &[u8], g2: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(le.len());
    if g2 {
        for coordinate in le.as_chunks::<64>().0 {
            let (c0, c1) = coordinate.split_at(32);
            out.extend(c1.iter().rev());
            out.extend(c0.iter().rev());
        }
    } else {
        for coordinate in le.as_chunks::<32>().0 {
            out.extend(coordinate.iter().rev());
        }
    }
    out
}

fn reference_proof(proof: &Proof<ark_bn254::Bn254>) -> ([u8; 32], [u8; 64], [u8; 32]) {
    let le = solana::assemble_proof_bytes_le(proof);
    let a: [u8; 64] = le_to_be(le.get(0..64).unwrap(), false).try_into().unwrap();
    let b: [u8; 128] = le_to_be(le.get(64..192).unwrap(), true).try_into().unwrap();
    let c: [u8; 64] = le_to_be(le.get(192..256).unwrap(), false)
        .try_into()
        .unwrap();
    (
        alt_bn128_g1_compress_be(&a).unwrap(),
        alt_bn128_g2_compress_be(&b).unwrap(),
        alt_bn128_g1_compress_be(&c).unwrap(),
    )
}

#[test]
fn compressed_proofs_match_the_xark_solana_encoding() {
    for (a, b, c) in [(1, 1, 1), (7, 11, 13), (u64::MAX, 3, u64::MAX - 1)] {
        let proof = Proof::<ark_bn254::Bn254> {
            a: g1(a),
            b: g2(b),
            c: g1(c),
        };
        let ours = compressed_proof(&compressed(&proof)).unwrap();
        assert_eq!((ours.a, ours.b, ours.c), reference_proof(&proof));
    }
}

#[test]
fn verifying_keys_match_the_xark_solana_encoding() {
    for inputs in [1u64, 2, 5] {
        let key = VerifyingKey::<ark_bn254::Bn254> {
            alpha_g1: g1(2),
            beta_g2: g2(3),
            gamma_g2: g2(5),
            delta_g2: g2(7),
            gamma_abc_g1: (0..inputs).map(|i| g1(100 + i)).collect(),
        };
        let le = solana::assemble_vk_bytes_le(&key);
        let ours = SolanaVerifyingKey::from_xark(&compressed(&key)).unwrap();
        let ours = ours.as_key();
        let expected_ic: Vec<Vec<u8>> = le
            .get(448..)
            .unwrap()
            .as_chunks::<64>()
            .0
            .iter()
            .map(|point| le_to_be(point, false))
            .collect();
        assert_eq!(
            (
                ours.nr_pubinputs,
                ours.vk_alpha_g1.to_vec(),
                ours.vk_beta_g2.to_vec(),
                ours.vk_gamma_g2.to_vec(),
                ours.vk_delta_g2.to_vec(),
                ours.vk_ic
                    .iter()
                    .map(|point| point.to_vec())
                    .collect::<Vec<_>>(),
            ),
            (
                usize::try_from(inputs).unwrap() - 1,
                le_to_be(le.get(0..64).unwrap(), false),
                le_to_be(le.get(64..192).unwrap(), true),
                le_to_be(le.get(192..320).unwrap(), true),
                le_to_be(le.get(320..448).unwrap(), true),
                expected_ic,
            )
        );
    }
}

#[test]
fn the_point_at_infinity_encodes_as_zeros_like_xark() {
    let key = VerifyingKey::<ark_bn254::Bn254> {
        alpha_g1: G1Affine::zero(),
        beta_g2: G2Affine::zero(),
        gamma_g2: g2(5),
        delta_g2: g2(7),
        gamma_abc_g1: vec![G1Affine::zero(), g1(9)],
    };
    let le = solana::assemble_vk_bytes_le(&key);
    let ours = SolanaVerifyingKey::from_xark(&compressed(&key)).unwrap();
    let ours = ours.as_key();
    assert_eq!(
        (
            ours.vk_alpha_g1,
            ours.vk_beta_g2.to_vec(),
            ours.vk_ic.first().copied()
        ),
        (
            [0u8; 64],
            le_to_be(le.get(64..192).unwrap(), true),
            Some([0u8; 64])
        )
    );
}

#[test]
fn malformed_and_trailing_bytes_are_rejected() {
    let proof = Proof::<ark_bn254::Bn254> {
        a: g1(1),
        b: g2(1),
        c: g1(1),
    };
    let mut bytes = compressed(&proof);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        compressed_proof(&trailing).map(|_| ()),
        Err("trailing proof bytes".to_string())
    );
    bytes.truncate(bytes.len() - 1);
    assert!(compressed_proof(&bytes)
        .unwrap_err()
        .starts_with("proof C: "));
    let key = VerifyingKey::<ark_bn254::Bn254> {
        alpha_g1: g1(2),
        beta_g2: g2(3),
        gamma_g2: g2(5),
        delta_g2: g2(7),
        gamma_abc_g1: vec![],
    };
    assert_eq!(
        SolanaVerifyingKey::from_xark(&compressed(&key)).map(|_| ()),
        Err("verifying key has no constant input".to_string())
    );
}
