//! Fold-only CU: host trapdoor verifies the RLC; CU cells use the same
//! `msm_cost` / `pairing_cost` functions LiteSVM charges for those call sizes.

use std::fs;

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar};
use solana_bn254_groth16_batch::{
    groth16_batch_verify, Proof, RandomizerMode, ValidatedVerifyingKey, VerifyingKey, Version,
};
use zolana_batch_syscalls::{msm_cost, pairing_cost};

struct TrapdoorKey {
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,
    ic: Vec<Fr>,
}

fn g1_bytes(point: &G1Affine) -> PodG1Point {
    let mut out = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
        out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    }
    PodG1Point(out)
}
fn g2_bytes(point: &G2Affine) -> PodG2Point {
    let mut out = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
        out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
        out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
        out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
    }
    PodG2Point(out)
}
fn fr_bytes(scalar: &Fr) -> PodScalar {
    let mut out = [0u8; 32];
    out.copy_from_slice(&scalar.into_bigint().to_bytes_be());
    PodScalar(out)
}
fn g1(scalar: Fr) -> G1Affine {
    (G1Projective::generator() * scalar).into_affine()
}
fn g2(scalar: Fr) -> G2Affine {
    (G2Projective::generator() * scalar).into_affine()
}

fn make_vk(rng: &mut StdRng, num_inputs: usize) -> (TrapdoorKey, ValidatedVerifyingKey) {
    let key = TrapdoorKey {
        alpha: Fr::rand(rng),
        beta: Fr::rand(rng),
        gamma: Fr::rand(rng),
        delta: Fr::rand(rng),
        ic: (0..=num_inputs).map(|_| Fr::rand(rng)).collect(),
    };
    let vk = VerifyingKey {
        alpha_g1: g1_bytes(&g1(key.alpha)),
        beta_g2: g2_bytes(&g2(key.beta)),
        gamma_g2: g2_bytes(&g2(key.gamma)),
        delta_g2: g2_bytes(&g2(key.delta)),
        ic: key.ic.iter().map(|s| g1_bytes(&g1(*s))).collect(),
        pedersen: None,
    };
    (key, vk.trust().expect("trust"))
}

fn make_proof(rng: &mut StdRng, key: &TrapdoorKey, vk_index: u16, inputs: &[Fr]) -> Proof {
    let a = Fr::rand(rng);
    let b = Fr::rand(rng);
    let mut l = key.ic[0];
    for (x, ic) in inputs.iter().zip(key.ic.iter().skip(1)) {
        l += *x * *ic;
    }
    let c = (a * b - key.alpha * key.beta - l * key.gamma) * key.delta.inverse().unwrap();
    Proof {
        vk_index,
        a: g1_bytes(&g1(a)),
        b: g2_bytes(&g2(b)),
        c: g1_bytes(&g1(c)),
        commitment: None,
        public_inputs: inputs.iter().map(fr_bytes).collect(),
    }
}

/// Independent same-vk, 1 public input: n×(MSM1 + MSM2) + 3×MSM(n) + pairing(n+3).
fn fold_syscall_cu_same_vk_n(n: u64) -> u64 {
    let mut cu = 0u64;
    for _ in 0..n {
        cu = cu.saturating_add(msm_cost(1));
        cu = cu.saturating_add(msm_cost(2));
    }
    cu = cu.saturating_add(msm_cost(n));
    cu = cu.saturating_add(msm_cost(n));
    cu = cu.saturating_add(msm_cost(n));
    cu = cu.saturating_add(pairing_cost(n + 3));
    cu
}

#[test]
fn host_fold_trapdoor_and_syscall_cu() {
    let mut rng = StdRng::seed_from_u64(0xc0ffee);
    let (key, vk) = make_vk(&mut rng, 1);

    let mut report = String::from(
        "# Fold-only CU (agave prices × Independent same-vk layout)\n\n\
         Host trapdoor fold verifies for each N. Syscall CU uses the same \
         `msm_cost` / `pairing_cost` LiteSVM charges when the fold runs on SBF.\n\n\
         | N | Host fold | Syscall CU |\n| ---: | --- | ---: |\n",
    );

    for n in [1u64, 2, 4, 8, 16] {
        let mut proofs = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let x = Fr::rand(&mut rng);
            proofs.push(make_proof(&mut rng, &key, 0, &[x]));
        }
        let ok = groth16_batch_verify(
            Version::V0,
            std::slice::from_ref(&vk),
            &proofs,
            RandomizerMode::Independent,
        )
        .expect("fold");
        assert!(ok, "N={n}");
        let cu = fold_syscall_cu_same_vk_n(n);
        report.push_str(&format!("| {n} | ok | {cu} |\n"));
        println!("N={n} ok cu={cu}");
    }

    let n2 = fold_syscall_cu_same_vk_n(2);
    let solo2 = 2 * (pairing_cost(4) + msm_cost(2) + msm_cost(1));
    report.push_str(&format!(
        "\n## vs solo ×2 (rough IC+pairing only)\n\n\
         Solo×2 ≈ {solo2}; batch N=2 = {n2}; delta ≈ {}\n",
        solo2 as i64 - n2 as i64
    ));

    // Keep dual full-path history in BATCH_CU_RESULTS.md; fold-only is separate.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/FOLD_CU.md");
    fs::write(path, &report).expect("write");
    println!("{report}");
}
