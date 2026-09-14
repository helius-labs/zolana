use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, Zero};
use serde_json::json;

use crate::Proof;

fn hex(value: Fq) -> String {
    format!(
        "0x{}",
        value
            .into_bigint()
            .to_bytes_be()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn g1(point: &G1Affine) -> serde_json::Value {
    let (x, y) = point.xy().unwrap_or((Fq::zero(), Fq::zero()));
    json!([hex(x), hex(y)])
}

fn g2(point: &G2Affine) -> serde_json::Value {
    match point.xy() {
        Some((x, y)) => json!([[hex(x.c1), hex(x.c0)], [hex(y.c1), hex(y.c0)]]),
        None => json!([
            [hex(Fq::zero()), hex(Fq::zero())],
            [hex(Fq::zero()), hex(Fq::zero())]
        ]),
    }
}

/// Encodes a proof exactly like the Zolana prover's `POST /prove` response.
pub fn proof_json(proof: &Proof) -> String {
    json!({ "ar": g1(&proof.ar), "bs": g2(&proof.bs), "krs": g1(&proof.krs) }).to_string()
}
