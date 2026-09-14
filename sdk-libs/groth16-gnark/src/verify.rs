use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof as ArkProof, VerifyingKey as ArkVk};

use crate::{Proof, VerifyingKey};

/// Verifies a proof against the parsed gnark key. Public inputs exclude wire 0.
pub fn verify(vk: &VerifyingKey, proof: &Proof, public_inputs: &[Fr]) -> bool {
    let prepared = PreparedVerifyingKey::from(ArkVk::<Bn254> {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        gamma_abc_g1: vk.k.clone(),
    });
    let proof = ArkProof {
        a: proof.ar,
        b: proof.bs,
        c: proof.krs,
    };
    Groth16::<Bn254>::verify_proof(&prepared, &proof, public_inputs).unwrap_or(false)
}
