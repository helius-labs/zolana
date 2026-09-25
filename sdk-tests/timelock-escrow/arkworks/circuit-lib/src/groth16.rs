use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::{Groth16, ProvingKey};
use ark_std::rand::{CryptoRng, Rng};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};

use crate::{convert::be_bytes, ArkworksCircuit, Circuit, ProofInput, RelationError};

pub struct Groth16Keys {
    proving_key: ProvingKey<Bn254>,
    verifying_key: SolanaVerifyingKey,
}

impl Groth16Keys {
    pub fn verifying_key(&self) -> &SolanaVerifyingKey {
        &self.verifying_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaVerifyingKey {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

impl SolanaVerifyingKey {
    pub fn groth16_verifyingkey(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey {
            nr_pubinputs: self.ic.len().saturating_sub(1),
            vk_alpha_g1: self.alpha_g1,
            vk_beta_g2: self.beta_g2,
            vk_gamma_g2: self.gamma_g2,
            vk_delta_g2: self.delta_g2,
            vk_ic: &self.ic,
            vk_commitment: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

impl SolanaProof {
    pub fn verify(
        &self,
        verifying_key: &SolanaVerifyingKey,
        public_input_hash: [u8; 32],
    ) -> Result<(), RelationError> {
        let public_inputs = [public_input_hash];
        let verifying_key = verifying_key.groth16_verifyingkey();
        Groth16Verifier::new(&self.a, &self.b, &self.c, &public_inputs, &verifying_key)
            .and_then(|mut verifier| verifier.verify())
            .map_err(|_| RelationError::ProofRejected)
    }

    pub fn compress(&self) -> Result<CompressedProof, RelationError> {
        let invalid = |_| RelationError::InvalidProofPoint;
        Ok(CompressedProof {
            a: alt_bn128_g1_compress_be(&self.a).map_err(invalid)?,
            b: alt_bn128_g2_compress_be(&self.b).map_err(invalid)?,
            c: alt_bn128_g1_compress_be(&self.c).map_err(invalid)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl<P> ArkworksCircuit<P>
where
    P: ProofInput + Clone,
    P::Circuit: Circuit,
{
    pub fn setup(&self, rng: &mut (impl Rng + CryptoRng)) -> Result<Groth16Keys, RelationError> {
        let proving_key =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(self.clone(), rng)?;
        let vk = &proving_key.vk;
        let verifying_key = SolanaVerifyingKey {
            alpha_g1: g1_bytes(&vk.alpha_g1),
            beta_g2: g2_bytes(&vk.beta_g2),
            gamma_g2: g2_bytes(&vk.gamma_g2),
            delta_g2: g2_bytes(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1_bytes).collect(),
        };
        Ok(Groth16Keys {
            proving_key,
            verifying_key,
        })
    }

    pub fn prove(
        &self,
        keys: &Groth16Keys,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<SolanaProof, RelationError> {
        self.check_constraints()?;
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            self.clone(),
            &keys.proving_key,
            rng,
        )?;
        let negated_a: G1Affine = (-proof.a.into_group()).into();
        let proof = SolanaProof {
            a: g1_bytes(&negated_a),
            b: g2_bytes(&proof.b),
            c: g1_bytes(&proof.c),
        };
        proof.verify(&keys.verifying_key, self.public_hash_bytes())?;
        Ok(proof)
    }
}

fn g1_bytes(point: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        let (x_bytes, y_bytes) = bytes.split_at_mut(32);
        x_bytes.copy_from_slice(&be_bytes(&x));
        y_bytes.copy_from_slice(&be_bytes(&y));
    }
    bytes
}

fn g2_bytes(point: &G2Affine) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        for (chunk, coordinate) in bytes
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([x.c1, x.c0, y.c1, y.c0].iter())
        {
            *chunk = be_bytes(coordinate);
        }
    }
    bytes
}
