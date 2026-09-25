#[cfg(feature = "client")]
use core::marker::PhantomData;
use std::path::Path;

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
#[cfg(feature = "client")]
use ark_groth16::Groth16;
#[cfg(feature = "client")]
use ark_std::rand::rngs::OsRng;
use groth16_solana::groth16::Groth16Verifyingkey;

#[cfg(feature = "client")]
use super::synthesis::{ArkworksCircuit, CircuitShape};
#[cfg(feature = "client")]
use crate::ZkProgram;
use crate::{conversion::be_bytes, RelationError};

pub type ProvingKey = ark_groth16::ProvingKey<Bn254>;
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;
pub type Proof = ark_groth16::Proof<Bn254>;

pub struct Groth16Keys {
    proving_key: ProvingKey,
    verifying_key: SolanaVerifyingKey,
}

impl From<ProvingKey> for Groth16Keys {
    fn from(proving_key: ProvingKey) -> Self {
        Self {
            verifying_key: SolanaVerifyingKey::from(&proving_key.vk),
            proving_key,
        }
    }
}

impl Groth16Keys {
    pub fn verifying_key(&self) -> &SolanaVerifyingKey {
        &self.verifying_key
    }

    #[cfg(feature = "client")]
    fn circuit_shape(&self) -> CircuitShape {
        CircuitShape {
            instance_variables: self.proving_key.vk.gamma_abc_g1.len(),
            witness_variables: self.proving_key.l_query.len(),
        }
    }

    #[cfg(feature = "setup")]
    pub fn save(&self, path: &Path) -> Result<(), RelationError> {
        use ark_serialize::CanonicalSerialize;

        let mut bytes = Vec::new();
        self.proving_key
            .serialize_uncompressed(&mut bytes)
            .map_err(RelationError::keys)?;
        std::fs::write(path, bytes).map_err(RelationError::keys)
    }

    #[cfg(feature = "client")]
    pub fn load(path: &Path) -> Result<Self, RelationError> {
        use ark_serialize::CanonicalDeserialize;

        let bytes = std::fs::read(path).map_err(RelationError::keys)?;
        let proving_key =
            ProvingKey::deserialize_uncompressed(bytes.as_slice()).map_err(RelationError::keys)?;
        Ok(Self::from(proving_key))
    }

    #[cfg(feature = "setup")]
    pub fn gnark_verifying_key(&self) -> Result<Vec<u8>, RelationError> {
        let vk = &self.proving_key.vk;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&g1_bytes(&vk.alpha_g1));
        bytes.extend_from_slice(&g1_bytes(&self.proving_key.beta_g1));
        bytes.extend_from_slice(&g2_bytes(&vk.beta_g2));
        bytes.extend_from_slice(&g2_bytes(&vk.gamma_g2));
        bytes.extend_from_slice(&g1_bytes(&self.proving_key.delta_g1));
        bytes.extend_from_slice(&g2_bytes(&vk.delta_g2));
        let ic_len = u32::try_from(vk.gamma_abc_g1.len())
            .map_err(|_| RelationError::Conversion("the verifying key has too many points"))?;
        bytes.extend_from_slice(&ic_len.to_be_bytes());
        for point in &vk.gamma_abc_g1 {
            bytes.extend_from_slice(&g1_bytes(point));
        }
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        Ok(bytes)
    }

    #[cfg(feature = "setup")]
    pub fn export_verifying_key(
        &self,
        export: &VerifyingKeyExport<'_>,
    ) -> Result<(), RelationError> {
        use groth16_solana::vk::{
            gnark::generate_bsb22_vk_file,
            setup::{ProvingKeySource, SetupKind},
        };

        std::fs::create_dir_all(export.output_dir).map_err(RelationError::keys)?;
        let raw = export
            .output_dir
            .join(format!(".{}.vk.bin", export.output_filename));
        std::fs::write(&raw, self.gnark_verifying_key()?).map_err(RelationError::keys)?;
        let generated = generate_bsb22_vk_file(
            &raw,
            export.output_dir,
            export.output_filename,
            export.const_name,
            SetupKind::InsecureTest,
            ProvingKeySource::File(export.proving_key),
        )
        .map_err(|error| RelationError::keys(format!("{error:?}")));
        std::fs::remove_file(&raw).map_err(RelationError::keys)?;
        generated
    }
}

#[cfg(feature = "setup")]
pub struct VerifyingKeyExport<'a> {
    pub proving_key: &'a Path,
    pub output_dir: &'a Path,
    pub output_filename: &'a str,
    pub const_name: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaVerifyingKey {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

impl From<&VerifyingKey> for SolanaVerifyingKey {
    fn from(vk: &VerifyingKey) -> Self {
        Self {
            alpha_g1: g1_bytes(&vk.alpha_g1),
            beta_g2: g2_bytes(&vk.beta_g2),
            gamma_g2: g2_bytes(&vk.gamma_g2),
            delta_g2: g2_bytes(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1_bytes).collect(),
        }
    }
}

impl<'a> From<&'a SolanaVerifyingKey> for Groth16Verifyingkey<'a> {
    fn from(verifying_key: &'a SolanaVerifyingKey) -> Self {
        Self {
            nr_pubinputs: verifying_key.ic.len().saturating_sub(1),
            vk_alpha_g1: verifying_key.alpha_g1,
            vk_beta_g2: verifying_key.beta_g2,
            vk_gamma_g2: verifying_key.gamma_g2,
            vk_delta_g2: verifying_key.delta_g2,
            vk_ic: &verifying_key.ic,
            vk_commitment: None,
        }
    }
}

#[cfg(feature = "client")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

#[cfg(feature = "client")]
impl From<&Proof> for SolanaProof {
    fn from(proof: &Proof) -> Self {
        let negated_a: G1Affine = (-proof.a.into_group()).into();
        Self {
            a: g1_bytes(&negated_a),
            b: g2_bytes(&proof.b),
            c: g1_bytes(&proof.c),
        }
    }
}

#[cfg(feature = "client")]
impl SolanaProof {
    pub fn verify(
        &self,
        verifying_key: &SolanaVerifyingKey,
        public_input_hash: [u8; 32],
    ) -> Result<(), RelationError> {
        use groth16_solana::groth16::Groth16Verifier;

        let public_inputs = [public_input_hash];
        let verifying_key = Groth16Verifyingkey::from(verifying_key);
        Groth16Verifier::new(&self.a, &self.b, &self.c, &public_inputs, &verifying_key)
            .and_then(|mut verifier| verifier.verify())
            .map_err(|_| RelationError::ProofRejected)
    }
}

#[cfg(feature = "client")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

#[cfg(feature = "client")]
impl TryFrom<&SolanaProof> for CompressedProof {
    type Error = RelationError;

    fn try_from(proof: &SolanaProof) -> Result<Self, RelationError> {
        use solana_bn254::compression::prelude::{
            alt_bn128_g1_compress_be, alt_bn128_g2_compress_be,
        };

        let invalid = |_| RelationError::InvalidProofPoint;
        Ok(Self {
            a: alt_bn128_g1_compress_be(&proof.a).map_err(invalid)?,
            b: alt_bn128_g2_compress_be(&proof.b).map_err(invalid)?,
            c: alt_bn128_g1_compress_be(&proof.c).map_err(invalid)?,
        })
    }
}

#[cfg(feature = "client")]
impl CompressedProof {
    pub fn verify(
        &self,
        verifying_key: &SolanaVerifyingKey,
        public_hash: [u8; 32],
    ) -> Result<(), RelationError> {
        use solana_bn254::compression::prelude::{
            alt_bn128_g1_decompress_be, alt_bn128_g2_decompress_be,
        };

        let invalid = |_| RelationError::InvalidProofPoint;
        SolanaProof {
            a: alt_bn128_g1_decompress_be(&self.a).map_err(invalid)?,
            b: alt_bn128_g2_decompress_be(&self.b).map_err(invalid)?,
            c: alt_bn128_g1_decompress_be(&self.c).map_err(invalid)?,
        }
        .verify(verifying_key, public_hash)
    }
}

#[cfg(feature = "client")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofResult {
    pub proof: SolanaProof,
    pub public_hash: [u8; 32],
}

#[cfg(feature = "client")]
pub struct Groth16Prover<P> {
    keys: Groth16Keys,
    program: PhantomData<fn() -> P>,
}

#[cfg(feature = "client")]
impl<P: ZkProgram> Groth16Prover<P> {
    pub fn new(keys: Groth16Keys) -> Result<Self, RelationError> {
        let placeholder = P::placeholder()?;
        if ArkworksCircuit::for_setup(&placeholder).shape()? != keys.circuit_shape() {
            return Err(RelationError::KeysForAnotherCircuit);
        }
        Ok(Self {
            keys,
            program: PhantomData,
        })
    }

    #[cfg(feature = "setup")]
    pub fn new_with_test_setup() -> Result<Self, RelationError> {
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        let placeholder = P::placeholder()?;
        let proving_key = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            ArkworksCircuit::for_setup(&placeholder),
            &mut StdRng::seed_from_u64(TEST_SETUP_SEED),
        )?;
        Ok(Self {
            keys: Groth16Keys::from(proving_key),
            program: PhantomData,
        })
    }

    pub fn keys(&self) -> &Groth16Keys {
        &self.keys
    }

    pub fn constraint_count(&self) -> Result<usize, RelationError> {
        let placeholder = P::placeholder()?;
        ArkworksCircuit::for_setup(&placeholder).constraint_count()
    }

    pub fn prove(&self, proof_inputs: &P) -> Result<ProofResult, RelationError> {
        let circuit = ArkworksCircuit::new(proof_inputs)?;
        circuit.check_constraints()?;
        let proof = SolanaProof::from(&Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit,
            &self.keys.proving_key,
            &mut OsRng,
        )?);
        let public_hash = circuit.public_hash_bytes();
        proof.verify(&self.keys.verifying_key, public_hash)?;
        Ok(ProofResult { proof, public_hash })
    }

    pub fn verify(&self, result: &ProofResult) -> Result<(), RelationError> {
        CompressedProof::try_from(&result.proof)?
            .verify(&self.keys.verifying_key, result.public_hash)
    }
}

#[cfg(all(feature = "client", feature = "setup"))]
const TEST_SETUP_SEED: u64 = 0;

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
