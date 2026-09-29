#[cfg(feature = "client")]
use core::marker::PhantomData;
#[cfg(any(feature = "setup", not(target_arch = "wasm32")))]
use std::path::Path;
#[cfg(feature = "client")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "client")]
use ark_bn254::Fr;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
#[cfg(feature = "client")]
use ark_std::{rand::rngs::OsRng, UniformRand};
use groth16_solana::groth16::Groth16Verifyingkey;

#[cfg(feature = "setup")]
pub use groth16_solana::vk::setup::SetupKind;

#[cfg(feature = "client")]
use super::{
    proof::create_proof,
    proof_inputs::ProofInputs,
    synthesis::{ArkworksCircuit, CircuitMatrices, CircuitShape},
    zkey::Zkey,
};
#[cfg(feature = "client")]
use crate::ZkProgram;
use crate::{conversion::be_bytes, ProverError, ProverErrorKind};

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

    pub fn proving_key(&self) -> &ProvingKey {
        &self.proving_key
    }

    #[cfg(feature = "client")]
    fn circuit_shape(&self) -> CircuitShape {
        CircuitShape {
            instance_variables: self.proving_key.vk.gamma_abc_g1.len(),
            witness_variables: self.proving_key.l_query.len(),
        }
    }

    #[cfg(feature = "setup")]
    pub fn save(&self, path: &Path) -> Result<(), ProverError> {
        use ark_serialize::CanonicalSerialize;

        let mut bytes = Vec::new();
        self.proving_key
            .serialize_uncompressed(&mut bytes)
            .map_err(ProverErrorKind::KeyEncoding)?;
        Ok(std::fs::write(path, bytes).map_err(|error| key_file(path, error))?)
    }

    #[cfg(feature = "client")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProverError> {
        use ark_serialize::CanonicalDeserialize;

        let proving_key =
            ProvingKey::deserialize_uncompressed(bytes).map_err(ProverErrorKind::KeyEncoding)?;
        Ok(Self::from(proving_key))
    }

    #[cfg(all(feature = "client", not(target_arch = "wasm32")))]
    pub fn load(path: &Path) -> Result<Self, ProverError> {
        Self::from_bytes(&std::fs::read(path).map_err(|error| key_file(path, error))?)
    }

    /// Writes the proving key in the memory-image format, the default format
    /// for saving and loading keys. Loading an image is two orders of
    /// magnitude faster than loading the canonical format because it skips
    /// curve validation, Montgomery conversion and parsing: each section is
    /// one memory copy. See `from_image_bytes` for the format.
    ///
    /// Always use this format; the canonical `save`/`load` pair exists only
    /// where circom/snarkjs compatibility is required.
    #[cfg(all(feature = "setup", target_endian = "little"))]
    pub fn save_image(&self, path: &Path) -> Result<(), ProverError> {
        Ok(std::fs::write(path, self.to_image_bytes()).map_err(|error| key_file(path, error))?)
    }

    /// The proving key in the memory-image format.
    #[cfg(all(feature = "setup", target_endian = "little"))]
    pub fn to_image_bytes(&self) -> Vec<u8> {
        key_image::write(&self.proving_key)
    }

    /// Reads a proving key in the memory-image format, the exact in-memory
    /// layout of the arkworks 0.6 BN254 points: Montgomery-form limbs, no
    /// flags, the point at infinity is the origin. Every bit pattern is a
    /// valid value of these types, so any bytes load; a corrupt image yields
    /// proofs that fail verification, never a panic or unsoundness.
    ///
    /// The format is specific to one target and one arkworks version. Use it
    /// as a local cache next to the canonical key, not for interchange, and
    /// only for bytes whose integrity is established the same way as the
    /// canonical key's (the proving-key lockfile's sha256): the loader runs
    /// no curve or subgroup checks.
    ///
    /// Always load keys with this (or `load_image`); the canonical
    /// `from_bytes`/`load` exists only where circom/snarkjs compatibility is
    /// required.
    #[cfg(all(feature = "client", target_endian = "little"))]
    pub fn from_image_bytes(bytes: &[u8]) -> Result<Self, ProverError> {
        Ok(Self::from(key_image::read(bytes)?))
    }

    /// Like `from_image_bytes`, but first verifies the bytes against their
    /// sha256, the digest the proving-key lockfile pins. Fails closed on a
    /// mismatch; on a match the bytes are authenticated, so skipping the
    /// curve checks costs nothing.
    #[cfg(all(feature = "client", target_endian = "little"))]
    pub fn from_image_checked(bytes: &[u8], checksum: &[u8; 32]) -> Result<Self, ProverError> {
        use sha2::{Digest, Sha256};

        if Sha256::digest(bytes).as_slice() != checksum {
            return Err(ProverErrorKind::KeyImageChecksumMismatch.into());
        }
        Self::from_image_bytes(bytes)
    }

    #[cfg(all(
        feature = "client",
        not(target_arch = "wasm32"),
        target_endian = "little"
    ))]
    pub fn load_image(path: &Path) -> Result<Self, ProverError> {
        Self::from_image_bytes(&std::fs::read(path).map_err(|error| key_file(path, error))?)
    }

    /// Like `load_image`, but first verifies the file against its sha256.
    /// See `from_image_checked`.
    #[cfg(all(
        feature = "client",
        not(target_arch = "wasm32"),
        target_endian = "little"
    ))]
    pub fn load_image_checked(path: &Path, checksum: &[u8; 32]) -> Result<Self, ProverError> {
        Self::from_image_checked(
            &std::fs::read(path).map_err(|error| key_file(path, error))?,
            checksum,
        )
    }

    /// Converts a proving key in the canonical format to the memory-image
    /// format, running the canonical key's curve validation once on the way
    /// in. Every later load of the image skips it.
    #[cfg(all(
        feature = "client",
        feature = "setup",
        not(target_arch = "wasm32"),
        target_endian = "little"
    ))]
    pub fn convert_to_image(canonical: &Path, image: &Path) -> Result<(), ProverError> {
        Self::load(canonical)?.save_image(image)
    }

    /// Converts a snarkjs zkey to the memory-image format, running the full
    /// zkey checks (the circuit's shape and A and B rows, the phase-2
    /// contribution, point validation) once on the way in.
    #[cfg(all(
        feature = "client",
        feature = "setup",
        not(target_arch = "wasm32"),
        target_endian = "little"
    ))]
    pub fn convert_zkey_to_image<P: ZkProgram>(
        zkey: &Path,
        image: &Path,
    ) -> Result<(), ProverError> {
        Self::load_zkey::<P>(zkey)?.save_image(image)
    }

    #[cfg(feature = "client")]
    pub fn from_zkey_bytes<P: ZkProgram>(bytes: &[u8]) -> Result<Self, ProverError> {
        Self::from_zkey_for(bytes, &circuit_matrices::<P>()?.clone())
    }

    #[cfg(all(feature = "client", not(target_arch = "wasm32")))]
    pub fn load_zkey<P: ZkProgram>(path: &Path) -> Result<Self, ProverError> {
        Self::from_zkey_bytes::<P>(&std::fs::read(path).map_err(|error| key_file(path, error))?)
    }

    #[cfg(feature = "client")]
    fn from_zkey_for(bytes: &[u8], matrices: &CircuitMatrices) -> Result<Self, ProverError> {
        let zkey = Zkey::read(bytes)?;
        zkey.check_circuit(matrices.matrices())?;
        Ok(Self::from(zkey.proving_key))
    }

    #[cfg(feature = "setup")]
    pub fn gnark_verifying_key(&self) -> Result<Vec<u8>, ProverError> {
        let vk = &self.proving_key.vk;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&g1_bytes(&vk.alpha_g1));
        bytes.extend_from_slice(&g1_bytes(&self.proving_key.beta_g1));
        bytes.extend_from_slice(&g2_bytes(&vk.beta_g2));
        bytes.extend_from_slice(&g2_bytes(&vk.gamma_g2));
        bytes.extend_from_slice(&g1_bytes(&self.proving_key.delta_g1));
        bytes.extend_from_slice(&g2_bytes(&vk.delta_g2));
        let ic_len = u32::try_from(vk.gamma_abc_g1.len()).map_err(|_| {
            ProverErrorKind::ExportTooLarge("the verifying key has too many points")
        })?;
        bytes.extend_from_slice(&ic_len.to_be_bytes());
        for point in &vk.gamma_abc_g1 {
            bytes.extend_from_slice(&g1_bytes(point));
        }
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        Ok(bytes)
    }

    #[cfg(feature = "setup")]
    pub fn export_verifying_key(&self, export: &VerifyingKeyExport<'_>) -> Result<(), ProverError> {
        use groth16_solana::vk::{gnark::generate_bsb22_vk_file, setup::ProvingKeySource};

        std::fs::create_dir_all(export.output_dir)
            .map_err(|error| key_file(export.output_dir, error))?;
        let raw = export
            .output_dir
            .join(format!(".{}.vk.bin", export.output_filename));
        std::fs::write(&raw, self.gnark_verifying_key()?).map_err(|error| key_file(&raw, error))?;
        let generated = generate_bsb22_vk_file(
            &raw,
            export.output_dir,
            export.output_filename,
            export.const_name,
            export.setup,
            ProvingKeySource::File(export.proving_key),
        )
        .map_err(ProverErrorKind::VerifyingKeyExport);
        let removed = std::fs::remove_file(&raw).map_err(|error| key_file(&raw, error));
        generated?;
        Ok(removed?)
    }
}

#[cfg(feature = "setup")]
pub struct VerifyingKeyExport<'a> {
    pub proving_key: &'a Path,
    pub output_dir: &'a Path,
    pub output_filename: &'a str,
    pub const_name: &'a str,
    pub setup: SetupKind,
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
    ) -> Result<(), ProverError> {
        use groth16_solana::groth16::Groth16Verifier;

        let public_inputs = [public_input_hash];
        let verifying_key = Groth16Verifyingkey::from(verifying_key);
        Ok(
            Groth16Verifier::new(&self.a, &self.b, &self.c, &public_inputs, &verifying_key)
                .and_then(|mut verifier| verifier.verify())
                .map_err(|_| ProverErrorKind::ProofRejected)?,
        )
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
    type Error = ProverError;

    fn try_from(proof: &SolanaProof) -> Result<Self, ProverError> {
        use solana_bn254::compression::prelude::{
            alt_bn128_g1_compress_be, alt_bn128_g2_compress_be,
        };

        let invalid = |_| ProverErrorKind::CorruptProof;
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
    ) -> Result<(), ProverError> {
        use solana_bn254::compression::prelude::{
            alt_bn128_g1_decompress_be, alt_bn128_g2_decompress_be,
        };

        let invalid = |_| ProverErrorKind::CorruptProof;
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
impl ProofResult {
    pub fn compressed(&self) -> Result<CompressedProof, ProverError> {
        CompressedProof::try_from(&self.proof)
    }
}

#[cfg(feature = "client")]
pub struct Groth16Prover<P> {
    keys: Groth16Keys,
    matrices: Arc<CircuitMatrices>,
    program: PhantomData<fn() -> P>,
}

#[cfg(feature = "client")]
impl<P: ZkProgram> Groth16Prover<P> {
    pub fn new(keys: Groth16Keys) -> Result<Self, ProverError> {
        Self::with_matrices(keys, circuit_matrices::<P>()?)
    }

    pub fn from_zkey_bytes(zkey: &[u8]) -> Result<Self, ProverError> {
        let matrices = circuit_matrices::<P>()?;
        let keys = Groth16Keys::from_zkey_for(zkey, &matrices)?;
        Self::with_matrices(keys, matrices)
    }

    fn with_matrices(
        keys: Groth16Keys,
        matrices: Arc<CircuitMatrices>,
    ) -> Result<Self, ProverError> {
        if matrices.shape() != keys.circuit_shape() {
            return Err(ProverErrorKind::KeysForAnotherCircuit.into());
        }
        Ok(Self {
            keys,
            matrices,
            program: PhantomData,
        })
    }

    #[cfg(feature = "setup")]
    pub fn new_with_test_setup() -> Result<Self, ProverError> {
        use ark_groth16::Groth16;
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        use super::reduction::CircomReduction;

        let placeholder = P::placeholder()?;
        let matrices = ArkworksCircuit::for_setup(&placeholder).matrices()?;
        let proving_key =
            Groth16::<Bn254, CircomReduction>::generate_random_parameters_with_reduction(
                ArkworksCircuit::for_setup(&placeholder),
                &mut StdRng::seed_from_u64(TEST_SETUP_SEED),
            )?;
        Ok(Self {
            keys: Groth16Keys::from(proving_key),
            matrices: Arc::new(matrices),
            program: PhantomData,
        })
    }

    pub fn keys(&self) -> &Groth16Keys {
        &self.keys
    }

    pub fn constraint_count(&self) -> usize {
        self.matrices.constraint_count()
    }

    pub fn prove(&self, proof_inputs: &P) -> Result<ProofResult, ProverError> {
        self.prove_inputs(&ArkworksCircuit::new(proof_inputs)?.proof_inputs()?)
    }

    pub fn prove_inputs(&self, proof_inputs: &ProofInputs) -> Result<ProofResult, ProverError> {
        let assignment = proof_inputs.values();
        self.matrices.check(assignment)?;
        let proof = SolanaProof::from(&create_proof(
            &self.keys.proving_key,
            Fr::rand(&mut OsRng),
            Fr::rand(&mut OsRng),
            self.matrices.matrices(),
            assignment,
        )?);
        let public_hash = proof_inputs.public_hash()?;
        proof.verify(&self.keys.verifying_key, public_hash)?;
        Ok(ProofResult { proof, public_hash })
    }

    pub fn verify(&self, result: &ProofResult) -> Result<(), ProverError> {
        CompressedProof::try_from(&result.proof)?
            .verify(&self.keys.verifying_key, result.public_hash)
    }
}

#[cfg(all(feature = "client", feature = "setup"))]
const TEST_SETUP_SEED: u64 = 0;

#[cfg(feature = "client")]
fn circuit_matrices<P: ZkProgram + 'static>() -> Result<Arc<CircuitMatrices>, ProverError> {
    use std::{any::TypeId, collections::HashMap, sync::OnceLock};

    // The matrices are deterministic per circuit, so synthesize them once
    // per process: constraint-system finalization is the load path's
    // dominant cost (~80 ms native, ~135 ms in the browser) and repeated
    // prover constructions of the same program get it for free.
    static CACHE: OnceLock<Mutex<HashMap<TypeId, Arc<CircuitMatrices>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = TypeId::of::<P>();
    if let Some(matrices) = cache.lock().expect("matrices cache poisoned").get(&key) {
        return Ok(Arc::clone(matrices));
    }
    let placeholder = P::placeholder()?;
    let matrices = Arc::new(ArkworksCircuit::for_setup(&placeholder).matrices()?);
    cache
        .lock()
        .expect("matrices cache poisoned")
        .insert(key, Arc::clone(&matrices));
    Ok(matrices)
}

#[cfg(any(feature = "setup", not(target_arch = "wasm32")))]
fn key_file(path: &Path, error: std::io::Error) -> ProverErrorKind {
    ProverErrorKind::KeyFile {
        path: path.to_path_buf(),
        error,
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

/// The memory-image proving-key format: the exact in-memory bytes of each
/// point vector behind a magic and `u64` section lengths. `G1Affine` is 64
/// bytes and `G2Affine` 128 (two coordinates of Montgomery-form limbs; the
/// BN254 zero flag is the unit type and the point at infinity is the
/// origin), so every bit pattern is a valid value and a section loads with
/// one copy. Little-endian targets only.
#[cfg(all(any(feature = "client", feature = "setup"), target_endian = "little"))]
mod key_image {
    use ark_bn254::{G1Affine, G2Affine};

    use super::{ProvingKey, VerifyingKey};
    use crate::{ProverError, ProverErrorKind};

    const MAGIC: &[u8; 8] = b"PKIMG001";

    #[cfg(feature = "setup")]
    fn bytes_of<T>(values: &[T]) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                values.as_ptr() as *const u8,
                core::mem::size_of_val(values),
            )
        }
    }

    #[cfg(feature = "setup")]
    pub fn write(key: &ProvingKey) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        for point in [&key.vk.alpha_g1, &key.beta_g1, &key.delta_g1] {
            out.extend_from_slice(bytes_of(core::slice::from_ref(point)));
        }
        for point in [&key.vk.beta_g2, &key.vk.gamma_g2, &key.vk.delta_g2] {
            out.extend_from_slice(bytes_of(core::slice::from_ref(point)));
        }
        for vector in [
            &key.vk.gamma_abc_g1,
            &key.a_query,
            &key.b_g1_query,
            &key.h_query,
        ] {
            out.extend_from_slice(&(vector.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes_of(vector.as_slice()));
        }
        out.extend_from_slice(&(key.b_g2_query.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes_of(key.b_g2_query.as_slice()));
        out.extend_from_slice(&(key.l_query.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes_of(key.l_query.as_slice()));
        out
    }

    struct Cursor<'a> {
        bytes: &'a [u8],
        offset: usize,
    }

    impl<'a> Cursor<'a> {
        fn take(&mut self, length: usize) -> Result<&'a [u8], ProverError> {
            let end = self
                .offset
                .checked_add(length)
                .filter(|end| *end <= self.bytes.len())
                .ok_or(ProverErrorKind::InvalidKeyImage("a section is truncated"))?;
            let slice = &self.bytes[self.offset..end];
            self.offset = end;
            Ok(slice)
        }

        fn section_len(&mut self) -> Result<usize, ProverError> {
            let bytes: [u8; 8] = self
                .take(8)?
                .try_into()
                .map_err(|_| ProverErrorKind::InvalidKeyImage("a length is truncated"))?;
            let length = u64::from_le_bytes(bytes);
            Ok(usize::try_from(length)
                .map_err(|_| ProverErrorKind::InvalidKeyImage("a section is too long"))?)
        }
    }

    /// Copies `length` values out of the cursor. Sound for the point types:
    /// they are plain limb arrays, so any bytes are a valid value.
    unsafe fn take_vec<T>(cursor: &mut Cursor, length: usize) -> Result<Vec<T>, ProverError> {
        let bytes = cursor.take(
            length
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(ProverErrorKind::InvalidKeyImage("a section is too long"))?,
        )?;
        let mut vector: Vec<T> = Vec::with_capacity(length);
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                vector.as_mut_ptr() as *mut u8,
                bytes.len(),
            );
            vector.set_len(length);
        }
        Ok(vector)
    }

    fn take_point<T>(cursor: &mut Cursor) -> Result<T, ProverError> {
        Ok(unsafe { take_vec::<T>(cursor, 1) }?.remove(0))
    }

    fn take_section<T>(cursor: &mut Cursor) -> Result<Vec<T>, ProverError> {
        let length = cursor.section_len()?;
        unsafe { take_vec(cursor, length) }
    }

    #[cfg(feature = "client")]
    pub fn read(bytes: &[u8]) -> Result<ProvingKey, ProverError> {
        let magic = bytes
            .get(..MAGIC.len())
            .ok_or(ProverErrorKind::InvalidKeyImage("the magic is truncated"))?;
        if magic != MAGIC {
            return Err(ProverErrorKind::InvalidKeyImage("bad magic").into());
        }
        let mut cursor = Cursor {
            bytes,
            offset: MAGIC.len(),
        };
        // The section order must match `write`: the G1 singles, the G2
        // singles, the G1 vectors, then the G2 vector and the L query.
        let alpha_g1 = take_point(&mut cursor)?;
        let beta_g1 = take_point(&mut cursor)?;
        let delta_g1 = take_point(&mut cursor)?;
        let beta_g2 = take_point(&mut cursor)?;
        let gamma_g2 = take_point(&mut cursor)?;
        let delta_g2 = take_point(&mut cursor)?;
        let key = ProvingKey {
            vk: VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1: take_section::<G1Affine>(&mut cursor)?,
            },
            beta_g1,
            delta_g1,
            a_query: take_section::<G1Affine>(&mut cursor)?,
            b_g1_query: take_section::<G1Affine>(&mut cursor)?,
            h_query: take_section::<G1Affine>(&mut cursor)?,
            b_g2_query: take_section::<G2Affine>(&mut cursor)?,
            l_query: take_section::<G1Affine>(&mut cursor)?,
        };
        if cursor.offset != bytes.len() {
            return Err(ProverErrorKind::InvalidKeyImage("trailing bytes").into());
        }
        Ok(key)
    }
}
