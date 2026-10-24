//! Native Groth16 proving with bounded buffers and disk-backed intermediate values.
//! The original gnark key supplies the queries, domain and compiled constraint system.
mod fft;
mod key;
mod msm;
mod witness;

use anyhow::{bail, Context, Result};
use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, One, PrimeField, UniformRand, Zero};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::{key::ExpectedProvingKey, BatchAddressAppendInputs, Proof};
use key::KeyLayout;

struct PreparedKey {
    file: File,
    layout: KeyLayout,
}

pub(crate) struct LocalProver {
    keys: PathBuf,
    scratch: PathBuf,
    prepared: Mutex<BTreeMap<String, Arc<PreparedKey>>>,
    execution: Mutex<()>,
}
impl LocalProver {
    pub fn new(keys: PathBuf, scratch: PathBuf) -> Self {
        Self {
            keys,
            scratch,
            prepared: Mutex::new(BTreeMap::new()),
            execution: Mutex::new(()),
        }
    }
    fn prepare(&self, key: &ExpectedProvingKey) -> Result<Arc<PreparedKey>> {
        let mut prepared = self
            .prepared
            .lock()
            .map_err(|_| anyhow::anyhow!("proving-key cache is poisoned"))?;
        if let Some(key) = prepared.get(&key.name) {
            return Ok(Arc::clone(key));
        }
        let path = self.keys.join(&key.name);
        let file = File::open(&path)
            .with_context(|| format!("open pinned proving key {}", path.display()))?;
        eprintln!("native: verifying SHA-256 of {}", path.display());
        let mut reader = BufReader::with_capacity(8 << 20, &file);
        let mut block = vec![0; 8 << 20];
        let mut digest = Sha256::new();
        loop {
            let count = reader.read(&mut block)?;
            if count == 0 {
                break;
            }
            digest.update(&block[..count]);
        }
        let actual: [u8; 32] = digest.finalize().into();
        if actual != key.sha256 {
            bail!(
                "proving key {} does not match its checked-in verifier",
                path.display()
            );
        }
        drop(reader);
        drop(block);
        let mut metadata_reader = file.try_clone()?;
        metadata_reader.seek(SeekFrom::Start(0))?;
        let layout = KeyLayout::read_from(&mut metadata_reader)?;
        let prepared_key = Arc::new(PreparedKey { file, layout });
        prepared.insert(key.name.clone(), Arc::clone(&prepared_key));
        Ok(prepared_key)
    }
    pub fn prove(
        &self,
        key: &ExpectedProvingKey,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof> {
        // One local job at a time also bounds the process's aggregate scratch and RAM.
        let permit = self
            .execution
            .lock()
            .map_err(|_| anyhow::anyhow!("native proof gate is poisoned"))?;
        let prepared = self.prepare(key)?;
        fs::create_dir_all(&self.scratch)?;
        let needed = witness::scratch_bytes(
            &prepared.file,
            prepared.layout.cs_offset,
            u64::try_from(prepared.layout.domain_size)?,
        )?;
        let available = fs2::available_space(&self.scratch)?;
        let reserve = 4u64 << 30;
        eprintln!("native: scratch estimate {needed} bytes; {available} bytes available");
        if available
            < needed
                .checked_add(reserve)
                .context("scratch reserve overflow")?
        {
            bail!("insufficient scratch space: need {needed} bytes plus {reserve} bytes reserve, have {available}");
        }
        let mut nonce = [0; 8];
        OsRng.fill_bytes(&mut nonce);
        let scratch = self.scratch.join(format!(
            "batch-{}-{}-{}",
            inputs.batch_size,
            std::process::id(),
            hex::encode(nonce)
        ));
        fs::create_dir(&scratch)?;
        eprintln!("native: scratch {}", scratch.display());
        let attempt = prove(&prepared.file, &prepared.layout, inputs, &scratch);
        let cleanup = fs::remove_dir_all(&scratch)
            .with_context(|| format!("remove proof scratch {}", scratch.display()));
        drop(permit);
        match (attempt, cleanup) {
            (Ok(proof), Ok(())) => Ok(proof),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(failure), Ok(())) => Err(failure),
            (Err(failure), Err(cleanup)) => {
                Err(failure.context(format!("scratch cleanup also failed: {cleanup:#}")))
            }
        }
    }
}

fn field(value: &num_bigint::BigUint) -> Result<Fr> {
    let digits = value.to_u64_digits();
    if digits.len() > 4 {
        bail!("proof input exceeds BN254 scalar width");
    }
    let mut limbs = [0u64; 4];
    for (limb, digit) in limbs.iter_mut().zip(digits) {
        *limb = digit;
    }
    Fr::from_bigint(BigInt(limbs)).context("proof input is not a canonical BN254 scalar")
}
fn flatten(inputs: &BatchAddressAppendInputs) -> Result<Vec<Fr>> {
    let size = usize::try_from(inputs.batch_size)?;
    let height = usize::try_from(inputs.tree_height)?;
    for values in [
        &inputs.low_element_values,
        &inputs.low_element_next_values,
        &inputs.low_element_indices,
        &inputs.new_element_values,
    ] {
        if values.len() != size {
            bail!("batch vector does not match batch size");
        }
    }
    for proofs in [&inputs.low_element_proofs, &inputs.new_element_proofs] {
        if proofs.len() != size || proofs.iter().any(|path| path.len() != height) {
            bail!("batch proof paths do not match key shape");
        }
    }
    let mut flat = Vec::with_capacity(6 + size * (4 + 2 * height));
    flat.push(Fr::one());
    for value in [
        &inputs.public_input_hash,
        &inputs.old_root,
        &inputs.new_root,
        &inputs.hashchain_hash,
    ] {
        flat.push(field(value)?);
    }
    flat.push(Fr::from(inputs.start_index));
    // Declaration order of BatchAddressTreeAppendCircuit is the key's input order.
    for values in [
        &inputs.low_element_values,
        &inputs.low_element_next_values,
        &inputs.low_element_indices,
    ] {
        for value in values {
            flat.push(field(value)?);
        }
    }
    for path in &inputs.low_element_proofs {
        for value in path {
            flat.push(field(value)?);
        }
    }
    for value in &inputs.new_element_values {
        flat.push(field(value)?);
    }
    for path in &inputs.new_element_proofs {
        for value in path {
            flat.push(field(value)?);
        }
    }
    Ok(flat)
}
fn prove(
    file: &File,
    layout: &KeyLayout,
    inputs: &BatchAddressAppendInputs,
    scratch: &Path,
) -> Result<Proof> {
    if layout.height != inputs.tree_height || layout.batch_size != inputs.batch_size {
        bail!("proving key shape does not match batch inputs");
    }
    let flat = flatten(inputs)?;
    eprintln!(
        "native: solving {}-element batch (domain {})",
        layout.batch_size, layout.domain_size
    );
    let solution = witness::solve(file, layout.cs_offset, &flat, scratch)?;
    if u64::try_from(solution.wire_count)? != layout.wire_count
        || u64::try_from(solution.public_count)? != layout.public_count
    {
        bail!("solved wire layout does not match proving key");
    }
    let selected = |offset| msm::Scalars {
        first: 0,
        count: layout.wire_count,
        infinity_offset: Some(offset),
    };
    eprintln!("native: witness solved; streaming key MSMs");
    let a = msm::g1(
        file,
        layout.a,
        &solution.wires_path,
        selected(layout.infinity_a_offset),
        "A",
    )?;
    let b = msm::g1(
        file,
        layout.b,
        &solution.wires_path,
        selected(layout.infinity_b_offset),
        "B1",
    )?;
    let k = msm::g1(
        file,
        layout.k,
        &solution.wires_path,
        msm::Scalars {
            first: layout.public_count,
            count: layout.wire_count - layout.public_count,
            infinity_offset: None,
        },
        "K",
    )?;
    let b2 = msm::g2(
        file,
        layout.b2,
        &solution.wires_path,
        selected(layout.infinity_b_offset),
        "B2",
    )?;
    fs::remove_file(&solution.wires_path)?;
    let domain = u64::try_from(layout.domain_size)?;
    let bytes = domain
        .checked_mul(32)
        .context("FFT scratch length overflow")?;
    if u64::try_from(solution.constraint_count)? > domain {
        bail!("constraints exceed proving-key domain");
    }
    for path in [&solution.a_path, &solution.b_path, &solution.c_path] {
        File::options().write(true).open(path)?.set_len(bytes)?;
    }
    eprintln!("native: computing quotient with bounded-memory FFTs");
    let h = fft::compute_h(
        &solution.a_path,
        &solution.b_path,
        &solution.c_path,
        domain,
        layout.root,
        layout.coset,
    )?;
    for path in [&solution.b_path, &solution.c_path] {
        if *path != h {
            fs::remove_file(path)?;
        }
    }
    let z = msm::g1(
        file,
        layout.z,
        &h,
        msm::Scalars {
            first: 0,
            count: domain - 1,
            infinity_offset: None,
        },
        "Z",
    )?;
    fs::remove_file(h)?;
    // Fresh OS randomness blinds every proof, including proofs of public tree data.
    let r = Fr::rand(&mut OsRng);
    let s = Fr::rand(&mut OsRng);
    let delta = layout.delta.into_group();
    let ar = (a + layout.alpha.into_group() + delta * r).into_affine();
    let bs1 = b + layout.beta.into_group() + delta * s;
    let bs = (b2 + layout.beta2.into_group() + layout.delta2.into_group() * s).into_affine();
    let krs = (k + z - delta * (r * s) + ar.into_group() * s + bs1 * r).into_affine();
    let mut public_point = G1Projective::zero();
    if layout.vk.ic.len() != usize::try_from(layout.public_count)? {
        bail!("verifying key input count mismatch");
    }
    for (point, scalar) in layout.vk.ic.iter().zip(flat.iter()) {
        public_point += point.mul_bigint(scalar.into_bigint());
    }
    let pairing = Bn254::multi_pairing(
        [ar, -layout.alpha, -public_point.into_affine(), -krs],
        [bs, layout.beta2, layout.vk.gamma2, layout.delta2],
    );
    if !pairing.is_zero() {
        bail!("native Rust proof failed its original verifying key");
    }
    eprintln!("native: original verifying key accepted proof");
    Ok(Proof {
        a: g1_bytes(-ar),
        b: g2_bytes(bs),
        c: g1_bytes(krs),
    })
}
fn fq_bytes(value: Fq) -> [u8; 32] {
    let encoded = value.into_bigint().to_bytes_be();
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    bytes
}
fn g1_bytes(point: G1Affine) -> [u8; 64] {
    if point.is_zero() {
        return [0; 64];
    }
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&fq_bytes(point.x));
    bytes[32..].copy_from_slice(&fq_bytes(point.y));
    bytes
}
fn g2_bytes(point: G2Affine) -> [u8; 128] {
    if point.is_zero() {
        return [0; 128];
    }
    let mut bytes = [0; 128];
    for (output, coordinate) in bytes
        .as_chunks_mut::<32>()
        .0
        .iter_mut()
        .zip([point.x.c1, point.x.c0, point.y.c1, point.y.c0])
    {
        output.copy_from_slice(&fq_bytes(coordinate));
    }
    bytes
}
