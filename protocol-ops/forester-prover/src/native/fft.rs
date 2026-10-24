//! External-memory quotient construction for the existing gnark Groth16 key.
//!
//! Scratch slots are 32-byte little-endian Montgomery BN254 scalars. The DIF
//! output order matches the bit-reversed G1.Z query in gnark's proving keys.
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInt, Field, PrimeField};

const SCALAR_BYTES: usize = 32;
const CHUNK_SCALARS: usize = 1 << 20;

/// Overwrite the padded A/B/C evaluation files with the quotient computation.
///
/// A becomes H in gnark's bit-reversed order. B and C contain their coset
/// evaluations afterward and may be removed by the caller. All three files
/// must be distinct, regular files containing exactly `domain_size` scalars.
pub(crate) fn compute_h(
    a_path: &Path,
    b_path: &Path,
    c_path: &Path,
    domain_size: u64,
    root: Fr,
    coset: Fr,
) -> Result<PathBuf> {
    compute_h_with_chunk_size(
        [a_path, b_path, c_path],
        domain_size,
        root,
        coset,
        CHUNK_SCALARS,
    )
}

fn compute_h_with_chunk_size(
    paths: [&Path; 3],
    domain_size: u64,
    root: Fr,
    coset: Fr,
    chunk_size: usize,
) -> Result<PathBuf> {
    let plan = FftPlan::new(domain_size, root, coset)?;
    ensure!(
        chunk_size.is_power_of_two(),
        "FFT chunk size must be a power of two"
    );
    let chunk_size = chunk_size.min(usize::try_from(domain_size)?);
    let files = [
        ScalarFile::open(paths[0], domain_size)?,
        ScalarFile::open(paths[1], domain_size)?,
        ScalarFile::open(paths[2], domain_size)?,
    ];
    for (index, file) in files.iter().enumerate() {
        ensure!(
            files
                .iter()
                .take(index)
                .all(|prior| prior.identity != file.identity),
            "A, B, and C scratch files must be distinct"
        );
    }
    let mut buffers = Buffers::new(chunk_size)?;
    for (index, file) in files.iter().enumerate() {
        eprintln!("native FFT: column {index} inverse/coset, {domain_size} scalars");
        plan.inverse_to_coset(file, &mut buffers)?;
        eprintln!("native FFT: column {index} forward/coset");
        plan.forward(file, &mut buffers)?;
    }
    eprintln!("native FFT: combining quotient evaluations");
    combine_coset_evaluations(&files, plan.quotient_denominator_inv, &mut buffers)?;
    eprintln!("native FFT: quotient inverse/coset");
    plan.inverse_from_coset(&files[0], &mut buffers)?;
    Ok(paths[0].to_path_buf())
}

struct FftPlan {
    size: u64,
    root: Fr,
    root_inv: Fr,
    quotient_denominator_inv: Fr,
    to_coset: CosetScale,
    from_coset: CosetScale,
}

impl FftPlan {
    fn new(size: u64, root: Fr, coset: Fr) -> Result<Self> {
        ensure!(
            size.is_power_of_two(),
            "FFT domain size must be a nonzero power of two"
        );
        ensure!(
            root.pow([size]) == Fr::ONE,
            "FFT root does not have the requested order"
        );
        ensure!(
            size == 1 || root.pow([size / 2]) != Fr::ONE,
            "FFT root is not primitive"
        );
        let root_inv = root.inverse().ok_or_else(|| anyhow!("FFT root is zero"))?;
        let coset_inv = coset
            .inverse()
            .ok_or_else(|| anyhow!("FFT coset is zero"))?;
        let quotient_denominator_inv = (coset.pow([size]) - Fr::ONE)
            .inverse()
            .ok_or_else(|| anyhow!("FFT coset intersects the constraint domain"))?;
        let size_inv = Fr::from(size)
            .inverse()
            .ok_or_else(|| anyhow!("FFT domain size is zero in the scalar field"))?;
        Ok(Self {
            size,
            root,
            root_inv,
            quotient_denominator_inv,
            to_coset: CosetScale::new(size, coset, size_inv)?,
            from_coset: CosetScale::new(size, coset_inv, size_inv)?,
        })
    }

    fn inverse_to_coset(&self, file: &ScalarFile, buffers: &mut Buffers) -> Result<()> {
        self.dif(file, self.root_inv, &self.to_coset, buffers)
    }

    fn inverse_from_coset(&self, file: &ScalarFile, buffers: &mut Buffers) -> Result<()> {
        self.dif(file, self.root_inv, &self.from_coset, buffers)
    }

    fn dif(
        &self,
        file: &ScalarFile,
        root: Fr,
        scale: &CosetScale,
        buffers: &mut Buffers,
    ) -> Result<()> {
        let chunk_size = buffers.left.len() as u64;
        let mut span = self.size;
        while span > chunk_size {
            let half = span / 2;
            let stage_root = root.pow([self.size / span]);
            let mut block = 0;
            while block < self.size {
                let mut offset = 0;
                while offset < half {
                    let count = usize::try_from(chunk_size.min(half - offset))?;
                    let left = buffers
                        .left
                        .get_mut(..count)
                        .context("left FFT chunk bounds")?;
                    let right = buffers
                        .right
                        .get_mut(..count)
                        .context("right FFT chunk bounds")?;
                    file.read(block + offset, left, &mut buffers.encoded)?;
                    file.read(block + half + offset, right, &mut buffers.encoded)?;
                    let mut twiddle = stage_root.pow([offset]);
                    for (first, second) in left.iter_mut().zip(right.iter_mut()) {
                        let difference = *first - *second;
                        *first += *second;
                        *second = difference * twiddle;
                        twiddle *= stage_root;
                    }
                    file.write(block + offset, left, &mut buffers.encoded)?;
                    file.write(block + half + offset, right, &mut buffers.encoded)?;
                    offset += count as u64;
                }
                block += span;
            }
            span /= 2;
        }
        let local_root = root.pow([self.size / chunk_size]);
        let mut block = 0;
        while block < self.size {
            file.read(block, &mut buffers.left, &mut buffers.encoded)?;
            dif_in_memory(&mut buffers.left, local_root)?;
            scale.apply(block, &mut buffers.left)?;
            file.write(block, &buffers.left, &mut buffers.encoded)?;
            block += chunk_size;
        }
        Ok(())
    }

    fn forward(&self, file: &ScalarFile, buffers: &mut Buffers) -> Result<()> {
        let chunk_size = buffers.left.len() as u64;
        let local_root = self.root.pow([self.size / chunk_size]);
        let mut block = 0;
        while block < self.size {
            file.read(block, &mut buffers.left, &mut buffers.encoded)?;
            dit_in_memory(&mut buffers.left, local_root)?;
            file.write(block, &buffers.left, &mut buffers.encoded)?;
            block += chunk_size;
        }
        let mut span = chunk_size.checked_mul(2).context("FFT span overflow")?;
        while span <= self.size {
            let half = span / 2;
            let stage_root = self.root.pow([self.size / span]);
            let mut block = 0;
            while block < self.size {
                let mut offset = 0;
                while offset < half {
                    let count = usize::try_from(chunk_size.min(half - offset))?;
                    let left = buffers
                        .left
                        .get_mut(..count)
                        .context("left FFT chunk bounds")?;
                    let right = buffers
                        .right
                        .get_mut(..count)
                        .context("right FFT chunk bounds")?;
                    file.read(block + offset, left, &mut buffers.encoded)?;
                    file.read(block + half + offset, right, &mut buffers.encoded)?;
                    let mut twiddle = stage_root.pow([offset]);
                    for (first, second) in left.iter_mut().zip(right.iter_mut()) {
                        let multiplied = *second * twiddle;
                        *second = *first - multiplied;
                        *first += multiplied;
                        twiddle *= stage_root;
                    }
                    file.write(block + offset, left, &mut buffers.encoded)?;
                    file.write(block + half + offset, right, &mut buffers.encoded)?;
                    offset += count as u64;
                }
                block += span;
            }
            span = span.checked_mul(2).context("FFT span overflow")?;
        }
        Ok(())
    }
}

/// Consecutive bit-reversed powers need only one multiplication per scalar.
/// Incrementing index i with t trailing ones changes rev(i) by
/// `3 * 2^(log_size - 1 - t) - size`; one ratio per t replaces a full coset table.
struct CosetScale {
    size: u64,
    log_size: u32,
    generator: Fr,
    normalization: Fr,
    increment_ratios: Vec<Fr>,
}

impl CosetScale {
    fn new(size: u64, generator: Fr, normalization: Fr) -> Result<Self> {
        let log_size = size.trailing_zeros();
        let inverse_cycle = generator
            .pow([size])
            .inverse()
            .context("zero coset cycle")?;
        let increment_ratios = (0..log_size)
            .map(|trailing| {
                let power = 3 * (1u64 << (log_size - 1 - trailing));
                generator.pow([power]) * inverse_cycle
            })
            .collect();
        Ok(Self {
            size,
            log_size,
            generator,
            normalization,
            increment_ratios,
        })
    }

    fn apply(&self, start: u64, scalars: &mut [Fr]) -> Result<()> {
        let initial_exponent = reverse_bits(start, self.log_size);
        let mut multiplier = self.generator.pow([initial_exponent]) * self.normalization;
        for (offset, scalar) in scalars.iter_mut().enumerate() {
            *scalar *= multiplier;
            let index = start + offset as u64;
            if index + 1 < self.size {
                multiplier *= self
                    .increment_ratios
                    .get(index.trailing_ones() as usize)
                    .context("bit-reversed coset increment bounds")?;
            }
        }
        Ok(())
    }
}

fn reverse_bits(index: u64, log_size: u32) -> u64 {
    if log_size == 0 {
        0
    } else {
        index.reverse_bits() >> (64 - log_size)
    }
}

fn dif_in_memory(scalars: &mut [Fr], root: Fr) -> Result<()> {
    ensure!(
        scalars.len().is_power_of_two(),
        "local DIF length must be a power of two"
    );
    let mut span = scalars.len();
    while span >= 2 {
        let half = span / 2;
        let stage_root = root.pow([(scalars.len() / span) as u64]);
        for block in scalars.chunks_exact_mut(span) {
            let (left, right) = block.split_at_mut(half);
            let mut twiddle = Fr::ONE;
            for (first, second) in left.iter_mut().zip(right.iter_mut()) {
                let difference = *first - *second;
                *first += *second;
                *second = difference * twiddle;
                twiddle *= stage_root;
            }
        }
        span /= 2;
    }
    Ok(())
}

fn dit_in_memory(scalars: &mut [Fr], root: Fr) -> Result<()> {
    ensure!(
        scalars.len().is_power_of_two(),
        "local DIT length must be a power of two"
    );
    let mut span = 2;
    while span <= scalars.len() {
        let half = span / 2;
        let stage_root = root.pow([(scalars.len() / span) as u64]);
        for block in scalars.chunks_exact_mut(span) {
            let (left, right) = block.split_at_mut(half);
            let mut twiddle = Fr::ONE;
            for (first, second) in left.iter_mut().zip(right.iter_mut()) {
                let multiplied = *second * twiddle;
                *second = *first - multiplied;
                *first += multiplied;
                twiddle *= stage_root;
            }
        }
        span = span.checked_mul(2).context("local FFT span overflow")?;
    }
    Ok(())
}

fn combine_coset_evaluations(
    files: &[ScalarFile; 3],
    denominator_inv: Fr,
    buffers: &mut Buffers,
) -> Result<()> {
    let mut third = vec![Fr::ZERO; buffers.left.len()];
    let mut offset = 0;
    while offset < files[0].scalars {
        files[0].read(offset, &mut buffers.left, &mut buffers.encoded)?;
        files[1].read(offset, &mut buffers.right, &mut buffers.encoded)?;
        files[2].read(offset, &mut third, &mut buffers.encoded)?;
        for ((first, second), third) in buffers.left.iter_mut().zip(&buffers.right).zip(&third) {
            *first = (*first * second - third) * denominator_inv;
        }
        files[0].write(offset, &buffers.left, &mut buffers.encoded)?;
        offset += buffers.left.len() as u64;
    }
    Ok(())
}

struct Buffers {
    left: Vec<Fr>,
    right: Vec<Fr>,
    encoded: Vec<u8>,
}

impl Buffers {
    fn new(chunk_size: usize) -> Result<Self> {
        Ok(Self {
            left: vec![Fr::ZERO; chunk_size],
            right: vec![Fr::ZERO; chunk_size],
            encoded: vec![
                0;
                chunk_size
                    .checked_mul(SCALAR_BYTES)
                    .context("FFT buffer size overflow")?
            ],
        })
    }
}

struct ScalarFile {
    file: File,
    scalars: u64,
    identity: (u64, u64),
}

impl ScalarFile {
    fn open(path: &Path, scalars: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open FFT scratch {}", path.display()))?;
        let metadata = file.metadata()?;
        let expected = scalars
            .checked_mul(SCALAR_BYTES as u64)
            .context("FFT scratch length overflow")?;
        ensure!(
            metadata.is_file() && metadata.len() == expected,
            "FFT scratch {} must contain exactly {expected} bytes",
            path.display()
        );
        Ok(Self {
            file,
            scalars,
            identity: (metadata.dev(), metadata.ino()),
        })
    }

    fn read(&self, offset: u64, scalars: &mut [Fr], encoded: &mut [u8]) -> Result<()> {
        let byte_count = scalars
            .len()
            .checked_mul(SCALAR_BYTES)
            .context("FFT read length overflow")?;
        let encoded = encoded
            .get_mut(..byte_count)
            .context("FFT read buffer bounds")?;
        let byte_offset = self.byte_offset(offset, scalars.len())?;
        self.file
            .read_exact_at(encoded, byte_offset)
            .context("read FFT scratch")?;
        for (scalar, bytes) in scalars
            .iter_mut()
            .zip(encoded.as_chunks::<SCALAR_BYTES>().0.iter())
        {
            let mut limbs = [0; 4];
            for (limb, bytes) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
                *limb = u64::from_le_bytes(*bytes);
            }
            let integer = BigInt(limbs);
            ensure!(
                integer < Fr::MODULUS,
                "FFT scratch contains a noncanonical Montgomery scalar"
            );
            *scalar = Fr::new_unchecked(integer);
        }
        Ok(())
    }

    fn write(&self, offset: u64, scalars: &[Fr], encoded: &mut [u8]) -> Result<()> {
        let byte_count = scalars
            .len()
            .checked_mul(SCALAR_BYTES)
            .context("FFT write length overflow")?;
        let encoded = encoded
            .get_mut(..byte_count)
            .context("FFT write buffer bounds")?;
        for (scalar, bytes) in scalars
            .iter()
            .zip(encoded.as_chunks_mut::<SCALAR_BYTES>().0.iter_mut())
        {
            for (limb, bytes) in scalar
                .0
                 .0
                .iter()
                .zip(bytes.as_chunks_mut::<8>().0.iter_mut())
            {
                bytes.copy_from_slice(&limb.to_le_bytes());
            }
        }
        self.file
            .write_all_at(encoded, self.byte_offset(offset, scalars.len())?)
            .context("write FFT scratch")
    }

    fn byte_offset(&self, offset: u64, count: usize) -> Result<u64> {
        let end = offset
            .checked_add(u64::try_from(count)?)
            .context("FFT scalar range overflow")?;
        ensure!(
            end <= self.scalars,
            "FFT scalar range exceeds scratch length"
        );
        offset
            .checked_mul(SCALAR_BYTES as u64)
            .context("FFT scalar offset overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    struct Scratch {
        directory: PathBuf,
        paths: [PathBuf; 3],
    }
    impl Scratch {
        fn new(evaluations: &[Vec<Fr>; 3]) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "forester-native-fft-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let paths = [
                directory.join("a"),
                directory.join("b"),
                directory.join("c"),
            ];
            for (path, scalars) in paths.iter().zip(evaluations) {
                let encoded = scalars
                    .iter()
                    .flat_map(|scalar| scalar.0 .0.iter().flat_map(|limb| limb.to_le_bytes()))
                    .collect::<Vec<_>>();
                fs::write(path, encoded).unwrap();
            }
            Self { directory, paths }
        }
        fn read_a(&self) -> Vec<Fr> {
            let encoded = fs::read(&self.paths[0]).unwrap();
            encoded
                .as_chunks::<32>()
                .0
                .iter()
                .map(|bytes| {
                    let mut limbs = [0; 4];
                    for (limb, bytes) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
                        *limb = u64::from_le_bytes(*bytes);
                    }
                    Fr::new_unchecked(BigInt(limbs))
                })
                .collect()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn evaluate(coefficients: &[Fr], argument: Fr) -> Fr {
        coefficients
            .iter()
            .rev()
            .fold(Fr::ZERO, |accumulator, coefficient| {
                accumulator * argument + coefficient
            })
    }

    #[test]
    fn quotient_matches_polynomial_identity_across_external_stage_boundaries() {
        for size in [1usize, 2, 4, 8, 16, 64, 128] {
            let domain = Radix2EvaluationDomain::<Fr>::new(size).unwrap();
            for root in [domain.group_gen, domain.group_gen.pow([3])] {
                let a = (0..size)
                    .map(|index| Fr::from((index as u64 * 17 + 3) % 101))
                    .collect::<Vec<_>>();
                let b = (0..size)
                    .map(|index| Fr::from((index as u64 * 31 + 7) % 103))
                    .collect::<Vec<_>>();
                let mut product = vec![Fr::ZERO; size * 2 - 1];
                for (first_index, first) in a.iter().enumerate() {
                    for (second_index, second) in b.iter().enumerate() {
                        product[first_index + second_index] += *first * second;
                    }
                }
                let mut c = vec![Fr::ZERO; size];
                let mut quotient = vec![Fr::ZERO; size];
                for (index, coefficient) in product.iter().enumerate() {
                    c[index % size] += coefficient;
                    if index >= size {
                        quotient[index - size] += coefficient;
                    }
                }
                let arguments = (0..size)
                    .map(|index| root.pow([index as u64]))
                    .collect::<Vec<_>>();
                let evaluations = [&a, &b, &c].map(|coefficients| {
                    arguments
                        .iter()
                        .map(|argument| evaluate(coefficients, *argument))
                        .collect::<Vec<_>>()
                });
                for chunk_size in [1usize, 2, 4, 8, 16, 64, 1 << 20] {
                    let scratch = Scratch::new(&evaluations);
                    let output = compute_h_with_chunk_size(
                        scratch.paths.each_ref().map(PathBuf::as_path),
                        size as u64,
                        root,
                        Fr::from(7),
                        chunk_size,
                    )
                    .unwrap();
                    assert_eq!(output, scratch.paths[0]);
                    let expected = (0..size)
                        .map(|index| {
                            quotient[reverse_bits(index as u64, size.trailing_zeros()) as usize]
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        scratch.read_a(),
                        expected,
                        "size={size}, chunk={chunk_size}"
                    );
                }
            }
        }
    }

    #[test]
    fn local_transforms_match_arkworks_natural_order() {
        for size in [1usize, 2, 4, 8, 16, 64, 128] {
            let domain = Radix2EvaluationDomain::<Fr>::new(size).unwrap();
            let scalars = (0..size)
                .map(|index| Fr::from(index as u64 * 71 + 5))
                .collect::<Vec<_>>();
            let natural_fft = domain.fft(&scalars);
            let mut bit_reversed = scalars.clone();
            dif_in_memory(&mut bit_reversed, domain.group_gen).unwrap();
            let expected = (0..size)
                .map(|index| {
                    natural_fft[reverse_bits(index as u64, size.trailing_zeros()) as usize]
                })
                .collect::<Vec<_>>();
            assert_eq!(bit_reversed, expected);
            dit_in_memory(&mut bit_reversed, domain.group_gen_inv).unwrap();
            for scalar in &mut bit_reversed {
                *scalar *= domain.size_inv;
            }
            assert_eq!(bit_reversed, scalars);
        }
    }

    #[test]
    fn bit_reversed_coset_scaling_matches_explicit_powers() {
        for size in [1u64, 2, 4, 8, 16, 64, 128] {
            let generator = Fr::from(7);
            let scale = CosetScale::new(size, generator, Fr::from(11)).unwrap();
            for start in 0..size {
                let count = usize::try_from((size - start).min(7)).unwrap();
                let mut scalars = vec![Fr::ONE; count];
                scale.apply(start, &mut scalars).unwrap();
                let expected = (start..start + count as u64)
                    .map(|index| {
                        generator.pow([reverse_bits(index, size.trailing_zeros())]) * Fr::from(11)
                    })
                    .collect::<Vec<_>>();
                assert_eq!(scalars, expected);
            }
        }
    }

    #[test]
    fn bad_domains_lengths_and_aliased_files_are_rejected() {
        let evaluations = [vec![Fr::ONE; 8], vec![Fr::ONE; 8], vec![Fr::ONE; 8]];
        let scratch = Scratch::new(&evaluations);
        let root = Radix2EvaluationDomain::<Fr>::new(8).unwrap().group_gen;
        for (size, root, coset) in [
            (0, root, Fr::from(7)),
            (3, root, Fr::from(7)),
            (8, Fr::ONE, Fr::from(7)),
            (8, root, Fr::ZERO),
            (8, root, Fr::ONE),
            (
                16,
                Radix2EvaluationDomain::<Fr>::new(16).unwrap().group_gen,
                Fr::from(7),
            ),
        ] {
            assert!(compute_h(
                &scratch.paths[0],
                &scratch.paths[1],
                &scratch.paths[2],
                size,
                root,
                coset
            )
            .is_err());
        }
        assert!(compute_h(
            &scratch.paths[0],
            &scratch.paths[0],
            &scratch.paths[2],
            8,
            root,
            Fr::from(7)
        )
        .is_err());
        let linked = scratch.directory.join("hard-link-a");
        fs::hard_link(&scratch.paths[0], &linked).unwrap();
        assert!(compute_h(
            &scratch.paths[0],
            &linked,
            &scratch.paths[2],
            8,
            root,
            Fr::from(7)
        )
        .is_err());
        assert_eq!(scratch.read_a(), evaluations[0]);
    }

    #[test]
    fn noncanonical_montgomery_slots_are_rejected() {
        let scratch = Scratch::new(&[vec![Fr::ONE; 8], vec![Fr::ONE; 8], vec![Fr::ONE; 8]]);
        fs::write(&scratch.paths[0], [0xff; 8 * 32]).unwrap();
        let root = Radix2EvaluationDomain::<Fr>::new(8).unwrap().group_gen;
        assert!(compute_h(
            &scratch.paths[0],
            &scratch.paths[1],
            &scratch.paths[2],
            8,
            root,
            Fr::from(7)
        )
        .unwrap_err()
        .to_string()
        .contains("noncanonical Montgomery"));
    }
}
