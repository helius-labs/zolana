//! Benchmark of proving-key load strategies.
//!
//! Variants, all loading the same arkworks Groth16 proving key:
//!   read            -- fs::read only (I/O floor)
//!   validated       -- current Groth16Keys::load: canonical + curve/subgroup checks
//!   unchecked       -- canonical, no validation
//!   unchecked-par   -- canonical, no validation, rayon per-point
//!   compressed      -- canonical compressed, validated
//!   image           -- SDK memory-image format (Groth16Keys::load_image)
//!   image-mmap      -- SDK memory-image format over an mmap
//!
//! Every key-loading variant is verified by re-serializing to canonical
//! uncompressed and comparing against the original file bytes.
//!
//! Run: cargo run -p key-load-bench --release

use std::{
    fs::File,
    path::PathBuf,
    time::{Duration, Instant},
};

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use memmap2::Mmap;
use rayon::prelude::*;
use timelock_escrow_program::circuits::{Escrow, Withdraw};
use zolana_program::{Groth16Keys, Groth16Prover, ZkProgram};

type Pk = ProvingKey<Bn254>;

const G1_SIZE: usize = 64;
const G2_SIZE: usize = 128;

fn bench_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/pk-bench");
    std::fs::create_dir_all(&dir).expect("bench dir");
    dir
}

fn key_paths(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = bench_dir();
    (
        dir.join(format!("{name}.pk")),
        dir.join(format!("{name}.pkc")),
        dir.join(format!("{name}.pki")),
    )
}

fn ensure_keys<P: ZkProgram>(name: &str) {
    let (canonical, compressed, image) = key_paths(name);
    if canonical.exists() && compressed.exists() && image.exists() {
        return;
    }
    println!("setting up {name} keys (one-time)...");
    let start = Instant::now();
    let prover = Groth16Prover::<P>::new_with_test_setup().expect("test setup");
    println!("  setup took {:?}", start.elapsed());
    let keys = prover.keys();
    let pk = keys.proving_key();

    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes).expect("serialize");
    std::fs::write(&canonical, bytes).expect("write canonical");

    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .expect("serialize compressed");
    std::fs::write(&compressed, bytes).expect("write compressed");

    keys.save_image(&image).expect("write image");
}

// ---------------------------------------------------------------------------
// canonical parallel unchecked
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        slice
    }

    fn section_len(&mut self) -> usize {
        u64::from_le_bytes(self.take(8).try_into().unwrap()) as usize
    }
}

fn par_g1(bytes: &[u8]) -> Vec<G1Affine> {
    bytes
        .par_chunks(G1_SIZE)
        .map(|c| G1Affine::deserialize_uncompressed_unchecked(c).expect("g1"))
        .collect()
}

fn par_g2(bytes: &[u8]) -> Vec<G2Affine> {
    bytes
        .par_chunks(G2_SIZE)
        .map(|c| G2Affine::deserialize_uncompressed_unchecked(c).expect("g2"))
        .collect()
}

fn par_vec_g1(cursor: &mut Cursor) -> Vec<G1Affine> {
    let len = cursor.section_len();
    par_g1(cursor.take(len * G1_SIZE))
}

fn par_vec_g2(cursor: &mut Cursor) -> Vec<G2Affine> {
    let len = cursor.section_len();
    par_g2(cursor.take(len * G2_SIZE))
}

fn load_canonical_parallel(buf: &[u8]) -> Pk {
    let mut cursor = Cursor { buf, pos: 0 };
    let alpha_g1 =
        G1Affine::deserialize_uncompressed_unchecked(cursor.take(G1_SIZE)).expect("alpha");
    let beta_g2 =
        G2Affine::deserialize_uncompressed_unchecked(cursor.take(G2_SIZE)).expect("beta g2");
    let gamma_g2 =
        G2Affine::deserialize_uncompressed_unchecked(cursor.take(G2_SIZE)).expect("gamma g2");
    let delta_g2 =
        G2Affine::deserialize_uncompressed_unchecked(cursor.take(G2_SIZE)).expect("delta g2");
    let gamma_abc_g1 = par_vec_g1(&mut cursor);
    let beta_g1 =
        G1Affine::deserialize_uncompressed_unchecked(cursor.take(G1_SIZE)).expect("beta g1");
    let delta_g1 =
        G1Affine::deserialize_uncompressed_unchecked(cursor.take(G1_SIZE)).expect("delta g1");
    let a_query = par_vec_g1(&mut cursor);
    let b_g1_query = par_vec_g1(&mut cursor);
    let b_g2_query = par_vec_g2(&mut cursor);
    let h_query = par_vec_g1(&mut cursor);
    let l_query = par_vec_g1(&mut cursor);
    assert_eq!(cursor.pos, buf.len(), "trailing bytes");
    Pk {
        vk: ark_groth16::VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        },
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    }
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn check(pk: &Pk, expected: &[u8], name: &str) {
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes).expect("reserialize");
    assert_eq!(bytes, expected, "{name}: roundtrip mismatch");
}

fn bench<T>(name: &str, f: &mut dyn FnMut() -> T) -> Duration {
    let mut best = Duration::MAX;
    let mut total = Duration::ZERO;
    let mut iters = 0u32;
    while iters < 3 || (total < Duration::from_secs(3) && iters < 50) {
        let start = Instant::now();
        let value = f();
        let elapsed = start.elapsed();
        drop(value);
        best = best.min(elapsed);
        total += elapsed;
        iters += 1;
    }
    let mean = total / iters;
    println!("  {name:<14} mean {mean:>9.2?}  best {best:>9.2?}  ({iters} iters)");
    mean
}

fn bench_as<T>(
    name: &str,
    expected: &[u8],
    extract: impl Fn(&T) -> &Pk,
    f: &mut dyn FnMut() -> T,
) -> Duration {
    check(extract(&f()), expected, name);
    bench(name, f)
}

fn bench_circuit(name: &str) {
    let (canonical, compressed, image) = key_paths(name);
    let canonical_bytes = std::fs::read(&canonical).expect("canonical");
    let compressed_bytes = std::fs::read(&compressed).expect("compressed");
    let image_size = std::fs::metadata(&image).expect("image meta").len();
    println!(
        "{name}: canonical {:.1} MB, compressed {:.1} MB, image {:.1} MB",
        canonical_bytes.len() as f64 / 1e6,
        compressed_bytes.len() as f64 / 1e6,
        image_size as f64 / 1e6,
    );

    bench("read", &mut || std::fs::read(&canonical).expect("read"));

    let baseline = bench_as("validated", &canonical_bytes, |pk| pk, &mut || {
        Pk::deserialize_uncompressed(&canonical_bytes[..]).expect("validated")
    });

    bench_as("unchecked", &canonical_bytes, |pk| pk, &mut || {
        Pk::deserialize_uncompressed_unchecked(&canonical_bytes[..]).expect("unchecked")
    });

    bench_as("unchecked-par", &canonical_bytes, |pk| pk, &mut || {
        load_canonical_parallel(&canonical_bytes)
    });

    bench_as("compressed", &canonical_bytes, |pk| pk, &mut || {
        Pk::deserialize_compressed(&compressed_bytes[..]).expect("compressed")
    });

    let image_mean = bench_as(
        "image",
        &canonical_bytes,
        Groth16Keys::proving_key,
        &mut || Groth16Keys::load_image(&image).expect("image"),
    );

    bench_as(
        "image-mmap",
        &canonical_bytes,
        Groth16Keys::proving_key,
        &mut || {
            let file = File::open(&image).expect("open image");
            let map = unsafe { Mmap::map(&file) }.expect("mmap");
            Groth16Keys::from_image_bytes(&map).expect("image mmap")
        },
    );

    println!(
        "  speedup image vs validated: {:.1}x",
        baseline.as_secs_f64() / image_mean.as_secs_f64()
    );
}

fn main() {
    ensure_keys::<Escrow>("escrow");
    ensure_keys::<Withdraw>("withdraw");
    bench_circuit("escrow");
    bench_circuit("withdraw");
}
