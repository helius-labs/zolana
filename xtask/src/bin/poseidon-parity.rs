//! Generates the Poseidon parity vectors that the TypeScript ports check
//! themselves against.
//!
//! `program-libs/hasher/src/poseidon.rs` is reimplemented five times in
//! TypeScript, each time by generating the round constants from the Grain LFSR
//! through `@noble/curves` rather than by porting the tables. Nothing compared
//! those generated tables against the Rust ones, so this binary emits both the
//! parameters and a spread of hash vectors straight from `zolana-hasher`.
//!
//! The parameters travel as digests: `arkSha256` and `mdsSha256` are SHA-256
//! over the big-endian 32-byte encoding of every round constant and every MDS
//! entry in row-major order. A TypeScript test that regenerates its own
//! constants and hashes them the same way compares all 949 constants and 169
//! matrix entries of the widest arity, not a sample of them.
//!
//! ```text
//! cargo run -p xtask --bin poseidon-parity            # write the fixture
//! cargo run -p xtask --bin poseidon-parity -- --check  # fail on any drift
//! ```

use std::{env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::merge_utils::{
    ciphertext_hash, owner_pk_field_compressed, pk_field_compressed,
};

/// `light_poseidon::MAX_X5_LEN` is 13, and the width is one wider than the
/// input count, so the Rust hasher accepts 1 through 12 inputs. The Solana
/// `sol_poseidon` syscall caps at 12 inputs as well.
const MAX_INPUTS: usize = 12;

const FIXTURE: &str = "sdk-libs/ts/vectors/poseidon-parity-v1.json";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("poseidon-parity failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "Generate the Rust-side Poseidon parity vectors.\n\nusage: cargo run -p xtask --bin poseidon-parity -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    let fixture = fixture()?;
    let mut bytes = serde_json::to_vec_pretty(&canonicalize(&fixture))?;
    bytes.push(b'\n');

    if check {
        let current = fs::read(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != bytes {
            bail!("{FIXTURE} differs from the Rust hasher; regenerate it");
        }
        println!("verified {FIXTURE}");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    println!("wrote {FIXTURE}");
    Ok(())
}

fn fixture() -> Result<Value> {
    Ok(json!({
        "ciphertextHashes": ciphertext_hashes()?,
        "field": field(),
        "generatorCommand": "cargo run -p xtask --bin poseidon-parity",
        "id": "hasher-poseidon-parity",
        "mergeUtils": merge_utils()?,
        "parameters": parameters(),
        "rejects": rejects(),
        "responsibility": concat!(
            "Rust oracle for every TypeScript reimplementation of ",
            "program-libs/hasher/src/poseidon.rs: the circom-x5 parameters per arity, ",
            "hash vectors over every supported arity and field edge, and the inputs ",
            "the Rust hasher refuses."
        ),
        "rustPath": "program-libs/hasher/src/poseidon.rs",
        "rustSymbol": "<Poseidon as Hasher>::hashv",
        "schema": "zolana-ts-fixtures-v1",
        "shortInputs": short_inputs()?,
        "vectors": vectors()?,
        "version": "1"
    }))
}

fn field() -> Value {
    json!({
        "bits": 254,
        "modulus": modulus_decimal(),
        "modulusBytes": hex(&modulus_bytes()),
        "modulusMinusOneBytes": hex(&fr_bytes(&(Fr::ZERO - Fr::ONE))),
    })
}

/// Round constants (`ark`) and MDS entries per arity, as digests over their
/// canonical big-endian encodings. A single differing constant changes the
/// digest, so this is an element-by-element comparison in 32 bytes.
fn parameters() -> Value {
    let per_arity = (1..=MAX_INPUTS)
        .map(|inputs| {
            let params = circom_parameters(inputs);
            let ark = params.ark.iter().flat_map(fr_bytes).collect::<Vec<u8>>();
            let mds = params
                .mds
                .iter()
                .flatten()
                .flat_map(fr_bytes)
                .collect::<Vec<u8>>();
            json!({
                "arkCount": params.ark.len(),
                "arkSha256": sha256(&ark),
                "inputs": inputs,
                "mdsCount": params.mds.len() * params.mds.len(),
                "mdsSha256": sha256(&mds),
                "roundsPartial": params.partial_rounds,
                "width": params.width,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "alpha": 5,
        "domainTagBytes": hex(&[0u8; 32]),
        "maxInputs": MAX_INPUTS,
        "perArity": per_arity,
        "roundsFull": 8,
    })
}

/// The permutation is fed `[domain_tag, ..inputs]` and the digest is state
/// element zero, so a swapped pair or a shifted input lands on a different
/// hash. Each family below is generated for every arity the Rust hasher
/// accepts.
fn vectors() -> Result<Vec<Value>> {
    let zero = [0u8; 32];
    let one = be_u64(1);
    let max = fr_bytes(&(Fr::ZERO - Fr::ONE));
    let mut out = Vec::new();

    for inputs in 1..=MAX_INPUTS {
        out.push(vector("zeros", inputs, vec![zero; inputs])?);
        out.push(vector("ones", inputs, vec![one; inputs])?);
        out.push(vector(
            "fill",
            inputs,
            (0..inputs).map(|i| [(i as u8) + 1; 32]).collect(),
        )?);
        out.push(vector("max", inputs, vec![max; inputs])?);

        let mut max_first = vec![zero; inputs];
        max_first[0] = max;
        out.push(vector("max-first", inputs, max_first)?);

        let mut max_last = vec![zero; inputs];
        max_last[inputs - 1] = max;
        out.push(vector("max-last", inputs, max_last)?);

        let mut counter = vec![zero; inputs];
        for (position, slot) in counter.iter_mut().enumerate() {
            *slot = be_u64(position as u64 + 1);
        }
        out.push(vector("counter", inputs, counter)?);

        out.push(vector(
            "pseudo",
            inputs,
            (0..inputs).map(|i| pseudo_field(inputs, i)).collect(),
        )?);
    }

    // Order sensitivity at the narrowest arity that can show it.
    out.push(vector("zero-one", 2, vec![zero, one])?);
    out.push(vector("one-zero", 2, vec![one, zero])?);
    // The largest value below the modulus next to the smallest above zero.
    out.push(vector("max-one", 2, vec![max, one])?);
    out.push(vector("one-max", 2, vec![one, max])?);

    Ok(out)
}

fn vector(family: &str, inputs: usize, values: Vec<[u8; 32]>) -> Result<Value> {
    let refs = values
        .iter()
        .map(|value| value.as_slice())
        .collect::<Vec<_>>();
    let expected =
        Poseidon::hashv(&refs).map_err(|error| anyhow::anyhow!("{family}/{inputs}: {error:?}"))?;
    Ok(json!({
        "expectedBytes": hex(&expected),
        "id": format!("poseidon-{family}-{inputs}"),
        "inputsBytes": values.iter().map(|value| hex(value)).collect::<Vec<_>>(),
    }))
}

/// Inputs the Rust hasher refuses, with the Rust error recorded so a future
/// widening of the Rust domain shows up as fixture drift rather than as a
/// silent divergence.
///
/// `kind` separates the rejections every port has to reproduce from the one
/// they deliberately do not: `shorterThan32` is the Rust hasher's strict
/// 32-byte input rule, and three ports read a shorter slice as a big-endian
/// integer instead, which `shortInputs` pins to the same digest.
fn rejects() -> Vec<Value> {
    let zero = [0u8; 32];
    let mut out = vec![reject("no-inputs", "arity", &[])];

    let thirteen = vec![zero; MAX_INPUTS + 1];
    out.push(reject(
        "arity-above-max",
        "arity",
        &thirteen.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
    ));

    let short = [1u8; 31];
    out.push(reject("input-31-bytes", "shorterThan32", &[&short[..]]));
    let long = [1u8; 33];
    out.push(reject("input-33-bytes", "longerThan32", &[&long[..]]));

    let modulus = modulus_bytes();
    out.push(reject(
        "input-equals-modulus",
        "notCanonical",
        &[&modulus[..]],
    ));
    let all_ones = [0xffu8; 32];
    out.push(reject(
        "input-above-modulus",
        "notCanonical",
        &[&all_ones[..]],
    ));

    out
}

/// The Rust hasher takes 32-byte inputs only, while three of the TypeScript
/// ports accept anything shorter and read it as a big-endian integer. That is
/// a wider input domain, not a different digest: each entry pins the shorter
/// form to the Rust hash of the same value right-aligned into 32 bytes, so the
/// laxness stays checked instead of assumed.
fn short_inputs() -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for length in [1usize, 8, 16, 31] {
        let short = (0..length)
            .map(|index| (index as u8) + 1)
            .collect::<Vec<u8>>();
        let mut aligned = [0u8; 32];
        aligned[32 - length..].copy_from_slice(&short);
        let expected = Poseidon::hashv(&[&aligned[..]])
            .map_err(|error| anyhow::anyhow!("short_inputs({length}): {error:?}"))?;
        out.push(json!({
            "alignedBytes": hex(&aligned),
            "expectedBytes": hex(&expected),
            "id": format!("short-input-{length}"),
            "shortBytes": hex(&short),
        }));
    }
    Ok(out)
}

fn reject(id: &str, kind: &str, inputs: &[&[u8]]) -> Value {
    let error = match Poseidon::hashv(inputs) {
        Ok(hash) => panic!("{id} unexpectedly hashed to {}", hex(&hash)),
        Err(error) => format!("{error:?}"),
    };
    json!({
        "id": format!("poseidon-reject-{id}"),
        "inputsBytes": inputs.iter().map(|input| hex(input)).collect::<Vec<_>>(),
        "kind": kind,
        "reason": error,
    })
}

/// `merge_utils::ciphertext_hash` is how `@zolana/interface` reaches its own
/// Poseidon: 16-byte big-endian chunks, right-aligned. The chunk count is the
/// arity, so 1 through 192 bytes walks arity 1 through 12 and 193 bytes is the
/// first length the Rust hasher cannot take.
fn ciphertext_hashes() -> Result<Vec<Value>> {
    let mut lengths = (1..=MAX_INPUTS)
        .map(|chunks| chunks * 16)
        .collect::<Vec<_>>();
    lengths.extend([1usize, 15, 17, 31, 33, 191]);
    lengths.sort_unstable();

    let mut out = Vec::new();
    for length in lengths {
        let ciphertext = ciphertext_bytes(length);
        let hash = ciphertext_hash(&ciphertext)
            .map_err(|error| anyhow::anyhow!("ciphertext_hash({length}): {error:?}"))?;
        out.push(json!({
            "chunkCount": length.div_ceil(16),
            "ciphertextBytes": hex(&ciphertext),
            "expectedBytes": hex(&hash),
            "id": format!("ciphertext-hash-{length}"),
            "lengthBytes": length,
        }));
    }
    for length in [0usize, 193, 208] {
        let ciphertext = ciphertext_bytes(length);
        let Err(error) = ciphertext_hash(&ciphertext) else {
            bail!("ciphertext_hash({length}) unexpectedly succeeded");
        };
        out.push(json!({
            "chunkCount": length.div_ceil(16),
            "ciphertextBytes": hex(&ciphertext),
            "id": format!("ciphertext-hash-reject-{length}"),
            "lengthBytes": length,
            "reason": format!("{error:?}"),
        }));
    }
    Ok(out)
}

fn ciphertext_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

/// The two compressed-P256 hashes in `merge_utils`, which pin the input order
/// of the low and high halves of `x` as well as the parity field element.
fn merge_utils() -> Result<Value> {
    let mut entries = Vec::new();
    for (id, prefix) in [("even", 0x02u8), ("odd", 0x03u8)] {
        let mut compressed = [0u8; 33];
        compressed[0] = prefix;
        for (index, slot) in compressed.iter_mut().skip(1).enumerate() {
            *slot = (index as u8).wrapping_mul(7).wrapping_add(11);
        }
        let pk_field = pk_field_compressed(&compressed)
            .map_err(|error| anyhow::anyhow!("pk_field_compressed({id}): {error:?}"))?;
        let owner_field = owner_pk_field_compressed(&compressed)
            .map_err(|error| anyhow::anyhow!("owner_pk_field_compressed({id}): {error:?}"))?;
        entries.push(json!({
            "compressedBytes": hex(&compressed),
            "id": format!("pk-field-{id}"),
            "ownerPkFieldBytes": hex(&owner_field),
            "pkFieldBytes": hex(&pk_field),
        }));
    }
    Ok(json!({ "pkFields": entries }))
}

/// Deterministic field elements with the top three bits cleared, which keeps
/// them below the modulus without a rejection loop.
fn pseudo_field(arity: usize, position: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zolana-poseidon-parity");
    hasher.update((arity as u64).to_be_bytes());
    hasher.update((position as u64).to_be_bytes());
    let mut bytes: [u8; 32] = hasher.finalize().into();
    bytes[0] &= 0x1f;
    bytes
}

fn circom_parameters(inputs: usize) -> light_poseidon::PoseidonParameters<Fr> {
    light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>((inputs + 1) as u8)
        .expect("circom-x5 parameters for a supported arity")
}

fn modulus_bytes() -> [u8; 32] {
    let mut bytes = fr_bytes(&(Fr::ZERO - Fr::ONE));
    for byte in bytes.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
    bytes
}

fn modulus_decimal() -> String {
    Fr::MODULUS.to_string()
}

fn fr_bytes(value: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = value.into_bigint().to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn be_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}
