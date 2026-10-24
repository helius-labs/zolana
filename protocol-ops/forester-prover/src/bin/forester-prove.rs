//! Generate one complete address-append proof without a validator or a Go runtime.
use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use serde_json::json;
use std::{path::PathBuf, process::ExitCode, time::Instant};
use zolana_forester_prover::{build_inputs, reference_nullifier_tree, ProverClient};
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;

fn run() -> Result<()> {
    let mut keys = None;
    let mut scratch = std::env::temp_dir().join("zolana-forester-prover");
    let mut output = None;
    let mut batch_size = 4999u32;
    let mut threads = 4usize;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = |arguments: &mut std::iter::Skip<std::env::Args>| {
            arguments
                .next()
                .with_context(|| format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--keys-dir" => keys = Some(PathBuf::from(value(&mut arguments)?)),
            "--scratch-dir" => scratch = PathBuf::from(value(&mut arguments)?),
            "--output" => output = Some(PathBuf::from(value(&mut arguments)?)),
            "--batch-size" => batch_size = value(&mut arguments)?.parse()?,
            "--threads" => threads = value(&mut arguments)?.parse()?,
            "--help" | "-h" => {
                println!("forester-prove --keys-dir <dir> --output <proof.json> [--batch-size 4999|10] [--scratch-dir <dir>] [--threads 4]");
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }
    if !matches!(batch_size, 10 | 4999) || threads == 0 {
        bail!("batch size must be 10 or 4999 and threads must be positive");
    }
    let keys = keys.context("--keys-dir is required")?;
    let output = output.context("--output is required")?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let started = Instant::now();
    let values = (1..=u64::from(batch_size))
        .map(|number| {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&number.to_be_bytes());
            bytes
        })
        .collect::<Vec<_>>();
    let mut reference = reference_nullifier_tree(40)?;
    let old_root = reference.root();
    let hash_chain = create_hash_chain_4_from_slice(&values)?;
    eprintln!("native: constructing all {batch_size} append inputs");
    let (inputs, new_root) = build_inputs(&mut reference, 1, 40, hash_chain, old_root, &values)?;
    eprintln!("native: built all {batch_size} append inputs with {threads} worker threads");
    let prover = ProverClient::local_with_scratch(keys, scratch)?;
    let proof = prover.prove_batch_address_append(&inputs)?;
    let public_input_hash = to_bytes(&inputs.public_input_hash)?;
    let tree_proof = zolana_tree::nullifier_tree::proof::NullifierTreeProof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    };
    zolana_tree::nullifier_tree::verify::verify_batch_update(
        u64::from(batch_size),
        public_input_hash,
        &tree_proof,
    )
    .map_err(|error| {
        anyhow::anyhow!("checked-in Solana verifier rejected native proof: {error:?}")
    })?;
    let mut changed_hash = public_input_hash;
    changed_hash[31] ^= 1;
    if zolana_tree::nullifier_tree::verify::verify_batch_update(
        u64::from(batch_size),
        changed_hash,
        &tree_proof,
    )
    .is_ok()
    {
        bail!("verifier accepted a changed public input");
    }
    let key_name = format!("batch_address-append_40_{batch_size}.key");
    let digest = zolana_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S
        .iter()
        .find(|(name, _)| *name == key_name)
        .map(|(_, sha)| hex::encode(sha))
        .context("unknown batch key")?;
    let report = json!({
        "backend":"native-rust", "treeHeight":40,"batchSize":batch_size,"startIndex":1,
        "provingKeySha256":digest,"oldRoot":hex::encode(old_root),"newRoot":hex::encode(new_root),
        "leavesHashChain":hex::encode(hash_chain),"publicInputHash":hex::encode(public_input_hash),
        "proof":{"a":hex::encode(proof.a),"b":hex::encode(proof.b),"c":hex::encode(proof.c)},
        "verified":true,"changedPublicInputRejected":true,"elapsedSeconds":started.elapsed().as_secs_f64(),"threads":threads,
    });
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    eprintln!(
        "native: verified {batch_size}-element proof written to {}",
        output.display()
    );
    Ok(())
}
fn to_bytes(value: &BigUint) -> Result<[u8; 32]> {
    let encoded = value.to_bytes_be();
    if encoded.len() > 32 {
        bail!("public input exceeds scalar width");
    }
    let mut bytes = [0u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(bytes)
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
