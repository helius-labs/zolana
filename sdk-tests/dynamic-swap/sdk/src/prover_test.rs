use std::{fs, ptr, sync::OnceLock};

use dynamic_swap_program::circuits::PoolDeposit;
use zolana_keypair::hash::sha256;
use zolana_program::{Groth16Keys, R1cs, ZkCircuit};

use super::{load_prover, CachedProver};

fn encoded_keys() -> &'static (Vec<u8>, [u8; 32]) {
    static KEYS: OnceLock<(Vec<u8>, [u8; 32])> = OnceLock::new();
    KEYS.get_or_init(|| {
        let circuit = R1cs::from_bytes(&PoolDeposit::export_r1cs().unwrap()).unwrap();
        let keys = Groth16Keys::new_with_test_setup(&circuit).unwrap();
        let bytes = keys.to_bytes().unwrap();
        let checksum = sha256(&bytes);
        (bytes, checksum)
    })
}

#[test]
fn missing_proving_key_can_be_created_and_retried() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pool_deposit.pk");
    let cache = CachedProver::<PoolDeposit>::new();
    let (bytes, checksum) = encoded_keys();

    assert!(load_prover(&cache, &path, checksum).is_err());
    fs::write(&path, bytes).unwrap();
    let loaded = load_prover(&cache, &path, checksum)
        .expect("creating the missing key must let the same cache retry");

    fs::remove_file(&path).unwrap();
    let reused = load_prover(&cache, &path, checksum)
        .expect("a successful load remains cached after the key file is removed");
    assert!(
        ptr::eq(loaded, reused),
        "reuse the successfully loaded prover"
    );
}

#[test]
fn mismatched_proving_key_can_be_repaired_and_retried() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pool_deposit.pk");
    let cache = CachedProver::<PoolDeposit>::new();
    let (bytes, checksum) = encoded_keys();

    fs::write(&path, b"an incomplete proving key").unwrap();
    assert!(load_prover(&cache, &path, checksum).is_err());

    fs::write(&path, bytes).unwrap();
    load_prover(&cache, &path, checksum).expect("repairing the key must let the same cache retry");
}
