use std::collections::HashMap;

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use swap_program::instructions::shared::u64_to_field;
use swap_prover::{bytes_to_decimal_string, prove, setup, CircuitId};

#[test]
fn stub_setup_prove_parse() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let build_dir = std::path::PathBuf::from(manifest_dir).join("../build/gnark/stub");

    setup(CircuitId::Stub, &build_dir).expect("setup failed");

    let a = u64_to_field(7);
    let b = u64_to_field(11);

    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("poseidon init");
    let public_input_hash = hasher.hash_bytes_be(&[&a, &b]).expect("poseidon hash");

    let mut witness: HashMap<String, Vec<String>> = HashMap::new();
    witness.insert(
        "PublicInputHash".to_string(),
        vec![bytes_to_decimal_string(&public_input_hash)],
    );
    witness.insert("A".to_string(), vec![bytes_to_decimal_string(&a)]);
    witness.insert("B".to_string(), vec![bytes_to_decimal_string(&b)]);

    let out = prove(CircuitId::Stub, &witness).expect("prove failed");

    assert_eq!(
        out.public_input_hash, public_input_hash,
        "prover public input must echo the Poseidon(A, B) public input hash"
    );

    let proof_a_zero = out.proof_a.iter().all(|byte| *byte == 0);
    let proof_b_zero = out.proof_b.iter().all(|byte| *byte == 0);
    let proof_c_zero = out.proof_c.iter().all(|byte| *byte == 0);
    assert!(!proof_a_zero, "proof_a must not be all zero");
    assert!(!proof_b_zero, "proof_b must not be all zero");
    assert!(!proof_c_zero, "proof_c must not be all zero");
}

#[test]
fn stub_prove_rejects_wrong_public_input() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let build_dir = std::path::PathBuf::from(manifest_dir).join("../build/gnark/stub");

    setup(CircuitId::Stub, &build_dir).expect("setup failed");

    let a = u64_to_field(7);
    let b = u64_to_field(11);
    let wrong = u64_to_field(123456);

    let mut witness: HashMap<String, Vec<String>> = HashMap::new();
    witness.insert(
        "PublicInputHash".to_string(),
        vec![bytes_to_decimal_string(&wrong)],
    );
    witness.insert("A".to_string(), vec![bytes_to_decimal_string(&a)]);
    witness.insert("B".to_string(), vec![bytes_to_decimal_string(&b)]);

    let result = prove(CircuitId::Stub, &witness);
    assert!(
        result.is_err(),
        "prove must fail when PublicInputHash != Poseidon(A, B)"
    );
}
