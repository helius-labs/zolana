#![cfg(feature = "gnark")]

mod support;

use spr_forester_prover::ProverClient;
use std::path::PathBuf;

#[test]
#[ignore = "requires the pinned batch_address-append_40_10.key in FORESTER_TEST_KEYS_DIR"]
fn local_batch_proof() {
    let keys = PathBuf::from(
        std::env::var_os("FORESTER_TEST_KEYS_DIR").expect("set FORESTER_TEST_KEYS_DIR"),
    );
    let inputs = support::batch_inputs(1);
    let prover = ProverClient::local(keys).unwrap();
    let proof = prover.prove_batch_address_append(&inputs).unwrap();
    support::assert_batch_proof(&inputs, &proof);
}
