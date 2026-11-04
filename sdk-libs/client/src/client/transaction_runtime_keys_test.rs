use serde_json::Value;

use crate::{
    prover::{verify::confidential_verifying_key, verify_proof_statement, ProvingKeySet},
    ClientError, Proof,
};

#[test]
fn explicit_verification_uses_the_selected_key_and_rejects_another_statement() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/runtime_key_proof.json"
    ))
    .unwrap();
    let proof = Proof::from_gnark_json(&vector["proof"].to_string()).unwrap();
    let public_input_hash = hex::decode(
        vector["publicInputHash"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let mut catalog: Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/runtime_proving_keys.json"
    ))
    .unwrap();
    // Reuse the fixture's verifier under a different shape to distinguish the
    // selected verifier from the compiled one without generating setup keys.
    let source = vector["key"].as_str().unwrap();
    let target = "transfer_confidential_2_4.key";
    catalog["runtime"]["verifyingKeys"][target] =
        catalog["runtime"]["verifyingKeys"][source].clone();
    let digest = catalog["runtime"]["verifyingKeys"][target]["provingKeySha256"].clone();
    let entry = catalog["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["name"] == target)
        .unwrap();
    let gnark = entry["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["format"] == "gnark")
        .unwrap();
    gnark["sha256"] = digest;
    let keys = ProvingKeySet::from_attested_response(&catalog.to_string()).unwrap();
    keys.verify(target, public_input_hash, &proof).unwrap();
    assert!(matches!(
        verify_proof_statement(
            &proof,
            public_input_hash,
            confidential_verifying_key(2, 4).unwrap()
        ),
        Err(ClientError::ProofVerification(_))
    ));

    let mut other_statement = public_input_hash;
    other_statement[31] ^= 1;
    assert!(matches!(
        keys.verify(target, other_statement, &proof),
        Err(ClientError::ProofVerification(_))
    ));
}
