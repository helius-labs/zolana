use num_bigint::BigUint;
use serde_json::Value;

use super::*;
use crate::{
    indexer::AsyncSprIndexer,
    prover::{
        CacheReadInputs, Proof, ProofInputUtxo, ProveRequest, ProvingKeySet, TransferInput,
        TransferInputs, TransferOutput,
    },
};

struct NoRpc;

#[async_trait::async_trait]
impl AsyncRpc for NoRpc {}

struct FixtureProver {
    proof: Proof,
    keys: Option<ProvingKeySet>,
}

impl Prover for FixtureProver {
    fn prove(&self, request: &dyn ProveRequest) -> Result<Proof, ClientError> {
        assert_eq!(request.proving_key()?.name, "transfer_confidential_2_4.key");
        Ok(self.proof)
    }

    fn key_set(&self) -> Option<&ProvingKeySet> {
        self.keys.as_ref()
    }
}

fn transfer_result(public_input_hash: [u8; 32]) -> TransferProofResult {
    // Only the shape and public hash are consumed by this acceptance helper.
    // The fixture prover supplies a real proof independently of these inputs.
    let input = TransferInput {
        utxo: ProofInputUtxo::default(),
        is_dummy: BigUint::ZERO,
        state_path_elements: Vec::new(),
        state_path_index: BigUint::ZERO,
        nullifier_low_value: BigUint::ZERO,
        nullifier_next_value: BigUint::ZERO,
        nullifier_low_path_elements: Vec::new(),
        nullifier_low_path_index: BigUint::ZERO,
        tree_slot: BigUint::ZERO,
        nullifier: BigUint::ZERO,
        owner_pk_hash: BigUint::ZERO,
        nullifier_secret: Some(BigUint::ZERO),
    };
    let output = TransferOutput {
        utxo: ProofInputUtxo::default(),
        is_dummy: BigUint::ZERO,
        hash: BigUint::ZERO,
        owner_pk_hash: BigUint::ZERO,
        nullifier_pk: BigUint::ZERO,
    };
    TransferProofResult {
        inputs: TransferInputs {
            inputs: vec![input; 2],
            outputs: vec![output; 4],
            tree_slots: core::array::from_fn(|_| Default::default()),
            output_tree_id: BigUint::ZERO,
            blinding_seed: BigUint::ZERO,
            external_data_hash: BigUint::ZERO,
            private_tx_hash: BigUint::ZERO,
            public_assets: core::array::from_fn(|_| BigUint::ZERO),
            public_amounts: core::array::from_fn(|_| BigUint::ZERO),
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: Vec::new(),
            input_flags: BigUint::ZERO,
            published_output_owner_pk_hashes: Vec::new(),
            cache: CacheReadInputs::default(),
            public_input_hash: BigUint::from_bytes_be(&public_input_hash),
        },
        public_input_hash,
        nullifiers: Vec::new(),
        output_hashes: Vec::new(),
        private_tx_hash: [0; 32],
        tree_contexts: Vec::new(),
        tree_ids: Vec::new(),
        input_tree_indexes: Vec::new(),
        cache_access: None,
        circuit: spr_interface::instruction::instruction_data::transact::CircuitId::ConfidentialSigner(2, 4, spr_interface::N_PUBLIC_SLOTS as u8),
        default_owner_tag: None,
    }
}

#[tokio::test]
async fn transfer_result_uses_the_selected_verifier_and_rejects_another_statement() {
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
    let client = AsyncSprClient::with_prover(
        NoRpc,
        AsyncSprIndexer::new("http://127.0.0.1:1"),
        FixtureProver {
            proof,
            keys: Some(keys),
        },
    );
    let result = transfer_result(public_input_hash);
    assert!(matches!(
        verify_confidential_transfer_proof(&result, &proof),
        Err(ClientError::ProofVerification(_))
    ));
    let accepted = client
        .prove_confidential_transfer_result(&result)
        .await
        .unwrap();
    let expected = ProofCompressed::try_from(proof).unwrap();
    assert_eq!(
        (accepted.a, accepted.b, accepted.c),
        (expected.a, expected.b, expected.c)
    );

    let mut other_statement = result;
    other_statement.public_input_hash[31] ^= 1;
    assert!(matches!(
        client
            .prove_confidential_transfer_result(&other_statement)
            .await,
        Err(ClientError::ProofVerification(_))
    ));

    let compiled = AsyncSprClient::with_prover(
        NoRpc,
        AsyncSprIndexer::new("http://127.0.0.1:1"),
        FixtureProver { proof, keys: None },
    );
    assert!(matches!(
        compiled
            .prove_confidential_transfer_result(&transfer_result(public_input_hash))
            .await,
        Err(ClientError::ProofVerification(_))
    ));
}
