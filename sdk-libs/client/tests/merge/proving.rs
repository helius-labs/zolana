//! Merge proof construction and verification cases.

use groth16_solana::groth16::Groth16Verifier;
use solana_address::Address;
use zolana_client::{
    prover::merge::MergeProver, Merge, MergeProofMaterial, ProverClient, Rpc, SppProofInputUtxo,
    MERGE_INPUTS,
};
use zolana_interface::verifying_keys::merge_8_1;
use zolana_keypair::{merge::merge_output_blinding, random_blinding, ShieldedKeypair, ViewingKey};
use zolana_transaction::{Data, Utxo};

use crate::{harness::MergeHarness, prover_bootstrap::start_prover, test_indexer::TestIndexer};

impl MergeHarness {
    pub(crate) fn prove_and_verify_merge(&self) {
        start_prover();
        let n = self.plan.real_inputs;
        assert!((1..=MERGE_INPUTS).contains(&n), "real inputs must be 1..=8");

        let sender = if self.plan.eddsa {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&random_blinding());
            ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("eddsa sender keypair")
        } else {
            ShieldedKeypair::new().expect("sender keypair")
        };
        let asset = Address::default(); // SOL
        let owner = sender.signing_pubkey();
        let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pk");

        // Real inputs: index each UTXO into the state tree so its inclusion and
        // nullifier non-inclusion proofs can be served.
        let mut indexer = TestIndexer::new();
        let mut inputs = Vec::with_capacity(n);
        for i in 0..n {
            let amount = 100 + i as u64;
            let utxo = Utxo {
                owner,
                asset,
                amount,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
                .expect("utxo hash");
            indexer.add_utxo(utxo_hash);
            inputs.push(SppProofInputUtxo::new(utxo, &sender));
        }
        // The plan derives the merged output and owner identity; preparing it pads to
        // MERGE_INPUTS, and the MergeProofMaterial folds in the owner nullifier key and the
        // proofs. The prover never sees the high-level plan.
        let merge = Merge::new(&sender, inputs)
            .expect("build merge plan")
            .with_expiry(0);
        let prepared = merge.prepare();
        let expected_output = prepared.output.clone();
        let commitments = prepared.input_utxo_hashes().expect("input commitments");
        let proofs = indexer
            .get_input_merkle_proofs(&commitments, None)
            .expect("merkle proofs");
        let dummy_nullifier_proofs = prepared
            .dummy_nullifiers(&sender.nullifier_key)
            .expect("dummy nullifiers")
            .into_iter()
            .map(|nullifier| indexer.dummy_nullifier_proof(nullifier))
            .collect();
        let result = MergeProver::try_from(MergeProofMaterial {
            prepared,
            nullifier_key: sender.nullifier_key.clone(),
            proofs,
            dummy_nullifier_proofs,
        })
        .expect("merge prover")
        .build()
        .expect("build merge proof");

        let proof = ProverClient::local()
            .prove_merge(&result.inputs)
            .expect("prove merge");
        assert!(
            proof.commitment.is_none(),
            "merge proof must use vanilla Groth16"
        );
        let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
        let mut verifier = Groth16Verifier::new(
            &proof.a,
            &proof.b,
            &proof.c,
            &public_inputs,
            &merge_8_1::VERIFYINGKEY,
        )
        .expect("construct verifier");
        verifier.verify().expect("merge groth16 proof verifies");

        // The owner reconstructs the ciphertext-free merge output from the
        // first real input and its published nullifier.
        assert_eq!(
            merge_output_blinding(&sender.nullifier_key, &result.nullifiers[0])
                .expect("derive merge output blinding"),
            expected_output.blinding,
            "owner reconstructs the merged output blinding",
        );
        assert_eq!(
            expected_output.hash().expect("reconstructed utxo hash"),
            result.output_hash,
            "owner reconstructs the merged output from the first nullifier",
        );
    }
}
