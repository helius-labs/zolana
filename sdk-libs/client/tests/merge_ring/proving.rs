//! Ring-merge proof construction and verification cases.

use groth16_solana::groth16::Groth16Verifier;
use solana_address::Address;
use zolana_client::{
    prover::merge_ring::MergeRingProver, MergeRing, MergeRingWitness, ProverClient, Rpc,
    SppProofInputUtxo, MERGE_INPUTS,
};
use zolana_interface::verifying_keys::merge_ring_8_1;
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::{instructions::merge::merge_output_blinding, Data, Utxo};

use crate::{harness::MergeRingHarness, prover_bootstrap::start_prover, test_indexer::TestIndexer};

/// Fixed test ring program id; every input and the merged output carry it and the
/// proof binds it as the shared `ring_program_id`.
fn ring_program() -> Address {
    Address::new_from_array([9u8; 32])
}

impl MergeRingHarness {
    pub(crate) fn prove_and_verify_merge_ring(&self) {
        start_prover();
        let n = self.plan.real_inputs;
        assert!((1..=MERGE_INPUTS).contains(&n), "real inputs must be 1..=8");

        let sender = if self.plan.eddsa {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&random_blinding());
            ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))
                .expect("eddsa sender keypair")
        } else {
            ShieldedKeypair::new_p256().expect("sender keypair")
        };
        let asset = Address::default(); // SOL
        let ring = ring_program();
        let owner = sender.signing_pubkey();
        let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pk");

        // Real inputs: index each ring-owned UTXO into the state tree so its inclusion
        // and nullifier non-inclusion proofs can be served.
        let mut indexer = TestIndexer::new();
        let mut inputs = Vec::with_capacity(n);
        for i in 0..n {
            let amount = 100 + i as u64;
            let mut ring_data_hash = [0u8; 32];
            ring_data_hash[31] = u8::try_from(i + 1).expect("merge input count fits u8");
            let utxo = Utxo {
                owner,
                asset,
                amount,
                blinding: random_blinding(),
                ring_program_id: Some(ring),
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &ring_data_hash)
                .expect("utxo hash");
            indexer.add_utxo(utxo_hash);
            inputs.push(SppProofInputUtxo::new(utxo, &sender).with_ring_data_hash(ring_data_hash));
        }
        // The plan derives the merged ring-owned output and owner identity; preparing
        // it pads to MERGE_INPUTS, and the MergeRingWitness folds in the owner
        // nullifier key and the proofs. The prover never sees the high-level plan.
        let mut output_ring_data_hash = [0u8; 32];
        output_ring_data_hash[31] = 0xd2;
        let merge = MergeRing::new(&sender, inputs, ring, Some(output_ring_data_hash))
            .expect("build merge-ring plan")
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
        let result = MergeRingProver::try_from(MergeRingWitness {
            prepared,
            nullifier_key: sender.nullifier_key.clone(),
            proofs,
            dummy_nullifier_proofs,
        })
        .expect("merge-ring prover")
        .build()
        .expect("build merge-ring proof");

        let proof = ProverClient::local()
            .prove_merge_ring(&result.inputs)
            .expect("prove merge-ring");
        assert!(
            proof.commitment.is_none(),
            "merge-ring proof must use vanilla Groth16"
        );
        let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
        let mut verifier = Groth16Verifier::new(
            &proof.a,
            &proof.b,
            &proof.c,
            &public_inputs,
            &merge_ring_8_1::VERIFYINGKEY,
        )
        .expect("construct verifier");
        verifier
            .verify()
            .expect("merge-ring groth16 proof verifies");

        // The owner reconstructs the ciphertext-free merge-ring output from the
        // first real input and its published nullifier.
        assert_eq!(
            merge_output_blinding(&sender.nullifier_key, &result.nullifiers[0])
                .expect("derive merge-ring output blinding"),
            expected_output.blinding,
            "owner reconstructs the merged ring output blinding",
        );
        assert_eq!(
            expected_output.hash().expect("reconstructed utxo hash"),
            result.output_hash,
            "owner reconstructs the merged ring output from the first nullifier",
        );
    }
}
