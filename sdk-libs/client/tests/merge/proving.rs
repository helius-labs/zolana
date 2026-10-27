//! Merge proof construction and verification cases.

use crate::input_fixture::wallet_utxo;
use groth16_solana::groth16::Groth16Verifier;
use spr_client::{MergeProver, ProverClient, ProverExt, Rpc};
use spr_interface::{
    instruction::instruction_data::merge_transact::MergeProof,
    verifying_keys::{merge_24_1, merge_52_1, merge_8_1},
};
use spr_keypair::{random_blinding, ShieldedKeypair};
use spr_transaction::instructions::merge::{MergeTransaction, MAX_MERGE_INPUTS};
use spr_transaction::{instructions::merge::merge_output_blinding, Data, Mint, Utxo};

use crate::{harness::MergeHarness, prover_bootstrap::start_prover, test_indexer::TestIndexer};

/// Test fixtures live in the first localnet tree.
// TODO(tree-id): resolve the tree id from the tree account.
const TEST_TREE_ID: u16 = 0;

impl MergeHarness {
    pub(crate) fn prove_and_verify_merge(&self) {
        start_prover();
        let n = self.plan.real_inputs;
        assert!(
            (1..=MAX_MERGE_INPUTS).contains(&n),
            "real inputs must be 1..={MAX_MERGE_INPUTS}"
        );

        let sender = ShieldedKeypair::new_ed25519().expect("sender keypair");
        let asset = Mint::SOL;
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
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
                .expect("utxo hash");
            let leaf_index = indexer.add_utxo(utxo_hash);
            inputs.push(wallet_utxo(
                utxo,
                &sender.nullifier_key,
                TEST_TREE_ID,
                leaf_index,
                None,
                None,
            ));
        }
        // The plan derives the merged output and owner identity; preparing it pads to
        // MERGE_INPUTS, and the MergeWitness folds in the owner nullifier key and the
        // proofs. The prover never sees the high-level plan.
        let merge = MergeTransaction::new(inputs)
            .expect("build merge plan")
            .with_expiry(0);
        let prepared = merge.encrypt(&sender).expect("encrypt merge");
        let expected_output = prepared.output_utxo.clone();
        let commitments = prepared.input_utxo_hashes().expect("input commitments");
        let proofs = indexer
            .get_input_merkle_proofs(&commitments, None)
            .expect("merkle proofs");
        let dummy_nullifier_proofs = prepared
            .dummy_nullifiers()
            .into_iter()
            .map(|nullifier| indexer.dummy_nullifier_proof(nullifier))
            .collect();
        let result = MergeProver {
            transaction: prepared,
            nullifier_key: sender.nullifier_key.clone(),
            proofs,
            dummy_nullifier_proofs,
            cache: None,
        }
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
        let vk = match result.nullifiers.len() {
            8 => &merge_8_1::VERIFYINGKEY,
            24 => &merge_24_1::VERIFYINGKEY,
            52 => &merge_52_1::VERIFYINGKEY,
            other => panic!("no committed verifying key for a {other}-input merge"),
        };
        let mut verifier = Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &public_inputs, vk)
            .expect("construct verifier");
        verifier.verify().expect("merge groth16 proof verifies");
        let sent = result
            .instruction_data(MergeProof::zeroed())
            .nullifiers
            .len();
        assert_eq!(sent, n, "compact padding is left out of the instruction");

        // The owner derives the merge output blinding from its nullifier key
        // and the first real input's published nullifier; the amount and mint
        // come from the proof-bound output ciphertext.
        assert_eq!(
            merge_output_blinding(&sender.nullifier_key, result.nullifiers.first().unwrap())
                .expect("derive merge output blinding"),
            expected_output.blinding,
            "owner reconstructs the merged output blinding",
        );
        assert_eq!(
            expected_output
                .hash(TEST_TREE_ID)
                .expect("reconstructed utxo hash"),
            result.output_hash,
            "owner reconstructs the merged output from the first nullifier",
        );
    }
}
