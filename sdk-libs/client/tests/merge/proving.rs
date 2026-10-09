//! Merge proof construction and verification cases.

use crate::input_fixture::wallet_utxo;
use groth16_solana::groth16::Groth16Verifier;
use zolana_client::{MergeProver, ProofCompressed, ProverClient, ProverExt, Rpc};
use zolana_interface::verifying_keys::{merge_24_1, merge_54_1, merge_8_1};
use zolana_keypair::{
    random_blinding, MergeEnvelopeDecryption, P256Pubkey, ShieldedKeypair, SigningKey,
};
use zolana_transaction::instructions::merge::{MergeTransaction, MAX_MERGE_INPUTS};
use zolana_transaction::{Data, Mint, Utxo};

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

        let sender = if self.plan.eddsa {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&random_blinding());
            ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))
                .expect("eddsa sender keypair")
        } else {
            ShieldedKeypair::new_p256().expect("sender keypair")
        };
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
        let commitment = proof
            .commitment
            .expect("the envelope's key agreement commits private inputs");
        let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
        let vk = match result.nullifiers.len() {
            8 => &merge_8_1::VERIFYINGKEY,
            24 => &merge_24_1::VERIFYINGKEY,
            54 => &merge_54_1::VERIFYINGKEY,
            other => panic!("no committed verifying key for a {other}-input merge"),
        };
        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof.a,
            &proof.b,
            &proof.c,
            &commitment.commitment,
            &commitment.commitment_pok,
            &public_inputs,
            vk,
        )
        .expect("construct verifier");
        verifier.verify().expect("merge groth16 proof verifies");
        let data = result
            .instruction_data(ProofCompressed::try_from(proof).expect("compress merge proof"))
            .expect("merge instruction data");
        assert_eq!(
            data.body.nullifiers.len(),
            n,
            "compact padding is left out of the instruction"
        );

        let envelope = data.envelope;
        let decrypted = MergeEnvelopeDecryption {
            viewing_key: &sender.viewing_key,
            ephemeral_pk: &P256Pubkey::from_bytes(envelope.ephemeral_pk).expect("ephemeral key"),
            ciphertext: &envelope.ciphertext,
            first_nullifier: data.body.nullifiers.first().expect("first nullifier"),
        }
        .decrypt()
        .expect("owner decrypts the merge envelope");
        assert_eq!(
            (decrypted.amount, decrypted.mint, decrypted.output_blinding),
            (
                expected_output.amount,
                expected_output.asset.asset.to_bytes(),
                expected_output.blinding
            ),
            "owner reconstructs the merged output from the envelope",
        );
        assert_eq!(
            expected_output
                .hash(TEST_TREE_ID)
                .expect("reconstructed utxo hash"),
            result.output_hash,
            "the reconstructed output is the committed one",
        );
    }
}
