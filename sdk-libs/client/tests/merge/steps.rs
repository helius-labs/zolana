//! Merge step definitions: build N real inputs (padded to 8 with dummies) sharing
//! one owner, consolidate them into one output, prove on the merge_8_1 circuit,
//! and verify against the committed merge verifying key.

use std::sync::Once;

use cucumber::{given, then};
use groth16_solana::groth16::Groth16Verifier;
use solana_address::Address;
use zolana_client::{
    private_transaction::field::asset_field, spawn_prover, Merge, PreparedMerge, ProverClient, Rpc,
    SpendUtxo, MERGE_INPUTS,
};
use zolana_interface::verifying_keys::merge_8_1;
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_transaction::{Data, OutputUtxo, Utxo};

use crate::{test_indexer::TestIndexer, world::MergeWorld};

#[given(expr = "{int} P256 SOL inputs to merge")]
fn given_inputs(world: &mut MergeWorld, n: usize) {
    world.plan.real_inputs = n;
    world.plan.eddsa = false;
}

#[given(expr = "{int} Solana SOL inputs to merge")]
fn given_eddsa_inputs(world: &mut MergeWorld, n: usize) {
    world.plan.real_inputs = n;
    world.plan.eddsa = true;
}

#[then("the merge proof verifies")]
fn then_verifies(world: &mut MergeWorld) {
    world.prove_and_verify_merge();
}

impl MergeWorld {
    pub(crate) fn prove_and_verify_merge(&self) {
        start_prover();
        let n = self.plan.real_inputs;
        assert!((1..=MERGE_INPUTS).contains(&n), "real inputs must be 1..=8");

        let sender = if self.plan.eddsa {
            let mut seed = [0u8; 32];
            seed[1..].copy_from_slice(&random_blinding());
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
                zone_program_id: None,
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
                .expect("utxo hash");
            indexer.add_utxo(utxo_hash);
            inputs.push(SpendUtxo::from((utxo, &sender)));
        }

        // The plan derives the merged output and owner identity; converting it to a
        // PreparedMerge pads to MERGE_INPUTS, and into_prover folds in the proofs.
        // The prover never sees the high-level plan.
        let merge = Merge::new(&sender, inputs)
            .expect("build merge plan")
            .with_expiry(0);
        let prepared = PreparedMerge::from(merge);
        let commitments = prepared.input_commitments().expect("input commitments");
        let proofs = indexer
            .get_input_merkle_proofs(&commitments)
            .expect("merkle proofs");
        let result = prepared
            .into_prover(&proofs)
            .expect("merge prover")
            .build()
            .expect("build merge proof");

        let proof = ProverClient::local()
            .prove_merge(&result.inputs)
            .expect("prove merge");
        let commitment = proof
            .commitment
            .expect("merge proof must carry a BSB22 commitment");
        let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof.a,
            &proof.b,
            &proof.c,
            &commitment.commitment,
            &commitment.commitment_pok,
            &public_inputs,
            &merge_8_1::VERIFYINGKEY,
        )
        .expect("construct verifier");
        verifier.verify().expect("merge groth16 proof verifies");

        // Owner decrypts the published ciphertext with their viewing key and
        // reconstructs the merged UTXO purely from the recovered fields, proving
        // the verifiable encryption yields a spendable output.
        let recovered = sender
            .decrypt_merge(&result.tx_viewing_pk, &result.ciphertext)
            .expect("decrypt merge ciphertext");
        assert_eq!(recovered.len(), 8 + 32 + 31, "merge plaintext length");
        let amount = u64::from_be_bytes(recovered[0..8].try_into().unwrap());
        let recovered_asset: [u8; 32] = recovered[8..40].try_into().unwrap();
        let blinding: [u8; 31] = recovered[40..71].try_into().unwrap();
        assert_eq!(
            recovered_asset,
            asset_field(&asset).expect("asset field"),
            "recovered asset field",
        );
        let reconstructed = OutputUtxo {
            owner_hash: sender.owner_hash().expect("owner hash"),
            asset,
            amount,
            blinding,
            zone_program_id: None,
            zone_data_hash: None,
            program_data_hash: None,
        };
        assert_eq!(
            reconstructed.hash().expect("reconstructed utxo hash"),
            result.output_hash,
            "owner reconstructs the merged output from the ciphertext",
        );
    }
}

fn start_prover() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}
