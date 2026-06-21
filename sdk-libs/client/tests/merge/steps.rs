//! Merge step definitions: build N real inputs (padded to 8 with dummies) sharing
//! one owner, consolidate them into one output, prove on the merge_8_1 circuit,
//! and verify against the committed merge verifying key.

use std::sync::Once;

use cucumber::{given, then};
use groth16_solana::groth16::Groth16Verifier;
use p256::SecretKey;
use solana_address::Address;
use zolana_client::private_transaction::field::asset_field;
use zolana_client::{
    spawn_prover, InputCommitment, MergeProver, ProverClient, Rpc, TransferSpendInput,
};
use zolana_interface::verifying_keys::merge_8_1;
use zolana_keypair::{random_blinding, ShieldedKeypair};
use zolana_transaction::{Data, OutputUtxo, Utxo};

use crate::test_indexer::TestIndexer;
use crate::world::MergeWorld;

const MERGE_INPUTS: usize = 8;

#[given(expr = "{int} P256 SOL inputs to merge")]
fn given_inputs(world: &mut MergeWorld, n: usize) {
    world.plan.real_inputs = n;
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

        let sender = ShieldedKeypair::new().expect("sender keypair");
        let asset = Address::default(); // SOL
        let owner = sender.signing_pubkey();
        let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pk");

        // Real inputs: index each UTXO into the state tree so its inclusion and
        // nullifier non-inclusion proofs can be served.
        let mut indexer = TestIndexer::new();
        let mut real_utxos = Vec::with_capacity(n);
        let mut commitments = Vec::with_capacity(n);
        let mut total: u64 = 0;
        for i in 0..n {
            let amount = 100 + i as u64;
            total += amount;
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
            let nullifier = sender
                .nullifier_key
                .nullifier(&utxo_hash, &utxo.blinding)
                .expect("nullifier");
            indexer.add_utxo(utxo_hash);
            commitments.push(InputCommitment {
                index: i,
                utxo_hash,
                nullifier,
            });
            real_utxos.push(utxo);
        }
        let proofs = indexer
            .get_input_merkle_proofs(&commitments)
            .expect("merkle proofs");

        let mut inputs: Vec<TransferSpendInput> = real_utxos
            .into_iter()
            .zip(proofs)
            .map(|(utxo, proof)| TransferSpendInput {
                utxo,
                nullifier_key: sender.nullifier_key.clone(),
                proof: Some(proof),
            })
            .collect();
        while inputs.len() < MERGE_INPUTS {
            inputs.push(TransferSpendInput {
                utxo: Utxo {
                    owner,
                    asset,
                    amount: 0,
                    blinding: random_blinding(),
                    zone_program_id: None,
                    data: Data::default(),
                },
                nullifier_key: sender.nullifier_key.clone(),
                proof: None,
            });
        }

        let output = OutputUtxo {
            owner_hash: sender.owner_hash().expect("owner hash"),
            asset,
            amount: total,
            blinding: random_blinding(),
            zone_program_id: None,
            zone_data_hash: None,
            program_data_hash: None,
        };

        // Ephemeral tx viewing scalar: 31 random bytes are < BN254 modulus, so the
        // value is a valid circuit witness as well as a P-256 scalar.
        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk = SecretKey::from_slice(&sk_bytes).expect("valid scalar");

        let result = MergeProver {
            inputs,
            output,
            external_data_hash: [0u8; 32],
            signing_pubkey: owner.as_p256().expect("p256 signing pubkey"),
            nullifier_key: sender.nullifier_key.clone(),
            user_viewing_pk: sender.viewing_pubkey(),
            tx_viewing_sk,
        }
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
