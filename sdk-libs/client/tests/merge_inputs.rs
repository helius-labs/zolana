#[path = "common/input.rs"]
mod input_fixture;
#[path = "test_indexer.rs"]
mod test_indexer;

use input_fixture::wallet_utxo;
use num_bigint::BigUint;
use test_indexer::TestIndexer;
use zolana_client::{
    prover::MergeEnvelopeInputs, ClientError, CompressedCommitments, MergeProofResult, MergeProver,
    ProofCompressed, Rpc,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::merge::{MergeProofInputs, MergeTransaction},
    Data, Mint, Utxo,
};

const TREE_ID: u16 = 0;

fn prove_default_merge(sender: &ShieldedKeypair) -> (MergeProofInputs, MergeProofResult) {
    let owner = sender.signing_pubkey();
    let nullifier_pk = sender.nullifier_key.pubkey().expect("nullifier pk");
    let mut indexer = TestIndexer::new();
    let inputs = (0..2)
        .map(|_| {
            let utxo = Utxo {
                owner,
                asset: Mint::SOL,
                amount: 100,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TREE_ID)
                .expect("utxo hash");
            let leaf_index = indexer.add_utxo(utxo_hash);
            wallet_utxo(utxo, &sender.nullifier_key, TREE_ID, leaf_index, None, None)
        })
        .collect();
    let prepared = MergeTransaction::new(inputs)
        .expect("build merge")
        .encrypt(sender)
        .expect("encrypt merge");
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
        transaction: prepared.clone(),
        nullifier_key: sender.nullifier_key.clone(),
        proofs,
        dummy_nullifier_proofs,
        cache: None,
    }
    .build()
    .expect("build merge proof inputs");
    (prepared, result)
}

fn renderings(secret: &[u8; 32]) -> [String; 3] {
    [
        secret.iter().map(|byte| format!("{byte:02x}")).collect(),
        format!("{secret:?}"),
        BigUint::from_bytes_be(secret).to_string(),
    ]
}

#[test]
fn merge_proof_inputs_and_instruction_carry_the_one_encrypted_envelope() {
    let sender = ShieldedKeypair::new_p256().expect("sender keypair");
    let (prepared, result) = prove_default_merge(&sender);
    let encrypted = *prepared
        .encrypted_envelope()
        .expect("default merge envelope");
    assert_eq!(result.envelope, Some(encrypted));

    let envelope_inputs = result.inputs.envelope.as_ref().expect("envelope inputs");
    let ephemeral = ViewingKey::from_bytes(&envelope_inputs.ephemeral_sk).expect("ephemeral key");
    assert_eq!(*ephemeral.pubkey().as_bytes(), encrypted.ephemeral_pk);

    let data = result
        .instruction_data(ProofCompressed {
            a: [0; 32],
            b: [0; 128],
            c: [0; 32],
            commitment: Some(CompressedCommitments {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            }),
        })
        .expect("merge instruction data");
    assert_eq!(
        (data.envelope.ephemeral_pk, data.envelope.ciphertext),
        (encrypted.ephemeral_pk, encrypted.ciphertext)
    );
}

#[test]
fn default_merge_instruction_data_moves_the_commitment_into_the_proof_commitment() {
    let sender = ShieldedKeypair::new_p256().expect("sender keypair");
    let (_, result) = prove_default_merge(&sender);

    let data = result
        .instruction_data(ProofCompressed {
            a: [1; 32],
            b: [2; 128],
            c: [3; 32],
            commitment: Some(CompressedCommitments {
                commitment: [4; 32],
                commitment_pok: [5; 32],
            }),
        })
        .expect("merge instruction data");

    assert_eq!(
        (data.body.proof.a, data.body.proof.b, data.body.proof.c),
        ([1; 32], [2; 128], [3; 32])
    );
    assert_eq!(
        (
            data.proof_commitment.commitment,
            data.proof_commitment.commitment_pok
        ),
        ([4; 32], [5; 32])
    );
}

#[test]
fn default_merge_instruction_data_rejects_a_proof_without_a_commitment() {
    let sender = ShieldedKeypair::new_p256().expect("sender keypair");
    let (_, result) = prove_default_merge(&sender);

    let error = result
        .instruction_data(ProofCompressed {
            a: [1; 32],
            b: [2; 128],
            c: [3; 32],
            commitment: None,
        })
        .expect_err("a default merge proof needs its BSB22 commitment");

    assert!(
        matches!(&error, ClientError::ProofParse(message) if message.contains("missing its BSB22 commitment")),
        "unexpected error: {error:?}"
    );
}

#[test]
fn merge_proof_inputs_debug_redacts_every_secret() {
    let sender = ShieldedKeypair::new_p256().expect("sender keypair");
    let (_, result) = prove_default_merge(&sender);
    let ephemeral_sk = *result
        .inputs
        .envelope
        .as_ref()
        .expect("envelope inputs")
        .ephemeral_sk;
    let mut nullifier_secret = [0u8; 32];
    let secret = sender.nullifier_key.secret();
    nullifier_secret
        .get_mut(32 - secret.len()..)
        .expect("nullifier secret fits a field")
        .copy_from_slice(&*secret);

    let rendered = format!("{result:?}");
    assert!(rendered.contains("<redacted>"));
    for secret in [ephemeral_sk, nullifier_secret] {
        for leaked in renderings(&secret) {
            assert!(
                !rendered.contains(&leaked),
                "Debug output leaks a secret as {leaked}"
            );
        }
    }
}

#[test]
fn merge_envelope_inputs_debug_redacts_the_ephemeral_secret() {
    let secret = [0xab; 32];
    let inputs = MergeEnvelopeInputs {
        viewing_pk: [4; 65],
        ephemeral_sk: secret.into(),
    };
    let rendered = format!("{inputs:?}");
    assert_eq!(
        rendered,
        format!(
            "MergeEnvelopeInputs {{ viewing_pk: {:?}, ephemeral_sk: <redacted> }}",
            [4u8; 65]
        )
    );
    for leaked in renderings(&secret) {
        assert!(!rendered.contains(&leaked));
    }
}
