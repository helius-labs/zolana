//! End-to-end zone-proof tests. Build the proof inputs in Rust, get a real
//! Groth16 proof from the prover server, and verify it on the host against the
//! committed on-chain zone verifying key using the same public-input hash the
//! on-chain program computes (zones/squads/program/src/shared/zone_proof.rs).
//!
//! The first request for a shape lazy-loads its proving key.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::verifying_keys::{zone_1_1, zone_2_2};

use crate::prover::zone::{
    decrypt_sender_change, derive_change_blinding, derive_sender_artifacts, TransferOutputs,
    ZoneProofInputs, ZoneProofResult, ZoneRecipient, ZoneUtxo,
};

/// Reads `ZOLANA_PROVER_URL` like `spawn_prover` does, so `.prove(...)` targets
/// the same server it starts.
fn prover_url() -> String {
    std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| SERVER_ADDRESS.to_string())
}

/// Point the spawned prover at the repo's proving keys so the tests always use
/// the keys the committed verifying-key constants were generated from.
fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("prover server must be available");
}

/// A random BN254-range field element (top byte cleared so it is < the field
/// modulus and < the P-256 order). Used for nullifier secrets and blindings.
fn random_field() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

/// Host verification of the 192-byte BSB22 proof against `vk` and the SDK-computed
/// public input, mirroring the program's `verify_groth16`.
fn verify_on_host(
    proof_result: &ZoneProofResult,
    vk: &Groth16Verifyingkey,
    public_input: &[u8; 32],
) -> bool {
    assert!(vk.vk_commitment.is_some(), "zone vk must be the BSB22 rail");
    let proof = &proof_result.proof;
    let proof_a = decompress_g1(&to32(&proof[0..32])).expect("decompress a");
    let proof_b = decompress_g2(&to64(&proof[32..96])).expect("decompress b");
    let proof_c = decompress_g1(&to32(&proof[96..128])).expect("decompress c");
    let commitment = decompress_g1(&to32(&proof[128..160])).expect("decompress commitment");
    let commitment_pok = decompress_g1(&to32(&proof[160..192])).expect("decompress pok");

    let public_inputs = [*public_input];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        vk,
    )
    .expect("verifier construction");
    verifier.verify().is_ok()
}

fn to32(s: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(s);
    o
}

fn to64(s: &[u8]) -> [u8; 64] {
    let mut o = [0u8; 64];
    o.copy_from_slice(s);
    o
}

/// `nullifier_pubkey = Poseidon([nullifier_secret])` (view_key.go:54).
fn nullifier_pubkey(nullifier_secret: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[nullifier_secret.as_slice()]).expect("poseidon")
}

/// A plain input UTXO with the given amount. Its blinding is arbitrary (only the
/// first input's fields feed the KDF chain, but every input's hash is bound into
/// private_tx_hash). owner/nullifier are the sender's.
fn input_utxo(amount: u64, owner_key_hash: [u8; 32], nullifier_pk: [u8; 32]) -> ZoneUtxo {
    ZoneUtxo {
        owner_key_hash,
        nullifier_pubkey: nullifier_pk,
        asset: [0u8; 32],
        amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    }
}

/// A zeroed dummy input slot. Its fields never enter the fold (the circuit selects 0
/// for its input-hash slot), so only `is_dummy` matters. The random blinding shows
/// the remaining fields are free.
fn dummy_input_utxo() -> ZoneUtxo {
    ZoneUtxo {
        owner_key_hash: [0u8; 32],
        nullifier_pubkey: [0u8; 32],
        asset: [0u8; 32],
        amount: 0,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: true,
    }
}

#[test]
fn decrypt_sender_change_round_trips_withdrawal_artifacts() {
    let viewing = SecretKey::random(&mut OsRng);
    let nullifier_secret = random_field();
    let nullifier_pk = nullifier_pubkey(&nullifier_secret);
    let owner = random_field();
    let first_input = input_utxo(1000, owner, nullifier_pk);

    let change_amount = 300u64;
    let change_asset = random_field();
    let artifacts = derive_sender_artifacts(
        &viewing,
        &nullifier_secret,
        &first_input,
        change_amount,
        &change_asset,
    )
    .expect("derive sender artifacts");

    let (amount, asset, change_blinding) = decrypt_sender_change(
        &viewing,
        &nullifier_secret,
        &first_input,
        &artifacts.sender_ciphertext,
    )
    .expect("decrypt sender change");
    assert_eq!(amount, change_amount);
    assert_eq!(asset, change_asset);
    assert_eq!(change_blinding, artifacts.change_blinding);

    let wrong_input = input_utxo(999, owner, nullifier_pk);
    let (_, wrong_asset, _) = decrypt_sender_change(
        &viewing,
        &nullifier_secret,
        &wrong_input,
        &artifacts.sender_ciphertext,
    )
    .expect("decrypt with wrong input");
    assert_ne!(wrong_asset, change_asset);
}

#[test]
fn decrypt_sender_change_round_trips_transfer_artifacts() {
    let viewing = SecretKey::random(&mut OsRng);
    let nullifier_secret = random_field();
    let nullifier_pk = nullifier_pubkey(&nullifier_secret);
    let owner = random_field();
    let first_input = input_utxo(1000, owner, nullifier_pk);

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let change_amount = 600u64;
    let change_asset = random_field();
    let transferred = 400u64;
    let recipient_blinding = random_field();

    let artifacts = TransferOutputs {
        change_amount,
        change_asset: &change_asset,
        recipient_viewing_pubkey: &recipient_viewing,
        transferred_amount: transferred,
        transferred_asset: &change_asset,
        recipient_blinding: &recipient_blinding,
    }
    .derive(&viewing, &nullifier_secret, &first_input)
    .expect("derive transfer artifacts");

    let (amount, asset, change_blinding) = decrypt_sender_change(
        &viewing,
        &nullifier_secret,
        &first_input,
        &artifacts.sender_ciphertext,
    )
    .expect("decrypt sender change");
    assert_eq!(amount, change_amount);
    assert_eq!(asset, change_asset);
    assert_eq!(change_blinding, artifacts.change_blinding);
}

#[test]
fn zone_transfer_2_2_proof_verifies_end_to_end() {
    start_prover();

    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();

    let inputs = vec![
        input_utxo(700, sender_owner, sender_nullifier_pk),
        input_utxo(300, sender_owner, sender_nullifier_pk),
    ];

    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, &inputs[0])
            .expect("derive change blinding");
    let change_output = ZoneUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: [0u8; 32],
        amount: 600,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };
    let recipient_output = ZoneUtxo {
        owner_key_hash: recipient_owner,
        nullifier_pubkey: recipient_nullifier_pk,
        asset: [0u8; 32],
        amount: 400,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    let proof_inputs = ZoneProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output, recipient_output],
        external_data_hash: random_field(),
        recipient: Some(ZoneRecipient {
            owner_key_hash: recipient_owner,
            nullifier_pubkey: recipient_nullifier_pk,
            viewing_pubkey: recipient_viewing,
        }),
        proposal: None,
        public_amount: [0u8; 32],
    };

    let proof_result = proof_inputs
        .prove(&prover_url())
        .expect("proof generation must succeed");

    assert_eq!(proof_result.sender_ciphertext.len(), 40);
    assert_eq!(proof_result.recipient_ciphertext.len(), 71);
    assert!(proof_result.tx_viewing_pk.is_some());

    assert!(
        verify_on_host(
            &proof_result,
            &zone_2_2::VERIFYINGKEY,
            &proof_result.public_input_hash
        ),
        "host Groth16 verification of the (2,2) zone proof failed",
    );

    let mut tampered = proof_result.public_input_hash;
    tampered[1] ^= 1;
    assert!(
        !verify_on_host(&proof_result, &zone_2_2::VERIFYINGKEY, &tampered),
        "verification must fail for a tampered public input",
    );
}

#[test]
fn zone_transfer_2_2_with_dummy_input_proof_verifies_end_to_end() {
    start_prover();

    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();

    let inputs = vec![
        input_utxo(1000, sender_owner, sender_nullifier_pk),
        dummy_input_utxo(),
    ];

    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, &inputs[0])
            .expect("derive change blinding");
    let change_output = ZoneUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: [0u8; 32],
        amount: 600,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };
    let recipient_output = ZoneUtxo {
        owner_key_hash: recipient_owner,
        nullifier_pubkey: recipient_nullifier_pk,
        asset: [0u8; 32],
        amount: 400,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    let proof_inputs = ZoneProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output, recipient_output],
        external_data_hash: random_field(),
        recipient: Some(ZoneRecipient {
            owner_key_hash: recipient_owner,
            nullifier_pubkey: recipient_nullifier_pk,
            viewing_pubkey: recipient_viewing,
        }),
        proposal: None,
        public_amount: [0u8; 32],
    };

    let proof_result = proof_inputs
        .prove(&prover_url())
        .expect("proof generation must succeed");

    assert_eq!(proof_result.sender_ciphertext.len(), 40);
    assert_eq!(proof_result.recipient_ciphertext.len(), 71);
    assert!(proof_result.tx_viewing_pk.is_some());

    assert!(
        verify_on_host(
            &proof_result,
            &zone_2_2::VERIFYINGKEY,
            &proof_result.public_input_hash
        ),
        "host Groth16 verification of the dummy-input (2,2) zone proof failed",
    );

    let mut tampered = proof_result.public_input_hash;
    tampered[1] ^= 1;
    assert!(
        !verify_on_host(&proof_result, &zone_2_2::VERIFYINGKEY, &tampered),
        "verification must fail for a tampered public input",
    );
}

#[test]
fn zone_prove_rejects_dummy_first_input() {
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();

    let inputs = vec![
        dummy_input_utxo(),
        input_utxo(1000, sender_owner, sender_nullifier_pk),
    ];
    let change_output = input_utxo(600, sender_owner, sender_nullifier_pk);
    let recipient_output = input_utxo(400, recipient_owner, recipient_nullifier_pk);

    let proof_inputs = ZoneProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output, recipient_output],
        external_data_hash: random_field(),
        recipient: Some(ZoneRecipient {
            owner_key_hash: recipient_owner,
            nullifier_pubkey: recipient_nullifier_pk,
            viewing_pubkey: recipient_viewing,
        }),
        proposal: None,
        public_amount: [0u8; 32],
    };

    let err = match proof_inputs.prove(&prover_url()) {
        Ok(_) => panic!("dummy inputs[0] must be rejected"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err,
            crate::prover::error::SquadsProverError::DummyFirstInput
        ),
        "expected DummyFirstInput, got: {err}",
    );
}

#[test]
fn zone_withdrawal_1_1_proof_verifies_end_to_end() {
    start_prover();

    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let inputs = vec![input_utxo(1000, sender_owner, sender_nullifier_pk)];

    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, &inputs[0])
            .expect("derive change blinding");
    let change_output = ZoneUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: [0u8; 32],
        amount: 300,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    let mut public_amount = [0u8; 32];
    public_amount[24..32].copy_from_slice(&700u64.to_be_bytes());

    let proof_inputs = ZoneProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output],
        external_data_hash: random_field(),
        recipient: None,
        proposal: None,
        public_amount,
    };

    let proof_result = proof_inputs
        .prove(&prover_url())
        .expect("proof generation must succeed");

    assert_eq!(proof_result.sender_ciphertext.len(), 40);
    assert!(proof_result.recipient_ciphertext.is_empty());
    assert!(proof_result.tx_viewing_pk.is_none());

    assert!(
        verify_on_host(
            &proof_result,
            &zone_1_1::VERIFYINGKEY,
            &proof_result.public_input_hash
        ),
        "host Groth16 verification of the (1,1) zone proof failed",
    );

    let mut tampered = proof_result.public_input_hash;
    tampered[2] ^= 1;
    assert!(
        !verify_on_host(&proof_result, &zone_1_1::VERIFYINGKEY, &tampered),
        "verification must fail for a tampered public input",
    );
}
