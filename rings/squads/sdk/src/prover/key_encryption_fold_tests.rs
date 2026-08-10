//! End-to-end key-encryption fold test: six recipient keys, more than any
//! unfolded circuit proves, split across two legs and folded into one proof.
//!
//! The fold is verified on the host against the committed fold verifying key
//! using the public-input hash the on-chain program recomputes.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::verifying_keys::key_encryption_fold_3_l2;

use crate::prover::{
    key_encryption_fold::{
        KeyEncryptionFoldProofInputs, KeyEncryptionFoldProofResult,
        KEY_ENCRYPTION_FOLD_KEYS_PER_LEG,
    },
    viewing_key_account::create_viewing_key_account_ix_data_folded,
};

fn prover_url() -> String {
    std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| SERVER_ADDRESS.to_string())
}

/// Point the spawned prover at the repo's proving keys, so the test uses the
/// keys the committed verifying-key constants were generated from.
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

fn random_bn254_scalar() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0; // < 2^248 < BN254 modulus.
    b
}

/// Host verification of the folded proof, mirroring the program's
/// `verify_groth16` against the key `select_key_encryption_vk(6)` picks.
fn verify_on_host(result: &KeyEncryptionFoldProofResult, public_input_hash: [u8; 32]) -> bool {
    let proof = &result.proof;
    let vk = &key_encryption_fold_3_l2::VERIFYINGKEY;
    assert!(
        vk.vk_commitment.is_some(),
        "the fold must be the BSB22 rail",
    );

    let proof_a = decompress_g1(&to32(&proof[0..32])).expect("decompress a");
    let proof_b = decompress_g2(&to64(&proof[32..96])).expect("decompress b");
    let proof_c = decompress_g1(&to32(&proof[96..128])).expect("decompress c");
    let commitment = decompress_g1(&to32(&proof[128..160])).expect("decompress commitment");
    let commitment_pok = decompress_g1(&to32(&proof[160..192])).expect("decompress pok");

    let public_inputs = [public_input_hash];
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

#[test]
fn a_wider_key_set_than_any_leg_proves_is_provable() {
    start_prover();

    // Six keys, twice what the widest unfolded circuit proves.
    let keys: Vec<P256Pubkey> = (0..2 * KEY_ENCRYPTION_FOLD_KEYS_PER_LEG)
        .map(|_| P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key()))
        .collect();

    let result = KeyEncryptionFoldProofInputs {
        viewing_secret_key: SecretKey::random(&mut OsRng),
        ephemeral_secret_key: SecretKey::random(&mut OsRng),
        nullifier_secret: random_bn254_scalar(),
        recipient_keys: keys.clone(),
        old_state_hash: [0u8; 32],
    }
    .prove(&prover_url())
    .expect("fold proof generation must succeed");

    assert_eq!(result.recipient_ciphertexts.len(), keys.len());
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            result.recipient_ciphertexts[index]
                .recipient_pubkey
                .as_bytes(),
            key.as_bytes(),
            "recipient {index} kept its caller order across the legs",
        );
        assert_eq!(result.recipient_ciphertexts[index].ciphertext.len(), 32);
    }
    assert_eq!(result.nullifier_ciphertext.len(), 31);

    assert!(
        verify_on_host(&result, result.public_input_hash),
        "host Groth16 verification of the folded proof failed",
    );

    let mut tampered = result.public_input_hash;
    tampered[31] ^= 1;
    assert!(
        !verify_on_host(&result, tampered),
        "verification must fail for a tampered public input",
    );

    let ix_data = create_viewing_key_account_ix_data_folded(&result, keys.len() - 1)
        .expect("instruction data must build");
    assert_eq!(ix_data.recovery_keys.len(), keys.len() - 1);
    assert_eq!(ix_data.key_ciphertexts.len(), keys.len());
}
