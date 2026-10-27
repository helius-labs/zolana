mod hsm;

use hsm::kms::{
    ed25519_client, ed25519_client_failing_after_bootstrap, KmsShieldedKeypair, KEY_ID,
};
use spr_keypair::{
    derivation::{ed25519_derivation_message, ED25519_DERIVATION_MSG},
    Curve, KeypairError, ShieldedKeypair, ShieldedKeypairTrait, SigningKey,
};

const SECRET: [u8; 32] = [11u8; 32];

fn software_keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&SECRET))
        .expect("software keypair")
}

#[test]
fn kms_backend_matches_software_keypair() {
    let (client, rules) = ed25519_client(&SECRET);
    let kms = KmsShieldedKeypair::bootstrap(client, KEY_ID);
    assert_eq!(rules.get_public_key.num_calls(), 1);
    assert_eq!(rules.sign.num_calls(), 1);

    let software = software_keypair();
    assert_eq!(kms.signing_pubkey(), software.signing_pubkey());
    assert_eq!(kms.viewing_pubkey(), software.viewing_pubkey());
    assert_eq!(kms.curve(), Curve::Ed25519);
    assert_eq!(
        kms.shielded_address().unwrap(),
        software.shielded_address().unwrap()
    );
    assert_eq!(kms.owner_hash().unwrap(), software.owner_hash().unwrap());
    assert_eq!(
        kms.compressed_address().unwrap(),
        software.compressed_address().unwrap()
    );
    assert_eq!(
        *kms.nullifier_key().secret(),
        *software.nullifier_key.secret()
    );
    assert_eq!(
        kms.nullifier_pubkey().unwrap(),
        software.nullifier_key.pubkey().unwrap()
    );

    let utxo_hash = [1u8; 32];
    let blinding = [2u8; 32];
    assert_eq!(
        kms.nullifier(&utxo_hash, &blinding).unwrap(),
        software.nullifier(&utxo_hash, &blinding).unwrap()
    );

    assert_eq!(rules.get_public_key.num_calls(), 1);
    assert_eq!(rules.sign.num_calls(), 1);
}

#[test]
fn kms_backend_signs_like_software_and_guards_derivation_inputs() {
    let (client, rules) = ed25519_client(&SECRET);
    let kms = KmsShieldedKeypair::bootstrap(client, KEY_ID);
    let software = software_keypair();

    let msg = b"private tx hash binding";
    let signature = kms.sign_message(msg).unwrap();
    assert_eq!(signature, software.sign_message(msg).unwrap());
    assert!(kms.signing_pubkey().verify_message(msg, &signature));
    assert_eq!(rules.sign.num_calls(), 2);

    let signer = software.signing_pubkey().as_ed25519().unwrap();
    assert_eq!(
        kms.sign_message(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        kms.sign_message(&ed25519_derivation_message(&signer)),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(rules.sign.num_calls(), 2);
}

#[test]
fn kms_sign_failure_surfaces_as_signing_failed() {
    let client = ed25519_client_failing_after_bootstrap(&SECRET);
    let kms = KmsShieldedKeypair::bootstrap(client, KEY_ID);
    assert_eq!(
        kms.owner_hash().unwrap(),
        software_keypair().owner_hash().unwrap()
    );
    assert_eq!(
        kms.sign_message(b"benign message"),
        Err(KeypairError::SigningFailed)
    );
}
