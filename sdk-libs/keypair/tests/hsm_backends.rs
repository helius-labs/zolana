mod hsm;

use hsm::{
    codec,
    kms::{ed25519_client, ed25519_client_failing_after_bootstrap, KmsShieldedKeypair, KEY_ID},
    kms_p256::{
        p256_client, p256_client_high_s, KmsP256ShieldedKeypair, P256Roots, P256Rules,
        NULLIFIER_KEY_ID, SIGN_KEY_ID, VIEWING_KEY_ID,
    },
};
use zolana_keypair::{
    derivation::{ed25519_derivation_message, ED25519_DERIVATION_MSG, P_DERIVE_SEC1},
    hash, CompressedShieldedAddress, Curve, KeypairError, NullifierKey, P256Pubkey,
    ShieldedAddress, ShieldedKeypair, ShieldedKeypairTrait, SigningKey, ViewingKey,
};

const SECRET: [u8; 32] = [11u8; 32];

const P256_ROOTS: P256Roots = P256Roots {
    sign: [21u8; 32],
    viewing: [22u8; 32],
    nullifier: [23u8; 32],
};

fn p256_bootstrap(client: aws_sdk_kms::Client) -> KmsP256ShieldedKeypair {
    KmsP256ShieldedKeypair::bootstrap(client, SIGN_KEY_ID, VIEWING_KEY_ID, NULLIFIER_KEY_ID)
}

fn p256_reference_nullifier_key() -> NullifierKey {
    ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&P256_ROOTS.nullifier).unwrap())
        .unwrap()
        .nullifier_key
}

fn assert_bootstrap_counts(rules: &P256Rules) {
    assert_eq!(rules.get_public_key_sign.num_calls(), 1);
    assert_eq!(rules.get_public_key_viewing.num_calls(), 1);
    assert_eq!(rules.get_public_key_nullifier.num_calls(), 0);
    assert_eq!(rules.derive_nullifier.num_calls(), 1);
    assert_eq!(rules.derive_viewing.num_calls(), 0);
    assert_eq!(rules.sign_usage_violation.num_calls(), 0);
    assert_eq!(rules.derive_usage_violation.num_calls(), 0);
}

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

    assert_eq!(kms.sign_hash(&[7u8; 32]), Err(KeypairError::NotP256));
    assert_eq!(rules.sign.num_calls(), 2);
}

#[test]
fn p256_spki_codec_round_trips_and_decompresses_p_derive() {
    let pubkey = ViewingKey::new().pubkey();
    let spki = codec::spki_from_p256(&pubkey);
    assert_eq!(codec::p256_from_spki(&spki), pubkey);

    let p_derive = P256Pubkey::from_bytes(P_DERIVE_SEC1).unwrap();
    let spki = codec::spki_from_p256(&p_derive);
    assert_eq!(spki.len(), 91);
    assert!(spki.starts_with(&codec::P256_SPKI_PREFIX));
    assert_eq!(spki.get(26), Some(&0x04));
}

#[test]
fn p256_der_codec_normalizes_forced_high_s() {
    use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};

    let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let digest = [7u8; 32];
    let signature: p256::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();

    let der_high = codec::der_from_compact_high_s(&signature.to_bytes().into());
    let high = p256::ecdsa::Signature::from_der(&der_high).unwrap();
    assert!(high.normalize_s().is_some());

    let compact = codec::compact_low_s_from_der(&der_high);
    let low = p256::ecdsa::Signature::from_slice(&compact).unwrap();
    assert!(low.normalize_s().is_none());
    assert!(p256::ecdsa::VerifyingKey::from(&signing)
        .verify_prehash(&digest, &low)
        .is_ok());
}

#[test]
fn kms_p256_backend_matches_software_parts() {
    let (client, rules) = p256_client(&P256_ROOTS);
    let kms = p256_bootstrap(client);
    assert_bootstrap_counts(&rules);
    assert_eq!(rules.sign.num_calls(), 0);

    let sign_software = SigningKey::from_p256_bytes(&P256_ROOTS.sign).unwrap();
    let viewing_software = ViewingKey::from_bytes(&P256_ROOTS.viewing).unwrap();
    let nullifier_reference = p256_reference_nullifier_key();

    assert_eq!(kms.signing_pubkey(), sign_software.pubkey());
    assert_eq!(kms.viewing_pubkey(), viewing_software.pubkey());
    assert_eq!(kms.curve(), Curve::P256);
    assert_eq!(*kms.nullifier_key().secret(), *nullifier_reference.secret());
    assert_eq!(
        kms.nullifier_pubkey().unwrap(),
        nullifier_reference.pubkey().unwrap()
    );

    let expected_owner_hash = hash::owner_hash(
        &sign_software.pubkey(),
        &nullifier_reference.pubkey().unwrap(),
    )
    .unwrap();
    assert_eq!(kms.owner_hash().unwrap(), expected_owner_hash);
    assert_eq!(
        kms.shielded_address().unwrap(),
        ShieldedAddress {
            signing_pubkey: sign_software.pubkey(),
            nullifier_pubkey: nullifier_reference.pubkey().unwrap(),
            viewing_pubkey: viewing_software.pubkey(),
        }
    );
    assert_eq!(
        kms.compressed_address().unwrap(),
        CompressedShieldedAddress {
            owner_hash: expected_owner_hash,
            viewing_pubkey: viewing_software.pubkey(),
        }
    );

    let utxo_hash = [1u8; 32];
    let blinding = [2u8; 32];
    assert_eq!(
        kms.nullifier(&utxo_hash, &blinding).unwrap(),
        nullifier_reference
            .nullifier(&utxo_hash, &blinding)
            .unwrap()
    );

    assert_bootstrap_counts(&rules);
    assert_eq!(rules.sign.num_calls(), 0);
}

#[test]
fn kms_p256_backend_signs_prehash() {
    let (client, rules) = p256_client(&P256_ROOTS);
    let kms = p256_bootstrap(client);
    let sign_software = SigningKey::from_p256_bytes(&P256_ROOTS.sign).unwrap();

    let digest = hash::sha256(b"private tx hash binding");
    let signature = kms.sign_hash(&digest).unwrap();
    assert_eq!(rules.sign.num_calls(), 1);

    assert_eq!(signature, sign_software.sign_hash(&digest).unwrap());

    let parsed = p256::ecdsa::Signature::from_slice(&signature).unwrap();
    assert!(parsed.normalize_s().is_none());
    assert!(kms.signing_pubkey().verify_hash(&digest, &signature));

    assert_eq!(kms.sign_hash(&digest).unwrap(), signature);
    assert_eq!(rules.sign.num_calls(), 2);

    let mut prefixed_digest = [0u8; 32];
    prefixed_digest[..12].copy_from_slice(b"TSPP/derive/");
    assert_eq!(
        kms.sign_hash(&prefixed_digest),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(rules.sign.num_calls(), 2);

    let message = b"registry binding";
    let message_signature = kms.sign_message(message).unwrap();
    assert_eq!(rules.sign.num_calls(), 3);
    assert!(kms
        .signing_pubkey()
        .verify_message(message, &message_signature));
    assert_eq!(
        kms.sign_message(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(rules.sign.num_calls(), 3);
}

#[test]
fn kms_p256_backend_normalizes_high_s() {
    let (client, rules) = p256_client_high_s(&P256_ROOTS);
    let kms = p256_bootstrap(client);

    let digest = hash::sha256(b"high-s device signature");
    let signature = kms.sign_hash(&digest).unwrap();
    assert_eq!(rules.sign.num_calls(), 1);

    let parsed = p256::ecdsa::Signature::from_slice(&signature).unwrap();
    assert!(parsed.normalize_s().is_none());
    assert!(kms.signing_pubkey().verify_hash(&digest, &signature));

    let sign_software = SigningKey::from_p256_bytes(&P256_ROOTS.sign).unwrap();
    assert_eq!(signature, sign_software.sign_hash(&digest).unwrap());
}

#[test]
fn kms_p256_single_key_rail_is_blocked() {
    use aws_sdk_kms::{
        operation::{derive_shared_secret::DeriveSharedSecretError, sign::SignError},
        primitives::Blob,
        types::{KeyAgreementAlgorithmSpec, MessageType, SigningAlgorithmSpec},
    };

    let (client, rules) = p256_client(&P256_ROOTS);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();

    let p_derive = P256Pubkey::from_bytes(P_DERIVE_SEC1).unwrap();
    let derive_error = runtime
        .block_on(
            client
                .derive_shared_secret()
                .key_id(SIGN_KEY_ID)
                .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
                .public_key(Blob::new(codec::spki_from_p256(&p_derive)))
                .send(),
        )
        .unwrap_err()
        .into_service_error();
    assert!(matches!(
        derive_error,
        DeriveSharedSecretError::InvalidKeyUsageException(_)
    ));
    assert_eq!(rules.derive_usage_violation.num_calls(), 1);

    let sign_error = runtime
        .block_on(
            client
                .sign()
                .key_id(NULLIFIER_KEY_ID)
                .message(Blob::new([5u8; 32].to_vec()))
                .message_type(MessageType::Digest)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .send(),
        )
        .unwrap_err()
        .into_service_error();
    assert!(matches!(sign_error, SignError::InvalidKeyUsageException(_)));
    assert_eq!(rules.sign_usage_violation.num_calls(), 1);
    assert_eq!(rules.derive_nullifier.num_calls(), 0);
    assert_eq!(rules.sign.num_calls(), 0);
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
