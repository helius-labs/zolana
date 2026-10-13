use zolana_keypair::{
    constants::BLINDING_LEN,
    derivation::{
        ed25519_derivation_message, DST_DERIVE_P_DERIVE, DST_PDA_ROOT_P_PDA, DST_VIEW_ROOT_P_CONST,
        ED25519_DERIVATION_MSG, P_CONST_SEC1, P_DERIVE_SEC1, P_PDA_SEC1,
    },
    KeypairError, NullifierKey, P256Pubkey, ShieldedKeypair, SigningKey,
};

use crate::KeypairWorld;

fn dalek_sign(secret: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;

    ed25519_dalek::SigningKey::from_bytes(secret)
        .sign(message)
        .to_bytes()
}

fn dalek_derivation_seed(secret: &[u8; 32]) -> [u8; 64] {
    let pubkey = ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes();
    dalek_sign(secret, &ed25519_derivation_message(&pubkey))
}

pub(crate) fn expand_nullifier_secret(seed: &[u8], info: &[u8]) -> [u8; BLINDING_LEN] {
    let mut secret = [0u8; BLINDING_LEN];
    hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
        .expand(info, &mut secret)
        .unwrap();
    secret
}

pub(crate) fn expand_viewing_pubkey(seed: &[u8], info: &[u8]) -> P256Pubkey {
    use p256::elliptic_curve::hash2curve::FromOkm;

    let mut okm = [0u8; 48];
    hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
        .expand(info, &mut okm)
        .unwrap();
    #[allow(deprecated)]
    let scalar = p256::Scalar::from_okm(p256::elliptic_curve::generic_array::GenericArray::<
        u8,
        p256::elliptic_curve::generic_array::typenum::U48,
    >::from_slice(&okm));
    let nonzero = p256::NonZeroScalar::new(scalar).unwrap();
    P256Pubkey::from_p256(&p256::SecretKey::from(nonzero).public_key())
}

/// Every committed point is regenerated from its own DST, so a substituted
/// point with a known discrete log fails here rather than silently rooting a
/// forged identity: `P_derive` stays reserved from the retired P-256 rail, `P_pda`
/// roots every single-holder PDA identity, and `P_const` roots `view_root` and
/// with it every view tag and the transaction-viewing secret.
pub(crate) fn committed_points_match_dsts() {
    use p256::{
        elliptic_curve::{
            hash2curve::{ExpandMsgXmd, GroupDigest},
            sec1::ToEncodedPoint,
        },
        NistP256,
    };
    use sha2::Sha256;

    let committed = [
        ("P_derive", DST_DERIVE_P_DERIVE, P_DERIVE_SEC1),
        ("P_const", DST_VIEW_ROOT_P_CONST, P_CONST_SEC1),
        ("P_pda", DST_PDA_ROOT_P_PDA, P_PDA_SEC1),
    ];

    for (name, dst, sec1) in committed {
        let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[b""], &[dst]).unwrap();
        assert_eq!(
            point.to_affine().to_encoded_point(true).as_bytes(),
            sec1,
            "{name} does not match its DST",
        );
    }

    for (index, (name, _, point)) in committed.iter().enumerate() {
        for (other_name, _, other) in committed.iter().skip(index + 1) {
            assert_ne!(point, other, "{name} and {other_name} collide");
        }
    }
}

pub(crate) fn derivation_seed_matches_rail_primitives() {
    let ed = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    assert_eq!(
        ed.derivation_seed().unwrap().as_slice(),
        dalek_derivation_seed(&[7u8; 32])
    );
    assert_ne!(
        ed.derivation_seed().unwrap().as_slice(),
        dalek_sign(&[7u8; 32], ED25519_DERIVATION_MSG)
    );
}

pub(crate) fn ed25519_rail_matches_signature_entry_point() {
    let sig = dalek_derivation_seed(&[7u8; 32]);
    let device_secret = expand_nullifier_secret(&sig, b"TSPP/nf_key/ed25519/v1");
    let software =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32])).unwrap();
    assert_eq!(device_secret, *software.nullifier_key.secret());
}

pub(crate) fn solana_keypair_matches_ed25519_rail() {
    let solana = solana_keypair::Keypair::new_from_array([7u8; 32]);
    let via_solana = ShieldedKeypair::from_keypair(&solana).unwrap();
    let via_signing =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32])).unwrap();
    assert_eq!(
        *via_solana.nullifier_key.secret(),
        *via_signing.nullifier_key.secret()
    );
    assert_eq!(
        via_solana.viewing_key.pubkey(),
        via_signing.viewing_key.pubkey()
    );
    assert_eq!(via_solana.signing_pubkey(), via_signing.signing_pubkey());
}

pub(crate) fn ed25519_keypair_derives_both_keys_from_one_signature() {
    let signing = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    let sig = dalek_derivation_seed(&[7u8; 32]);
    let kp = ShieldedKeypair::from_keypair(signing).unwrap();
    assert_eq!(
        kp.viewing_key.pubkey(),
        expand_viewing_pubkey(&sig, b"TSPP/view_key/ed25519/v1")
    );
    assert_eq!(
        *kp.nullifier_key.secret(),
        expand_nullifier_secret(&sig, b"TSPP/nf_key/ed25519/v1")
    );
}

pub(crate) fn primitives_refuse_derivation_inputs() {
    let ed = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    assert_eq!(
        ed.sign_message(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        ed.sign_message(&ed25519_derivation_message(&[7u8; 32])),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        ed.sign_message(b"TSPP/derive/pda/v1/x"),
        Err(KeypairError::DerivationInput)
    );
    assert!(ed.sign_message(b"benign message").is_ok());

    let mut prefixed_digest = [0u8; 32];
    prefixed_digest[..12].copy_from_slice(b"TSPP/derive/");
    assert_eq!(
        ed.sign_message(&prefixed_digest),
        Err(KeypairError::DerivationInput)
    );

    let p_derive = P256Pubkey::from_bytes(P_DERIVE_SEC1).unwrap();
    let p_pda = P256Pubkey::from_bytes(P_PDA_SEC1).unwrap();
    let p_const = P256Pubkey::from_bytes(P_CONST_SEC1).unwrap();
    let benign = zolana_keypair::ViewingKey::new().pubkey();
    let vk = zolana_keypair::ViewingKey::new();
    assert_eq!(vk.ecdh(&p_derive), Err(KeypairError::DerivationInput));
    assert_eq!(vk.ecdh(&p_pda), Err(KeypairError::DerivationInput));
    assert_eq!(vk.ecdh(&p_const), Err(KeypairError::DerivationInput));
    assert!(vk.ecdh(&benign).is_ok());
}

pub(crate) fn nullifier_deterministic(world: &mut KeypairWorld, key: String) {
    let a = ShieldedKeypair::from_keypair(world.sig_key(&key).clone()).unwrap();
    let b = ShieldedKeypair::from_keypair(world.sig_key(&key).clone()).unwrap();
    assert_eq!(*a.nullifier_key.secret(), *b.nullifier_key.secret());
    assert_eq!(
        a.nullifier_key.pubkey().unwrap(),
        b.nullifier_key.pubkey().unwrap()
    );
    assert_eq!(a.viewing_key.pubkey(), b.viewing_key.pubkey());
}

pub(crate) fn distinct_nullifier_secrets(world: &mut KeypairWorld, a: String, b: String) {
    let na = ShieldedKeypair::from_keypair(world.sig_key(&a).clone()).unwrap();
    let nb = ShieldedKeypair::from_keypair(world.sig_key(&b).clone()).unwrap();
    assert_ne!(*na.nullifier_key.secret(), *nb.nullifier_key.secret());
}

pub(crate) fn nullifier_binds_inputs() {
    let nk = NullifierKey::from_secret([9u8; BLINDING_LEN]);
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];
    let b1 = [3u8; 32];
    let b2 = [4u8; 32];
    let base = nk.nullifier(&h1, &b1).unwrap();
    assert_eq!(base, nk.nullifier(&h1, &b1).unwrap());
    assert_ne!(base, nk.nullifier(&h2, &b1).unwrap());
    assert_ne!(base, nk.nullifier(&h1, &b2).unwrap());
    let other = NullifierKey::from_secret([8u8; BLINDING_LEN]);
    assert_ne!(base, other.nullifier(&h1, &b1).unwrap());
}

pub(crate) fn nullifier_pubkey_golden(fill: u8, expected: String) {
    let nk = NullifierKey::from_secret([fill; BLINDING_LEN]);
    assert_eq!(hex::encode(nk.pubkey().unwrap()), expected);
}
