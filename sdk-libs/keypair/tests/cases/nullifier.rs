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

fn p256_ecdh_x(secret: &[u8; 32], point_sec1: &[u8]) -> [u8; 32] {
    let sk = p256::SecretKey::from_slice(secret).unwrap();
    let pk = p256::PublicKey::from_sec1_bytes(point_sec1).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut x = [0u8; 32];
    x.copy_from_slice(shared.raw_secret_bytes());
    x
}

/// Every committed point is regenerated from its own DST, so a substituted
/// point with a known discrete log fails here rather than silently rooting a
/// forged identity: `P_derive` roots both role keys on the P-256 rail, `P_pda`
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

pub(crate) fn derivation_seed_matches_rail_primitives(world: &mut KeypairWorld, key: String) {
    let sk = world.sig_key(&key);
    assert_eq!(
        sk.derivation_seed().unwrap().as_slice(),
        p256_ecdh_x(&sk.secret_bytes(), &P_DERIVE_SEC1)
    );
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

pub(crate) fn p256_rail_matches_ecdh_entry_point(world: &mut KeypairWorld, key: String) {
    let sk = world.sig_key(&key);
    let shared_x = p256_ecdh_x(&sk.secret_bytes(), &P_DERIVE_SEC1);
    let device_secret = expand_nullifier_secret(&shared_x, b"TSPP/nf_key/ecdh/v1");
    let software = ShieldedKeypair::from_keypair(sk.clone()).unwrap();
    assert_eq!(device_secret, *software.nullifier_key.secret());
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

pub(crate) fn rails_differ_for_identical_root_bytes() {
    let root = [7u8; 32];
    let p256 = ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&root).unwrap()).unwrap();
    let ed25519 = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&root)).unwrap();
    assert_ne!(
        *p256.nullifier_key.secret(),
        *ed25519.nullifier_key.secret()
    );
    assert_ne!(p256.viewing_key.pubkey(), ed25519.viewing_key.pubkey());
}

pub(crate) fn ed25519_ecdh_is_not_p256() {
    let ed25519 = SigningKey::from_ed25519_bytes(&[7u8; 32]);
    let counterparty = zolana_keypair::ViewingKey::new().pubkey();
    assert_eq!(ed25519.ecdh(&counterparty), Err(KeypairError::NotP256));
}

pub(crate) fn primitives_refuse_derivation_inputs(world: &mut KeypairWorld, key: String) {
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

    let sk = world.sig_key(&key);
    let p_derive = P256Pubkey::from_bytes(P_DERIVE_SEC1).unwrap();
    assert_eq!(sk.ecdh(&p_derive), Err(KeypairError::DerivationInput));
    assert_eq!(
        sk.sign_message(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    let mut prefixed_digest = [0u8; 32];
    prefixed_digest[..12].copy_from_slice(b"TSPP/derive/");
    assert_eq!(
        sk.sign_hash(&prefixed_digest),
        Err(KeypairError::DerivationInput)
    );
    let benign = zolana_keypair::ViewingKey::new().pubkey();
    assert!(sk.ecdh(&benign).is_ok());

    let p_pda = P256Pubkey::from_bytes(P_PDA_SEC1).unwrap();
    assert_eq!(sk.ecdh(&p_pda), Err(KeypairError::DerivationInput));

    let p_const = P256Pubkey::from_bytes(P_CONST_SEC1).unwrap();
    assert_eq!(sk.ecdh(&p_const), Err(KeypairError::DerivationInput));

    for mut bytes in [P_DERIVE_SEC1, P_PDA_SEC1, P_CONST_SEC1] {
        bytes[0] ^= 1;
        let negated = P256Pubkey::from_bytes(bytes).expect("negated derivation point");
        assert_eq!(sk.ecdh(&negated), Err(KeypairError::DerivationInput));
        assert_eq!(
            zolana_keypair::ViewingKey::new().ecdh(&negated),
            Err(KeypairError::DerivationInput)
        );
    }

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
