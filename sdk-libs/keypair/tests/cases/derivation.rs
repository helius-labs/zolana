use solana_address::Address;
use spr_keypair::{
    derivation::{
        ed25519_derivation_message, expand_roles, is_derivation_input, ring_nullifier_key,
        DERIVATION_PAYLOAD_PREFIX, DOMAIN_MERGE_DUMMY_NULLIFIER, DOMAIN_MERGE_OUTPUT_BLINDING_V1,
        DOM_SEP_KEY, DOM_SEP_NONCE, DOM_SEP_SILO, ED25519_DERIVATION_MSG, ED25519_SEED_LEN,
        ENC_INFO_RING_DEPOSIT, ENC_INFO_TRANSFER, HPKE_PREFIX, INFO_NF_KEY_ED25519,
        INFO_PAIR_DOMAIN_PREFIX, INFO_PAIR_HINT_PREFIX, INFO_PDA_NF_KEY, INFO_PDA_VIEW_KEY,
        INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX, INFO_RECIPIENT_VIEW_TAG_SECRET, INFO_RING_NF_KEY,
        INFO_SENDER_VIEW_TAG_PREFIX, INFO_SENDER_VIEW_TAG_SECRET, INFO_TX_VIEWING_X25519,
        INFO_VIEW_KEY_ED25519_X25519, MERGE_INFO, OFFCHAIN_MESSAGE_MAGIC, TSPP_APPLICATION_DOMAIN,
    },
    hash::sha256,
    Curve, KeypairError, NullifierKey, ShieldedKeypair, ShieldedKeypairTrait, ShieldedPda,
    SigningKey, ViewingKey,
};

pub(crate) fn hkdf_tags_pairwise_distinct() {
    let tags: &[&[u8]] = &[
        ED25519_DERIVATION_MSG,
        DERIVATION_PAYLOAD_PREFIX,
        INFO_NF_KEY_ED25519,
        INFO_VIEW_KEY_ED25519_X25519,
        INFO_PDA_NF_KEY,
        INFO_PDA_VIEW_KEY,
        INFO_RING_NF_KEY,
        INFO_SENDER_VIEW_TAG_SECRET,
        INFO_RECIPIENT_VIEW_TAG_SECRET,
        INFO_TX_VIEWING_X25519,
        INFO_SENDER_VIEW_TAG_PREFIX,
        INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
        INFO_PAIR_DOMAIN_PREFIX,
        INFO_PAIR_HINT_PREFIX,
        HPKE_PREFIX,
        ENC_INFO_TRANSFER,
        ENC_INFO_RING_DEPOSIT,
        MERGE_INFO,
    ];
    for (i, a) in tags.iter().enumerate() {
        for b in tags.iter().skip(i + 1) {
            assert_ne!(a, b, "duplicate HKDF domain-separation tag");
        }
    }
}

pub(crate) fn application_domain_is_payload_hash() {
    assert_eq!(TSPP_APPLICATION_DOMAIN, sha256(ED25519_DERIVATION_MSG));
}

pub(crate) fn offchain_derivation_message_golden() {
    let message = ed25519_derivation_message(&[7u8; 32]);
    assert_eq!(message.len(), 99);
    assert_eq!(
        hex::encode(&message),
        concat!(
            "ff736f6c616e61206f6666636861696e",
            "00",
            "1d32a88533af12d35e5ac6fce817a4cb810bcc4115386b14a78e8b2ef09d864c",
            "00",
            "01",
            "0707070707070707070707070707070707070707070707070707070707070707",
            "0e00",
            "545350502f6465726976652f7631",
        )
    );
}

fn offchain_v0(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&OFFCHAIN_MESSAGE_MAGIC);
    message.push(0);
    message.extend_from_slice(&TSPP_APPLICATION_DOMAIN);
    message.push(0);
    message.push(1);
    message.extend_from_slice(&[7u8; 32]);
    message.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    message.extend_from_slice(payload);
    message
}

pub(crate) fn derivation_inputs_are_detected() {
    assert!(is_derivation_input(ED25519_DERIVATION_MSG));
    assert!(is_derivation_input(DERIVATION_PAYLOAD_PREFIX));
    assert!(is_derivation_input(
        b"TSPP/derive/pda/v1/9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
    ));
    assert!(is_derivation_input(&ed25519_derivation_message(&[7u8; 32])));
    assert!(is_derivation_input(&offchain_v0(b"TSPP/derive/pda/v1/x")));

    assert!(!is_derivation_input(b"TSPP/derive"));
    assert!(!is_derivation_input(b"private_tx_hash"));
    assert!(!is_derivation_input(INFO_NF_KEY_ED25519));
    assert!(!is_derivation_input(&offchain_v0(b"hello")));

    let mut truncated = ed25519_derivation_message(&[7u8; 32]);
    truncated.pop();
    assert!(!is_derivation_input(&truncated));
}

/// `expand_roles` is the entry a remote backend derives through, so it must
/// produce exactly what the software constructor produces for Ed25519. A
/// divergence here is silent: the identity stays well-formed and every
/// signature still verifies, it is simply not the user's wallet.
pub(crate) fn expand_roles_matches_the_software_constructor() {
    let keys = [SigningKey::from_ed25519_bytes(&[5u8; 32])];
    for signing_key in keys {
        let curve = signing_key.curve();
        let seed = signing_key.derivation_seed().expect("derivation seed");
        let (nullifier_key, viewing_key) =
            expand_roles(&seed, curve).expect("roles expand from the seed");
        let software = ShieldedKeypair::from_keypair(signing_key).expect("software keypair");

        assert_eq!(
            *nullifier_key.secret(),
            *software.nullifier_key.secret(),
            "{curve:?} nullifier secret diverged from the software path"
        );
        assert_eq!(
            *viewing_key.secret_bytes(),
            *software.viewing_key.secret_bytes(),
            "{curve:?} viewing secret diverged from the software path"
        );
    }
}

/// HKDF-Extract accepts any input length, so a device that returned a truncated
/// seed would expand cleanly into a wrong-but-valid identity. The width is fixed
/// per rail, so reject anything else rather than derive from it.
pub(crate) fn expand_roles_rejects_a_seed_of_the_wrong_width() {
    for (curve, expected) in [(Curve::Ed25519, ED25519_SEED_LEN)] {
        for got in [expected - 1, expected + 1, 0] {
            assert_eq!(
                expand_roles(&vec![7u8; got], curve).err(),
                Some(KeypairError::InvalidDerivationSeed { got, expected }),
                "{curve:?} accepted a {got}-byte seed"
            );
        }
        assert!(expand_roles(&vec![7u8; expected], curve).is_ok());
    }
}

/// A PDA holds no signing secret, so it has no seed and no roles to expand.
pub(crate) fn expand_roles_rejects_the_pda_curve() {
    assert!(matches!(
        expand_roles(&[0u8; 64], Curve::Pda),
        Err(KeypairError::PdaCannotSign)
    ));
}

fn ring(n: u8) -> Address {
    Address::new_from_array([n; 32])
}

fn wallet(n: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[n; 32])).unwrap()
}

fn secret(key: &NullifierKey) -> [u8; 31] {
    *key.secret()
}

/// Labels spelled out, a renamed constant fails here.
pub(crate) fn ring_key_is_the_labelled_hkdf_of_the_root() {
    let root = wallet(7).nullifier_key;
    let mut info = b"TSPP/ring_nf/v1".to_vec();
    info.extend_from_slice(ring(1).as_ref());
    let mut expected = [0u8; 31];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(b"TSPP/ring_nf_root/v1"), root.secret().as_slice())
        .expand(&info, &mut expected)
        .unwrap();
    assert_eq!(
        secret(&ring_nullifier_key(&root, &ring(1)).unwrap()),
        expected
    );
}

pub(crate) fn ring_keys_separate_rings_wallets_and_the_root() {
    let owner = wallet(7);
    let first = owner.ring_nullifier_key(&ring(1)).unwrap();
    let second = owner.ring_nullifier_key(&ring(2)).unwrap();
    assert_ne!(secret(&first), secret(&second));
    assert_ne!(secret(&first), secret(&owner.nullifier_key));
    assert_ne!(
        secret(&first),
        secret(&wallet(8).ring_nullifier_key(&ring(1)).unwrap())
    );
    assert_eq!(
        secret(&first),
        secret(&owner.ring_nullifier_key(&ring(1)).unwrap())
    );
    let from_ring_secret = ring_nullifier_key(&first, &ring(2)).unwrap();
    assert_ne!(secret(&from_ring_secret), secret(&second));
    assert_ne!(secret(&from_ring_secret), secret(&owner.nullifier_key));
}

pub(crate) fn a_zero_root_has_no_ring_key() {
    assert_eq!(
        ring_nullifier_key(&NullifierKey::from_secret([0; 31]), &ring(1)).err(),
        Some(KeypairError::ZeroNullifierSecret)
    );
}

pub(crate) fn pda_ring_keys_expand_the_pda_root() {
    let holder = ViewingKey::from_bytes(&[5; 32]);
    let peer = ViewingKey::from_bytes(&[6; 32]);
    let sole = ShieldedPda::from_viewing_key(ring(3), &holder).unwrap();
    let key = sole.ring_nullifier_key(&ring(1)).unwrap();

    let other_pda = ShieldedPda::from_viewing_key(ring(4), &holder).unwrap();
    assert_ne!(
        secret(&key),
        secret(&other_pda.ring_nullifier_key(&ring(1)).unwrap())
    );
    assert_ne!(
        secret(&key),
        secret(&sole.ring_nullifier_key(&ring(2)).unwrap())
    );
    assert_ne!(secret(&key), secret(sole.as_ref()));
    assert_ne!(
        secret(&key),
        secret(&ring_nullifier_key(sole.as_ref(), &ring(1)).unwrap()),
        "the PDA form is not the wallet form over its nullifier secret"
    );

    let dyn_holder: &dyn ShieldedKeypairTrait = &sole;
    assert_eq!(
        secret(&key),
        secret(&dyn_holder.ring_nullifier_key(&ring(1)).unwrap())
    );

    let from_holder = ShieldedPda::from_key_exchange(ring(3), &holder, &peer.pubkey()).unwrap();
    let from_peer = ShieldedPda::from_key_exchange(ring(3), &peer, &holder.pubkey()).unwrap();
    assert_eq!(
        secret(&from_holder.ring_nullifier_key(&ring(1)).unwrap()),
        secret(&from_peer.ring_nullifier_key(&ring(1)).unwrap())
    );
}

pub(crate) fn supplied_pda_roles_have_no_ring_key() {
    let supplied = ShieldedPda::with_viewing_key(
        ring(3),
        NullifierKey::from_secret([9; 31]),
        ViewingKey::new(),
    );
    assert_eq!(
        supplied.ring_nullifier_key(&ring(1)).err(),
        Some(KeypairError::PdaRootNotHeld)
    );
}

pub(crate) fn poseidon_tags_pairwise_distinct() {
    let tags = [
        DOM_SEP_SILO,
        DOM_SEP_KEY,
        DOM_SEP_KEY + 1,
        DOM_SEP_NONCE,
        DOMAIN_MERGE_OUTPUT_BLINDING_V1,
        DOMAIN_MERGE_DUMMY_NULLIFIER,
    ];
    for (i, a) in tags.iter().enumerate() {
        for b in tags.iter().skip(i + 1) {
            assert_ne!(a, b, "duplicate Poseidon domain-separation tag");
        }
    }
}
