use zolana_keypair::{
    derivation::{
        ed25519_derivation_message, is_derivation_input, DERIVATION_PAYLOAD_PREFIX,
        DOMAIN_MERGE_DUMMY_NULLIFIER, DOMAIN_MERGE_OUTPUT_BLINDING_V1, DOM_SEP_KEY, DOM_SEP_NONCE,
        DOM_SEP_SILO, DST_DERIVE_P_DERIVE, DST_VIEW_ROOT_P_CONST, ED25519_DERIVATION_MSG,
        ENC_INFO_RING_DEPOSIT, ENC_INFO_TRANSFER, HPKE_PREFIX, INFO_NF_KEY_ECDH,
        INFO_NF_KEY_ED25519, INFO_PAIR_DOMAIN_PREFIX, INFO_PAIR_HINT_PREFIX, INFO_PDA_NF_KEY,
        INFO_PDA_VIEW_KEY, INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX, INFO_RECIPIENT_VIEW_TAG_SECRET,
        INFO_SEED_P256_VIEWING, INFO_SENDER_VIEW_TAG_PREFIX, INFO_SENDER_VIEW_TAG_SECRET,
        INFO_TX_VIEWING, INFO_VIEW_KEY_ECDH, INFO_VIEW_KEY_ED25519, MERGE_INFO,
        OFFCHAIN_MESSAGE_MAGIC, TSPP_APPLICATION_DOMAIN,
    },
    hash::sha256,
};

pub(crate) fn hkdf_tags_pairwise_distinct() {
    let tags: &[&[u8]] = &[
        DST_VIEW_ROOT_P_CONST,
        DST_DERIVE_P_DERIVE,
        zolana_keypair::derivation::DST_PDA_ROOT_P_PDA,
        ED25519_DERIVATION_MSG,
        DERIVATION_PAYLOAD_PREFIX,
        INFO_NF_KEY_ED25519,
        INFO_NF_KEY_ECDH,
        INFO_VIEW_KEY_ED25519,
        INFO_VIEW_KEY_ECDH,
        INFO_PDA_NF_KEY,
        INFO_PDA_VIEW_KEY,
        INFO_SEED_P256_VIEWING,
        INFO_SENDER_VIEW_TAG_SECRET,
        INFO_RECIPIENT_VIEW_TAG_SECRET,
        INFO_TX_VIEWING,
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
