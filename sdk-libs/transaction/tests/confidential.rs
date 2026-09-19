use borsh::BorshDeserialize;
use zolana_event::OutputDataEncoding;
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, SALT_LEN},
    ViewingKey,
};
use zolana_transaction::{
    serialization::confidential::*, Data, DecodeCx, EncryptedScheme, TransactionError,
    UtxoSerialization, SOL_ASSET_ID,
};

const SALT: [u8; SALT_LEN] = [9u8; SALT_LEN];
const SLOT_INDEX: u32 = 2;

fn plaintext() -> ConfidentialOutputPlaintext {
    ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
        amount: 42,
        blinding: [7u8; 32],
        ring_program_id: None,
        data: Data::default(),
    }
}

fn encoded_body(tx: &ViewingKey, recipient: &ViewingKey) -> Vec<u8> {
    let ciphertext = Confidential::encode_plaintext(
        &plaintext(),
        [0u8; 32],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: recipient.pubkey(),
            salt: SALT,
            slot_index: SLOT_INDEX,
        },
    )
    .expect("encode");
    let OutputDataEncoding::Encrypted(blob) =
        OutputDataEncoding::try_from_slice(&ciphertext.data).expect("output data")
    else {
        panic!("expected encrypted output data");
    };
    let (&scheme_byte, body) = blob.split_first().expect("scheme byte");
    assert_eq!(scheme_byte, EncryptedScheme::Confidential.as_byte());
    body.to_vec()
}

#[test]
fn recipient_and_tx_key_both_decrypt_the_slot() {
    let tx = ViewingKey::new();
    let recipient = ViewingKey::new();
    let body = encoded_body(&tx, &recipient);

    let cx = DecodeCx {
        viewing_key: &recipient,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        slot_index: SLOT_INDEX,
        first_nullifier: None,
    };
    assert_eq!(
        (
            Confidential::decode(&body, &cx).expect("recipient decode"),
            Confidential::decrypt_with_tx_key(&tx, &body, SALT, SLOT_INDEX).expect("tx key decode"),
        ),
        (plaintext(), plaintext())
    );
}

#[test]
fn embedded_viewing_pk_is_the_recipient_pk() {
    let tx = ViewingKey::new();
    let recipient = ViewingKey::new();
    let body = encoded_body(&tx, &recipient);
    assert_eq!(
        Confidential::embedded_viewing_pk(&body).expect("embedded pk"),
        recipient.pubkey()
    );
}

#[test]
fn short_body_fails_with_invalid_length() {
    let short = [1u8; 10];
    let expected = TransactionError::InvalidLength {
        expected: P256_PUBKEY_LEN,
        actual: short.len(),
    };
    let tx = ViewingKey::new();
    let recipient = ViewingKey::new();
    let cx = DecodeCx {
        viewing_key: &recipient,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        slot_index: SLOT_INDEX,
        first_nullifier: None,
    };
    assert_eq!(
        (
            Confidential::decrypt(&short, &cx).unwrap_err(),
            Confidential::embedded_viewing_pk(&short).unwrap_err(),
            Confidential::decrypt_with_tx_key(&tx, &short, SALT, SLOT_INDEX).unwrap_err(),
        ),
        (expected.clone(), expected.clone(), expected)
    );
}
