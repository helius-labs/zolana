use custom_ring_interface::RingDepositAuditCapsule;
use zolana_transaction::error::TransactionError;

pub fn deposit_payload(bytes: &[u8]) -> Result<&[u8], TransactionError> {
    RingDepositAuditCapsule::parse(bytes)
        .map(|capsule| capsule.map_or(bytes, |capsule| capsule.recipient_ciphertext))
        .map_err(|error| TransactionError::Deserialize(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_keypair::ViewingKey;
    use zolana_transaction::serialization::ring_deposit::RingDepositPlaintext;

    #[test]
    fn recipient_opens_legacy_and_auditor_wrapped_ciphertexts() {
        let recipient = ViewingKey::new();
        let plaintext = RingDepositPlaintext {
            blinding: [7; 32],
            utxo_data: Some(vec![1, 2]),
            memo: Some(vec![3]),
            ring_data: vec![4],
        };
        let mut encrypted = plaintext.encrypt(&recipient.pubkey()).unwrap();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 7,
            eph_pk: &[2; 33],
            ciphertext: &[3; 64],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode();
        let wrapped = encrypted.ciphertext.clone();
        encrypted.ciphertext = deposit_payload(&wrapped).unwrap().to_vec();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert!(deposit_payload(&wrapped[..105]).is_err());
    }
}
