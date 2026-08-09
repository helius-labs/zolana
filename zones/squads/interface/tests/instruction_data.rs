//! Wire-layout pins for the instruction data types. Only the facts a client
//! depends on are asserted here: the empty payloads stay empty and the
//! variable-length envelope keeps its exact byte length.

mod empty_payloads {
    use zolana_squads_interface::instruction::{
        CancelKeyUpdateIxData, CancelProposalIxData, CloseViewingKeyAccountIxData,
    };

    /// These instructions carry only the dispatch tag. A payload byte here would
    /// change every builder's instruction length.
    #[test]
    fn carry_no_bytes() {
        assert!(CancelKeyUpdateIxData
            .serialize()
            .expect("serialize")
            .is_empty());
        assert!(CancelProposalIxData
            .serialize()
            .expect("serialize")
            .is_empty());
        assert!(CloseViewingKeyAccountIxData
            .serialize()
            .expect("serialize")
            .is_empty());
    }
}

mod encrypted_utxos {
    use zolana_squads_interface::instruction::EncryptedUtxos;

    /// `tx_viewing_pk` (33) + `sender_ciphertext` (40) + a one-byte recipient
    /// count + one 71-byte recipient ciphertext.
    #[test]
    fn transfer_envelope_length() {
        let value = EncryptedUtxos {
            tx_viewing_pk: [1u8; 33],
            sender_ciphertext: [2u8; 40],
            recipient_ciphertexts: vec![[3u8; 71]],
        };
        assert_eq!(
            value.serialize().expect("serialize").len(),
            33 + 40 + 1 + 71
        );
    }

    /// A withdrawal has no recipient slot, so only the count byte remains.
    #[test]
    fn withdrawal_envelope_length() {
        let value = EncryptedUtxos {
            tx_viewing_pk: [1u8; 33],
            sender_ciphertext: [2u8; 40],
            recipient_ciphertexts: vec![],
        };
        assert_eq!(value.serialize().expect("serialize").len(), 33 + 40 + 1);
    }
}
