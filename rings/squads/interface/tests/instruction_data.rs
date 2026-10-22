mod cancel_key_update {
    use zolana_squads_interface::instruction::CancelKeyUpdateIxData;

    #[test]
    fn round_trip() {
        let value = CancelKeyUpdateIxData;
        let bytes = value.serialize().expect("serialize");
        assert!(bytes.is_empty());
        let parsed = CancelKeyUpdateIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod cancel_proposal {
    use zolana_squads_interface::instruction::CancelProposalIxData;

    #[test]
    fn round_trip() {
        let value = CancelProposalIxData;
        let bytes = value.serialize().expect("serialize");
        assert!(bytes.is_empty());
        let parsed = CancelProposalIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod close_viewing_key_account {
    use zolana_squads_interface::instruction::CloseViewingKeyAccountIxData;

    #[test]
    fn round_trip() {
        let value = CloseViewingKeyAccountIxData;
        let bytes = value.serialize().expect("serialize");
        assert!(bytes.is_empty());
        let parsed = CloseViewingKeyAccountIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod create_proposal {
    use zolana_squads_interface::instruction::CreateProposalIxData;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip() {
        let value = CreateProposalIxData {
            recipient: Address::new_from_array([1u8; 32]),
            asset: Address::new_from_array([2u8; 32]),
            proposal_hash: [3u8; 32],
            cipher_text: [4u8; 88],
            expiry: 1_700_000_000,
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = CreateProposalIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod create_viewing_key_account {
    use zolana_squads_interface::instruction::CreateViewingKeyAccountIxData;

    #[test]
    fn round_trip() {
        let value = CreateViewingKeyAccountIxData {
            key_encryption_proof: [1u8; 192],
            encryption_scheme: 1,
            owner_kind: 0,
            shared_viewing_key: [2u8; 33],
            shared_viewing_key_commitment: [3u8; 32],
            nullifier_pubkey: [4u8; 32],
            key_ciphertext_ephemeral: [5u8; 33],
            encrypted_nullifier_secret: [6u8; 31],
            recovery_keys: vec![[7u8; 33], [8u8; 33]],
            key_ciphertexts: vec![[9u8; 32], [10u8; 32], [11u8; 32]],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = CreateViewingKeyAccountIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod create_ring_config {
    use zolana_squads_interface::instruction::CreateRingConfigIxData;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip() {
        let value = CreateRingConfigIxData {
            authority: Address::new_from_array([1u8; 32]),
            co_signer: Address::new_from_array([2u8; 32]),
            max_proposal_lifetime: 86_400,
            auditor_keys: vec![[3u8; 33]],
            merge_authorities: vec![
                Address::new_from_array([4u8; 32]),
                Address::new_from_array([5u8; 32]),
            ],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = CreateRingConfigIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod execute_key_update {
    use zolana_squads_interface::instruction::ExecuteKeyUpdateIxData;

    #[test]
    fn round_trip() {
        let value = ExecuteKeyUpdateIxData {
            rotation_proof: [1u8; 192],
            new_shared_viewing_key: [2u8; 33],
            new_shared_viewing_key_commitment: [3u8; 32],
            new_nullifier_pubkey: [4u8; 32],
            new_key_ciphertext_ephemeral: [5u8; 33],
            new_encrypted_nullifier_secret: [6u8; 31],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = ExecuteKeyUpdateIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod fill_key_update {
    use zolana_squads_interface::instruction::FillKeyUpdateIxData;

    #[test]
    fn round_trip() {
        let value = FillKeyUpdateIxData {
            ciphertexts: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = FillKeyUpdateIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod toggle_viewing_key_account {
    use zolana_squads_interface::instruction::ToggleViewingKeyAccountIxData;

    #[test]
    fn round_trip() {
        let value = ToggleViewingKeyAccountIxData { state: 1 };
        let bytes = value.serialize().expect("serialize");
        let parsed = ToggleViewingKeyAccountIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod update_viewing_key_account {
    use zolana_squads_interface::instruction::UpdateViewingKeyAccountIxData;
    use zolana_squads_interface::state::KeyOperation;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip() {
        let value = UpdateViewingKeyAccountIxData {
            domain: 7,
            operations: vec![
                KeyOperation {
                    op: 0,
                    index: 0,
                    key: [1u8; 33],
                },
                KeyOperation {
                    op: 2,
                    index: 1,
                    key: [2u8; 33],
                },
            ],
            expiry: 1_700_000_000,
            executor: Address::new_from_array([3u8; 32]),
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = UpdateViewingKeyAccountIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod update_ring_config {
    use zolana_squads_interface::instruction::UpdateRingConfigIxData;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip() {
        let value = UpdateRingConfigIxData {
            authority: Address::new_from_array([10u8; 32]),
            co_signer: Address::new_from_array([11u8; 32]),
            max_proposal_lifetime: 172_800,
            auditor_keys: vec![[12u8; 33]],
            merge_authorities: vec![Address::new_from_array([13u8; 32])],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = UpdateRingConfigIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}
