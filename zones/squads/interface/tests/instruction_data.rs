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

mod create_zone_config {
    use zolana_squads_interface::instruction::CreateZoneConfigIxData;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip() {
        let value = CreateZoneConfigIxData {
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
        let parsed = CreateZoneConfigIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod deposit {
    use zolana_squads_interface::instruction::DepositIxData;

    #[test]
    fn round_trip() {
        let value = DepositIxData {
            view_tag: [1u8; 32],
            blinding: [2u8; 31],
            amount: 1_000_000,
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = DepositIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod encrypted_utxos {
    use zolana_squads_interface::instruction::EncryptedUtxos;

    #[test]
    fn transfer_round_trip() {
        let value = EncryptedUtxos {
            tx_viewing_pk: [1u8; 33],
            sender_ciphertext: [2u8; 40],
            recipient_ciphertexts: vec![[3u8; 71]],
        };
        let bytes = value.serialize().expect("serialize");
        assert_eq!(bytes.len(), 33 + 40 + 1 + 71);
        let parsed = EncryptedUtxos::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }

    #[test]
    fn withdrawal_round_trip() {
        let value = EncryptedUtxos {
            tx_viewing_pk: [1u8; 33],
            sender_ciphertext: [2u8; 40],
            recipient_ciphertexts: vec![],
        };
        let bytes = value.serialize().expect("serialize");
        assert_eq!(bytes.len(), 33 + 40 + 1);
        let parsed = EncryptedUtxos::deserialize(&bytes).expect("deserialize");
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

mod execute_proposal {
    use zolana_squads_interface::instruction::{
        EncryptedUtxos, ExecuteProposalIxData, InputContext,
    };

    #[test]
    fn round_trip() {
        let value = ExecuteProposalIxData {
            zone_proof: [1u8; 192],
            spp_proof: [2u8; 192],
            public_amount: None,
            private_tx_hash: [3u8; 32],
            salt: [11u8; 16],
            output_view_tags: vec![[12u8; 32], [13u8; 32]],
            output_utxo_hashes: vec![[4u8; 32], [5u8; 32]],
            input_contexts: vec![InputContext {
                nullifier: [6u8; 32],
                tree_index: 0,
                utxo_root_index: 7,
                nullifier_root_index: 8,
            }],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [9u8; 33],
                sender_ciphertext: [10u8; 40],
                recipient_ciphertexts: vec![],
            },
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = ExecuteProposalIxData::deserialize(&bytes).expect("deserialize");
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

mod full_withdrawal {
    use zolana_squads_interface::instruction::{
        EncryptedUtxos, FullWithdrawalIxData, InputContext,
    };

    #[test]
    fn round_trip() {
        let value = FullWithdrawalIxData {
            spp_proof: [1u8; 192],
            public_amount: 500_000,
            private_tx_hash: [8u8; 32],
            expiry: 1_700_000_000,
            salt: [9u8; 16],
            output_view_tags: vec![[10u8; 32]],
            output_utxo_hashes: vec![[11u8; 32]],
            input_contexts: vec![
                InputContext {
                    nullifier: [2u8; 32],
                    tree_index: 0,
                    utxo_root_index: 3,
                    nullifier_root_index: 4,
                },
                InputContext {
                    nullifier: [5u8; 32],
                    tree_index: 1,
                    utxo_root_index: 6,
                    nullifier_root_index: 7,
                },
            ],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [12u8; 33],
                sender_ciphertext: [13u8; 40],
                recipient_ciphertexts: vec![],
            },
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = FullWithdrawalIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}

mod merge_transact {
    use zolana_squads_interface::instruction::{InputContext, MergeTransactIxData};

    #[test]
    fn round_trip() {
        let value = MergeTransactIxData {
            spp_proof: [2u8; 192],
            expiry_unix_ts: 1_700_000_000,
            merge_view_tag: [9u8; 32],
            private_tx_hash: [3u8; 32],
            output_utxo_hash: [4u8; 32],
            input_contexts: vec![InputContext {
                nullifier: [5u8; 32],
                tree_index: 2,
                utxo_root_index: 6,
                nullifier_root_index: 7,
            }],
            encrypted_utxo: vec![8u8; 77],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = MergeTransactIxData::deserialize(&bytes).expect("deserialize");
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

mod transact {
    use zolana_squads_interface::instruction::{EncryptedUtxos, InputContext, TransactIxData};

    #[test]
    fn round_trip() {
        let value = TransactIxData {
            zone_proof: [1u8; 192],
            spp_proof: [2u8; 192],
            public_amount: Some(42),
            private_tx_hash: [3u8; 32],
            expiry: 1_700_000_000,
            salt: [15u8; 16],
            output_view_tags: vec![[16u8; 32], [17u8; 32]],
            output_utxo_hashes: vec![[4u8; 32], [5u8; 32]],
            input_contexts: vec![
                InputContext {
                    nullifier: [6u8; 32],
                    tree_index: 0,
                    utxo_root_index: 7,
                    nullifier_root_index: 8,
                },
                InputContext {
                    nullifier: [9u8; 32],
                    tree_index: 1,
                    utxo_root_index: 10,
                    nullifier_root_index: 11,
                },
            ],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [12u8; 33],
                sender_ciphertext: [13u8; 40],
                recipient_ciphertexts: vec![[14u8; 71]],
            },
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = TransactIxData::deserialize(&bytes).expect("deserialize");
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

mod update_zone_config {
    use zolana_squads_interface::instruction::UpdateZoneConfigIxData;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip() {
        let value = UpdateZoneConfigIxData {
            authority: Address::new_from_array([10u8; 32]),
            co_signer: Address::new_from_array([11u8; 32]),
            max_proposal_lifetime: 172_800,
            auditor_keys: vec![[12u8; 33]],
            merge_authorities: vec![Address::new_from_array([13u8; 32])],
        };
        let bytes = value.serialize().expect("serialize");
        let parsed = UpdateZoneConfigIxData::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed, value);
    }
}
