use solana_pubkey::Pubkey;

mod cancel_key_update {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::builders::CancelKeyUpdate, instruction::tag, PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CancelKeyUpdate {
            owner: Pubkey::new_from_array([1; 32]),
            target: Pubkey::new_from_array([1; 32]),
            key_update_proposal: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::CANCEL_KEY_UPDATE]);
        assert_eq!(ix.accounts.len(), 4);
        // owner signs.
        assert!(ix.accounts[0].is_signer);
    }
}

mod cancel_proposal {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::builders::CancelProposal, instruction::tag, PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CancelProposal {
            owner: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            proposal: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::CANCEL_PROPOSAL]);
        assert_eq!(ix.accounts.len(), 4);
        // owner signs.
        assert!(ix.accounts[0].is_signer);
    }
}

mod close_viewing_key_account {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::builders::CloseViewingKeyAccount, instruction::tag, PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CloseViewingKeyAccount {
            owner: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::CLOSE_VIEWING_KEY_ACCOUNT]);
        // owner, vka, rent_recipient.
        assert_eq!(ix.accounts.len(), 3);
        // owner signs.
        assert!(ix.accounts[0].is_signer);
    }
}

mod create_proposal {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::CreateProposal, tag, CreateProposalIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CreateProposal {
            fee_payer: Pubkey::new_from_array([1; 32]),
            proposal: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            owner: Pubkey::new_from_array([1; 32]),
            data: CreateProposalIxData {
                recipient: Pubkey::new_from_array([1u8; 32]),
                asset: Pubkey::new_from_array([2u8; 32]),
                proposal_hash: [3u8; 32],
                cipher_text: [4u8; 88],
                expiry: 0,
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::CREATE_PROPOSAL);
        assert_eq!(ix.accounts.len(), 5);
        // fee_payer signs and is writable.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // owner signs (smart account vault).
        assert!(ix.accounts[4].is_signer);
    }
}

mod create_viewing_key_account {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::CreateViewingKeyAccount, tag, CreateViewingKeyAccountIxData},
        PROGRAM_ID_PUBKEY,
    };

    fn data() -> CreateViewingKeyAccountIxData {
        CreateViewingKeyAccountIxData {
            key_encryption_proof: [1u8; 192],
            encryption_scheme: 1,
            owner_kind: 0,
            shared_viewing_key: [2u8; 33],
            shared_viewing_key_commitment: [3u8; 32],
            nullifier_pubkey: [4u8; 32],
            key_ciphertext_ephemeral: [5u8; 33],
            encrypted_nullifier_secret: [6u8; 31],
            recovery_keys: vec![],
            key_ciphertexts: vec![[7u8; 32]],
        }
    }

    #[test]
    fn builds_owner_signed_instruction() {
        let ix = CreateViewingKeyAccount {
            fee_payer: Pubkey::new_from_array([1; 32]),
            owner: Pubkey::new_from_array([1; 32]),
            owner_signs: true,
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            data: data(),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::CREATE_VIEWING_KEY_ACCOUNT);
        assert_eq!(ix.accounts.len(), 5);
        // fee_payer signs and is writable.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // owner signs when registering recovery keys.
        assert!(ix.accounts[1].is_signer);
    }

    #[test]
    fn auditor_only_owner_does_not_sign() {
        let ix = CreateViewingKeyAccount {
            fee_payer: Pubkey::new_from_array([1; 32]),
            owner: Pubkey::new_from_array([1; 32]),
            owner_signs: false,
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            data: data(),
        }
        .instruction();

        assert!(!ix.accounts[1].is_signer);
    }
}

mod create_ring_config {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::CreateRingConfig, tag, CreateRingConfigIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CreateRingConfig {
            creator: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            data: CreateRingConfigIxData {
                authority: Pubkey::new_from_array([1u8; 32]),
                co_signer: Pubkey::new_from_array([2u8; 32]),
                max_proposal_lifetime: 3600,
                auditor_keys: vec![[3u8; 33]],
                merge_authorities: vec![Pubkey::new_from_array([4u8; 32])],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::CREATE_RING_CONFIG);
        assert_eq!(ix.accounts.len(), 3);
        // creator signs and is writable.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
    }
}

mod execute_key_update {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::ExecuteKeyUpdate, tag, ExecuteKeyUpdateIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = ExecuteKeyUpdate {
            executor: Pubkey::new_from_array([1; 32]),
            co_signer: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([1; 32]),
            key_update_proposal: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            data: ExecuteKeyUpdateIxData {
                rotation_proof: [1u8; 192],
                new_shared_viewing_key: [2u8; 33],
                new_shared_viewing_key_commitment: [3u8; 32],
                new_nullifier_pubkey: [4u8; 32],
                new_key_ciphertext_ephemeral: [5u8; 33],
                new_encrypted_nullifier_secret: [6u8; 31],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::EXECUTE_KEY_UPDATE);
        // executor, co_signer, vka, ring_config, proposal, rent_recipient,
        // system_program, program (self-CPI).
        assert_eq!(ix.accounts.len(), 8);
        // executor signs and is writable (fee payer).
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // co_signer signs.
        assert!(ix.accounts[1].is_signer);
    }
}

mod fill_key_update {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::FillKeyUpdate, tag, FillKeyUpdateIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = FillKeyUpdate {
            executor: Pubkey::new_from_array([1; 32]),
            key_update_proposal: Pubkey::new_from_array([1; 32]),
            data: FillKeyUpdateIxData {
                ciphertexts: vec![[1u8; 32]],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::FILL_KEY_UPDATE);
        assert_eq!(ix.accounts.len(), 2);
        // executor signs and is writable (fee payer).
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
    }
}

mod init_spp_ring_config {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::builders::InitSppRingConfig, instruction::tag, PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = InitSppRingConfig {
            authority: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([2; 32]),
            protocol_config: Pubkey::new_from_array([3; 32]),
            ring_auth: Pubkey::new_from_array([4; 32]),
            system_program: Pubkey::new_from_array([5; 32]),
            spp_program: Pubkey::new_from_array([6; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::INIT_SPP_RING_CONFIG]);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[0].is_signer);
    }
}

mod toggle_viewing_key_account {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::ToggleViewingKeyAccount, tag, ToggleViewingKeyAccountIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = ToggleViewingKeyAccount {
            owner: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            data: ToggleViewingKeyAccountIxData { state: 1 },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::TOGGLE_VIEWING_KEY_ACCOUNT);
        assert_eq!(ix.accounts.len(), 2);
        // owner signs.
        assert!(ix.accounts[0].is_signer);
    }
}

mod update_viewing_key_account {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::UpdateViewingKeyAccount, tag, UpdateViewingKeyAccountIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = UpdateViewingKeyAccount {
            proposer: Pubkey::new_from_array([1; 32]),
            target: Pubkey::new_from_array([1; 32]),
            key_update_proposal: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([1; 32]),
            data: UpdateViewingKeyAccountIxData {
                domain: 0,
                operations: vec![],
                expiry: 0,
                executor: Pubkey::new_from_array([1u8; 32]),
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::UPDATE_VIEWING_KEY_ACCOUNT);
        assert_eq!(ix.accounts.len(), 5);
        // proposer signs and is writable (fee payer).
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
    }
}

mod update_ring_config {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::UpdateRingConfig, tag, UpdateRingConfigIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = UpdateRingConfig {
            authority: Pubkey::new_from_array([1; 32]),
            ring_config: Pubkey::new_from_array([1; 32]),
            data: UpdateRingConfigIxData {
                authority: Pubkey::new_from_array([1u8; 32]),
                co_signer: Pubkey::new_from_array([2u8; 32]),
                max_proposal_lifetime: 3600,
                auditor_keys: vec![[3u8; 33]],
                merge_authorities: vec![Pubkey::new_from_array([4u8; 32])],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::UPDATE_RING_CONFIG);
        assert_eq!(ix.accounts.len(), 2);
        // authority signs.
        assert!(ix.accounts[0].is_signer);
    }
}

mod forwarded {
    use solana_instruction::AccountMeta;
    use solana_pubkey::Pubkey;
    use zolana_interface::instruction::{
        instruction_data::{
            deposit::DepositAssetKind,
            merge_ring::MergeRingIxData,
            merge_transact::{MergeProof, MergeTransactIxData as SppMergeTransactIxData},
        },
        CircuitId, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData as SppTransactIxData,
        TransactOutput, TransactProof, TreeContext,
    };
    use zolana_squads_interface::{
        instruction::{
            builders::{Deposit, ExecuteProposal, FullWithdrawal, MergeTransact, Transact},
            tag, DepositIxData, ExecuteProposalIxData, FullWithdrawalIxData, MergeTransactIxData,
            TransactIxData,
        },
        PROGRAM_ID_PUBKEY,
    };

    fn key(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn spp_accounts() -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(key(40), true),
            AccountMeta::new(key(41), false),
            AccountMeta::new_readonly(key(42), false),
        ]
    }

    fn spp(withdrawal: bool) -> SppTransactIxData {
        SppTransactIxData {
            expiry_unix_ts: 9,
            tx_viewing_pk: [2u8; 33],
            salt: [3u8; 16],
            interface_transfers: if withdrawal {
                vec![InterfaceTransfer::SolWithdrawal { amount: 5 }]
            } else {
                Vec::new()
            },
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![TransactOutput {
                utxo_hash: [4u8; 32],
                owner_tag: OwnerTag::Inline([5u8; 32]),
                data: Some(vec![6u8; 40]),
            }],
            messages: Vec::new(),
            private_tx_hash: [7u8; 32],
            circuit: CircuitId::RingAuthority(1, 1, 3),
            proof: TransactProof {
                a: [8u8; 32],
                b: [9u8; 128],
                c: [10u8; 32],
            },
            inputs: vec![InputUtxo {
                nullifier_hash: [11u8; 32],
                tree_index: 0,
            }],
            tree_contexts: vec![TreeContext {
                utxo_tree_root_index: 1,
                nullifier_tree_root_index: 2,
            }],
        }
    }

    fn tagged(tag: u8, body: Vec<u8>) -> Vec<u8> {
        let mut data = vec![tag];
        data.extend(body);
        data
    }

    #[test]
    fn transact_forwards_spp_accounts_after_the_ring_prefix() {
        let data = TransactIxData {
            ring_proof: [1u8; 192],
            spp: spp(false),
        };
        let ix = Transact {
            payer: key(1),
            co_signer: key(2),
            ring_config: key(3),
            sender_viewing_key_account: key(4),
            recipient_viewing_key_account: Some(key(5)),
            spp_accounts: spp_accounts(),
            data: data.clone(),
        }
        .instruction();

        let mut expected = vec![
            AccountMeta::new(key(1), true),
            AccountMeta::new_readonly(key(2), true),
            AccountMeta::new_readonly(key(3), false),
            AccountMeta::new_readonly(key(4), false),
            AccountMeta::new_readonly(key(5), false),
        ];
        expected.extend(spp_accounts());
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.accounts, expected);
        assert_eq!(ix.data, tagged(tag::TRANSACT, data.serialize().unwrap()));
    }

    #[test]
    fn withdrawal_transact_omits_the_recipient_account() {
        let ix = Transact {
            payer: key(1),
            co_signer: key(2),
            ring_config: key(3),
            sender_viewing_key_account: key(4),
            recipient_viewing_key_account: None,
            spp_accounts: spp_accounts(),
            data: TransactIxData {
                ring_proof: [1u8; 192],
                spp: spp(true),
            },
        }
        .instruction();
        assert_eq!(ix.accounts.len(), 4 + spp_accounts().len());
        assert_eq!(ix.accounts.get(4), spp_accounts().first());
    }

    #[test]
    fn execute_proposal_forwards_spp_accounts_after_the_rent_recipient() {
        let data = ExecuteProposalIxData {
            ring_proof: [1u8; 192],
            spp: spp(false),
        };
        let ix = ExecuteProposal {
            payer: key(1),
            co_signer: key(2),
            ring_config: key(3),
            proposal: key(4),
            sender_viewing_key_account: key(5),
            recipient_viewing_key_account: Some(key(6)),
            rent_recipient: key(7),
            spp_accounts: spp_accounts(),
            data: data.clone(),
        }
        .instruction();

        let mut expected = vec![
            AccountMeta::new(key(1), true),
            AccountMeta::new_readonly(key(2), true),
            AccountMeta::new_readonly(key(3), false),
            AccountMeta::new(key(4), false),
            AccountMeta::new_readonly(key(5), false),
            AccountMeta::new_readonly(key(6), false),
            AccountMeta::new(key(7), false),
        ];
        expected.extend(spp_accounts());
        assert_eq!(ix.accounts, expected);
        assert_eq!(
            ix.data,
            tagged(tag::EXECUTE_PROPOSAL, data.serialize().unwrap())
        );
    }

    #[test]
    fn full_withdrawal_is_exactly_the_spp_account_list() {
        let data = FullWithdrawalIxData { spp: spp(true) };
        let ix = FullWithdrawal {
            spp_accounts: spp_accounts(),
            data: data.clone(),
        }
        .instruction();
        assert_eq!(ix.accounts, spp_accounts());
        assert_eq!(
            ix.data,
            tagged(tag::FULL_WITHDRAWAL, data.serialize().unwrap())
        );
    }

    #[test]
    fn merge_transact_forwards_spp_accounts_after_the_owner_account() {
        let data = MergeTransactIxData {
            spp: MergeRingIxData {
                output_ring_data_hash: [0u8; 32],
                merge: SppMergeTransactIxData {
                    expiry_unix_ts: 9,
                    proof: MergeProof {
                        a: [1u8; 32],
                        b: [2u8; 128],
                        c: [3u8; 32],
                    },
                    output_utxo_hash: [4u8; 32],
                    output_encryption: zolana_interface::instruction::instruction_data::MergeOutputEncryption::PoseidonCtrV1 {
                        salt: [7u8; 16],
                        ciphertext: [[8u8; 32]; 3],
                    },
                    private_tx_hash: [5u8; 32],
                    nullifiers: vec![[6u8; 32]; 8],
                    utxo_tree_root_index: 1,
                    nullifier_tree_root_index: 2,
                    cache_slot: None,
                },
            },
        };
        let ix = MergeTransact {
            merge_authority: key(1),
            ring_config: key(2),
            owner_viewing_key_account: key(3),
            spp_accounts: spp_accounts(),
            data: data.clone(),
        }
        .instruction();

        let mut expected = vec![
            AccountMeta::new(key(1), true),
            AccountMeta::new_readonly(key(2), false),
            AccountMeta::new_readonly(key(3), false),
        ];
        expected.extend(spp_accounts());
        assert_eq!(ix.accounts, expected);
        assert_eq!(
            ix.data,
            tagged(tag::MERGE_TRANSACT, data.serialize().unwrap())
        );
    }

    #[test]
    fn deposit_forwards_spp_accounts_after_the_recipient_account() {
        let data = DepositIxData {
            view_tag: [1u8; 32],
            blinding: [2u8; 32],
            amount: 3,
            asset: DepositAssetKind::Sol,
        };
        let ix = Deposit {
            recipient_viewing_key_account: key(1),
            spp_accounts: spp_accounts(),
            data,
        }
        .instruction();

        let mut expected = vec![AccountMeta::new_readonly(key(1), false)];
        expected.extend(spp_accounts());
        assert_eq!(ix.accounts, expected);
        assert_eq!(ix.data, tagged(tag::DEPOSIT, data.serialize().unwrap()));
    }
}
