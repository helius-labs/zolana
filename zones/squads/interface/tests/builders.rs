use solana_pubkey::Pubkey;

mod cancel_key_update {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::builders::CancelKeyUpdate, instruction::tag, PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CancelKeyUpdate {
            authority: Pubkey::new_from_array([1; 32]),
            target: Pubkey::new_from_array([1; 32]),
            key_update_proposal: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::CANCEL_KEY_UPDATE]);
        assert_eq!(ix.accounts.len(), 5);
        // The authority signs.
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
            authority: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            proposal: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::CANCEL_PROPOSAL]);
        assert_eq!(ix.accounts.len(), 5);
        // The authority signs.
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
            authority: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            rent_recipient: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::CLOSE_VIEWING_KEY_ACCOUNT]);
        // authority, vka, rent_recipient, zone_config, program (self-CPI).
        assert_eq!(ix.accounts.len(), 5);
        // The authority signs.
        assert!(ix.accounts[0].is_signer);
        assert_eq!(ix.accounts[4].pubkey, PROGRAM_ID_PUBKEY);
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
            proposal: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([2; 32]),
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
        assert_eq!(ix.accounts.len(), 6);
        // fee_payer signs and is writable.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // owner signs (smart account vault).
        assert!(ix.accounts[5].is_signer);
        assert_eq!(ix.accounts[0].pubkey, ix.accounts[5].pubkey);
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
    fn builds_authenticated_enrollment_instruction() {
        let ix = CreateViewingKeyAccount {
            enrollment_authority: Pubkey::new_from_array([1; 32]),
            owner_identity: Pubkey::new_from_array([2; 32]),
            viewing_key_account: Pubkey::new_from_array([3; 32]),
            zone_config: Pubkey::new_from_array([4; 32]),
            system_program: Pubkey::new_from_array([5; 32]),
            data: data(),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::CREATE_VIEWING_KEY_ACCOUNT);
        assert_eq!(ix.accounts.len(), 5);
        // The configured co-signer authenticates enrollment and pays rent.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // owner_identity is public proof identity data and never signs.
        assert!(!ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[1].pubkey, Pubkey::new_from_array([2; 32]));
    }

    #[test]
    fn marks_exact_owner_identity_signer_for_recovery_enrollment() {
        let mut recovery_data = data();
        recovery_data.recovery_keys.push([8u8; 33]);
        recovery_data.key_ciphertexts.push([9u8; 32]);
        let ix = CreateViewingKeyAccount {
            enrollment_authority: Pubkey::new_from_array([1; 32]),
            owner_identity: Pubkey::new_from_array([2; 32]),
            viewing_key_account: Pubkey::new_from_array([3; 32]),
            zone_config: Pubkey::new_from_array([4; 32]),
            system_program: Pubkey::new_from_array([5; 32]),
            data: recovery_data,
        }
        .instruction();

        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[1].is_signer);
    }
}

mod create_zone_config {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::CreateZoneConfig, tag, CreateZoneConfigIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = CreateZoneConfig {
            creator: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
            system_program: Pubkey::new_from_array([1; 32]),
            data: CreateZoneConfigIxData {
                authority: Pubkey::new_from_array([1u8; 32]),
                co_signer: Pubkey::new_from_array([2u8; 32]),
                max_proposal_lifetime: 3600,
                auditor_keys: vec![[3u8; 33]],
                merge_authorities: vec![Pubkey::new_from_array([4u8; 32])],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::CREATE_ZONE_CONFIG);
        assert_eq!(ix.accounts.len(), 5);
        // creator signs and is writable.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // The program and canonical ProgramData accounts trail read-only.
        assert_eq!(ix.accounts[3].pubkey, PROGRAM_ID_PUBKEY);
        let expected_program_data = Pubkey::find_program_address(
            &[PROGRAM_ID_PUBKEY.as_ref()],
            &zolana_interface::BPF_LOADER_UPGRADEABLE_PUBKEY,
        )
        .0;
        assert_eq!(ix.accounts[4].pubkey, expected_program_data);
        assert!(!ix.accounts[3].is_writable && !ix.accounts[4].is_writable);
    }
}

mod deposit {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{
            builders::{Deposit, DepositSettlement},
            tag, DepositIxData,
        },
        PROGRAM_ID_PUBKEY,
    };

    fn data() -> DepositIxData {
        DepositIxData {
            view_tag: [7u8; 32],
            asset: zolana_interface::instruction::DepositAssetKind::Sol,
            amount: 7,
            blinding: [8u8; 32],
            encrypted: zolana_interface::instruction::EncryptedRingDepositData {
                tx_viewing_pk: [9u8; 33],
                salt: [10u8; 16],
                ciphertext: vec![11u8; 8],
            },
        }
    }

    #[test]
    fn builds_sol_instruction() {
        let ix = Deposit {
            depositor: Pubkey::new_from_array([1; 32]),
            recipient_viewing_key_account: Pubkey::new_from_array([2; 32]),
            ring_auth: Pubkey::new_from_array([3; 32]),
            spp_program: Pubkey::new_from_array([4; 32]),
            tree: Pubkey::new_from_array([5; 32]),
            settlement: DepositSettlement::Sol {
                sol_interface: Pubkey::new_from_array([6; 32]),
            },
            data: data(),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data.first().copied(), Some(tag::DEPOSIT));
        // depositor, recipient_vka, ring_auth, spp_program, tree + 3 SOL accounts.
        assert_eq!(ix.accounts.len(), 8);
        let depositor = ix.accounts.first().expect("depositor");
        assert!(depositor.is_signer && depositor.is_writable);
    }

    #[test]
    fn builds_spl_instruction() {
        let ix = Deposit {
            depositor: Pubkey::new_from_array([1; 32]),
            recipient_viewing_key_account: Pubkey::new_from_array([2; 32]),
            ring_auth: Pubkey::new_from_array([3; 32]),
            spp_program: Pubkey::new_from_array([4; 32]),
            tree: Pubkey::new_from_array([5; 32]),
            settlement: DepositSettlement::Spl {
                user_token: Pubkey::new_from_array([6; 32]),
                vault: Pubkey::new_from_array([7; 32]),
                registry: Pubkey::new_from_array([8; 32]),
                token_program: Pubkey::new_from_array([9; 32]),
            },
            data: data(),
        }
        .instruction();

        // depositor, recipient_vka, ring_auth, spp_program, tree + 4 SPL accounts.
        assert_eq!(ix.accounts.len(), 9);
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
            zone_config: Pubkey::new_from_array([1; 32]),
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
        // executor, co_signer, vka, zone_config, proposal, rent_recipient,
        // system_program, program (self-CPI).
        assert_eq!(ix.accounts.len(), 8);
        // executor signs and is writable (fee payer).
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        // co_signer signs.
        assert!(ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[7].pubkey, PROGRAM_ID_PUBKEY);
    }
}

mod execute_proposal {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::ExecuteProposal, tag, EncryptedUtxos, ExecuteProposalIxData},
        PROGRAM_ID_PUBKEY,
    };

    fn ix_data() -> ExecuteProposalIxData {
        ExecuteProposalIxData {
            zone_proof: [1u8; 192],
            spp_proof: [2u8; 192],
            public_amount: None,
            spl_interface_bump: 0,
            private_tx_hash: [3u8; 32],
            salt: [7u8; 16],
            output_view_tags: vec![[8u8; 32]],
            output_utxo_hashes: vec![[4u8; 32]],
            input_contexts: vec![],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [5u8; 33],
                sender_ciphertext: [6u8; 40],
                recipient_ciphertexts: vec![],
            },
        }
    }

    #[test]
    fn builds_transfer_instruction() {
        let ix = ExecuteProposal {
            payer: Pubkey::new_from_array([1; 32]),
            co_signer: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
            proposal: Pubkey::new_from_array([1; 32]),
            sender_viewing_key_account: Pubkey::new_from_array([1; 32]),
            recipient_viewing_key_account: Some(Pubkey::new_from_array([1; 32])),
            withdrawal: None,
            rent_recipient: Pubkey::new_from_array([1; 32]),
            ring_auth: Pubkey::new_from_array([1; 32]),
            spp_program: Pubkey::new_from_array([1; 32]),
            tree_accounts: vec![Pubkey::new_from_array([1; 32])],
            data: ix_data(),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::EXECUTE_PROPOSAL);
        // payer, co_signer, zone_config, proposal, sender, recipient,
        // rent_recipient, ring_auth, spp_program, 1 tree.
        assert_eq!(ix.accounts.len(), 10);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
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

mod full_withdrawal {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{
            builders::{FullWithdrawal, TransactWithdrawal},
            tag, EncryptedUtxos, FullWithdrawalIxData,
        },
        PROGRAM_ID_PUBKEY,
    };

    fn data() -> FullWithdrawalIxData {
        FullWithdrawalIxData {
            spp_proof: [1u8; 192],
            public_amount: 100,
            spl_interface_bump: 0,
            private_tx_hash: [2u8; 32],
            expiry: 0,
            salt: [3u8; 16],
            output_view_tags: vec![[4u8; 32]],
            output_utxo_hashes: vec![[5u8; 32]],
            input_contexts: vec![],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [6u8; 33],
                sender_ciphertext: [7u8; 40],
                recipient_ciphertexts: vec![],
            },
        }
    }

    #[test]
    fn builds_sol_instruction() {
        let ix = FullWithdrawal {
            payer: Pubkey::new_from_array([1; 32]),
            ring_auth: Pubkey::new_from_array([3; 32]),
            spp_program: Pubkey::new_from_array([4; 32]),
            tree: Pubkey::new_from_array([5; 32]),
            settlement: TransactWithdrawal::Sol {
                sol_interface: Pubkey::new_from_array([6; 32]),
                recipient: Pubkey::new_from_array([7; 32]),
            },
            data: data(),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data.first().copied(), Some(tag::FULL_WITHDRAWAL));
        // payer, ring_auth, spp_program, tree + 3 SOL settlement accounts.
        assert_eq!(ix.accounts.len(), 7);
        let payer = ix.accounts.first().expect("payer");
        assert!(payer.is_signer && payer.is_writable);
    }

    #[test]
    fn builds_spl_instruction() {
        let ix = FullWithdrawal {
            payer: Pubkey::new_from_array([1; 32]),
            ring_auth: Pubkey::new_from_array([3; 32]),
            spp_program: Pubkey::new_from_array([4; 32]),
            tree: Pubkey::new_from_array([5; 32]),
            settlement: TransactWithdrawal::Spl {
                cpi_authority: Pubkey::new_from_array([6; 32]),
                mint: Pubkey::new_from_array([7; 32]),
                spl_interface: Pubkey::new_from_array([8; 32]),
                user_token_account: Pubkey::new_from_array([9; 32]),
                token_program: Pubkey::new_from_array([10; 32]),
            },
            data: data(),
        }
        .instruction();

        // payer, ring_auth, spp_program, tree + 5 SPL settlement accounts.
        assert_eq!(ix.accounts.len(), 9);
    }
}

mod init_spp_zone_config {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::builders::InitSppZoneConfig, instruction::tag, PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = InitSppZoneConfig {
            authority: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([2; 32]),
            protocol_config: Pubkey::new_from_array([3; 32]),
            ring_auth: Pubkey::new_from_array([4; 32]),
            system_program: Pubkey::new_from_array([5; 32]),
            spp_program: Pubkey::new_from_array([6; 32]),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data, vec![tag::INIT_SPP_ZONE_CONFIG]);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[0].is_signer);
    }
}

mod merge_transact {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::MergeTransact, tag, MergeTransactIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = MergeTransact {
            merge_authority: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
            owner_viewing_key_account: Pubkey::new_from_array([1; 32]),
            ring_auth: Pubkey::new_from_array([1; 32]),
            spp_program: Pubkey::new_from_array([1; 32]),
            tree_accounts: vec![
                Pubkey::new_from_array([1; 32]),
                Pubkey::new_from_array([1; 32]),
            ],
            data: MergeTransactIxData {
                spp_proof: [2u8; 192],
                expiry_unix_ts: 1_700_000_000,
                output_ring_data_hash: [5u8; 32],
                private_tx_hash: [3u8; 32],
                output_utxo_hash: [4u8; 32],
                input_contexts: vec![],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::MERGE_TRANSACT);
        // merge_authority, zone_config, owner vka, ring_auth, spp_program, 2 trees.
        assert_eq!(ix.accounts.len(), 7);
        // merge_authority signs and is writable (fee payer).
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
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
            authority: Pubkey::new_from_array([1; 32]),
            viewing_key_account: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
            data: ToggleViewingKeyAccountIxData { state: 1 },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::TOGGLE_VIEWING_KEY_ACCOUNT);
        assert_eq!(ix.accounts.len(), 3);
        // The authority signs.
        assert!(ix.accounts[0].is_signer);
    }
}

mod transact {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{
            builders::{Transact, TransactWithdrawal},
            tag, EncryptedUtxos, TransactIxData,
        },
        PROGRAM_ID_PUBKEY,
    };

    fn ix_data() -> TransactIxData {
        TransactIxData {
            zone_proof: [1u8; 192],
            spp_proof: [2u8; 192],
            public_amount: None,
            spl_interface_bump: 0,
            private_tx_hash: [3u8; 32],
            expiry: 0,
            salt: [7u8; 16],
            output_view_tags: vec![[8u8; 32]],
            output_utxo_hashes: vec![[4u8; 32]],
            input_contexts: vec![],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [5u8; 33],
                sender_ciphertext: [6u8; 40],
                recipient_ciphertexts: vec![],
            },
        }
    }

    #[test]
    fn builds_transfer_instruction() {
        let ix = Transact {
            payer: Pubkey::new_from_array([1; 32]),
            co_signer: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
            sender_viewing_key_account: Pubkey::new_from_array([1; 32]),
            recipient_viewing_key_account: Some(Pubkey::new_from_array([1; 32])),
            withdrawal: None,
            ring_auth: Pubkey::new_from_array([1; 32]),
            spp_program: Pubkey::new_from_array([1; 32]),
            tree_accounts: vec![Pubkey::new_from_array([1; 32])],
            data: ix_data(),
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::TRANSACT);
        // payer, co_signer, zone_config, sender, recipient, ring_auth,
        // spp_program, 1 tree.
        assert_eq!(ix.accounts.len(), 8);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(ix.accounts[1].is_signer);
    }

    #[test]
    fn builds_sol_withdrawal_instruction() {
        let ix = Transact {
            payer: Pubkey::new_from_array([1; 32]),
            co_signer: Pubkey::new_from_array([2; 32]),
            zone_config: Pubkey::new_from_array([3; 32]),
            sender_viewing_key_account: Pubkey::new_from_array([4; 32]),
            recipient_viewing_key_account: None,
            withdrawal: Some(TransactWithdrawal::Sol {
                sol_interface: Pubkey::new_from_array([5; 32]),
                recipient: Pubkey::new_from_array([6; 32]),
            }),
            ring_auth: Pubkey::new_from_array([7; 32]),
            spp_program: Pubkey::new_from_array([8; 32]),
            tree_accounts: vec![Pubkey::new_from_array([9; 32])],
            data: ix_data(),
        }
        .instruction();

        // payer, co_signer, zone_config, sender, ring_auth, spp_program (6),
        // 1 tree, then SOL settlement [sol_interface, recipient, system_program].
        assert_eq!(ix.accounts.len(), 10);
        let payer = ix.accounts.first().expect("payer");
        assert!(payer.is_signer && payer.is_writable);
        assert!(ix.accounts.get(1).expect("co_signer").is_signer);
    }

    #[test]
    fn builds_spl_withdrawal_instruction() {
        let ix = Transact {
            payer: Pubkey::new_from_array([1; 32]),
            co_signer: Pubkey::new_from_array([2; 32]),
            zone_config: Pubkey::new_from_array([3; 32]),
            sender_viewing_key_account: Pubkey::new_from_array([4; 32]),
            recipient_viewing_key_account: None,
            withdrawal: Some(TransactWithdrawal::Spl {
                cpi_authority: Pubkey::new_from_array([5; 32]),
                mint: Pubkey::new_from_array([6; 32]),
                spl_interface: Pubkey::new_from_array([7; 32]),
                user_token_account: Pubkey::new_from_array([8; 32]),
                token_program: Pubkey::new_from_array([9; 32]),
            }),
            ring_auth: Pubkey::new_from_array([10; 32]),
            spp_program: Pubkey::new_from_array([11; 32]),
            tree_accounts: vec![Pubkey::new_from_array([12; 32])],
            data: ix_data(),
        }
        .instruction();

        // 6 fixed + 1 tree + 5 SPL settlement accounts.
        assert_eq!(ix.accounts.len(), 12);
        let keys: Vec<_> = ix.accounts.iter().map(|meta| meta.pubkey).collect();
        assert_eq!(
            &keys[7..],
            &[
                Pubkey::new_from_array([5; 32]),
                Pubkey::new_from_array([6; 32]),
                Pubkey::new_from_array([7; 32]),
                Pubkey::new_from_array([8; 32]),
                Pubkey::new_from_array([9; 32]),
            ]
        );
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
            zone_config: Pubkey::new_from_array([1; 32]),
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

mod update_zone_config {
    use super::Pubkey;
    use zolana_squads_interface::{
        instruction::{builders::UpdateZoneConfig, tag, UpdateZoneConfigIxData},
        PROGRAM_ID_PUBKEY,
    };

    #[test]
    fn builds_instruction() {
        let ix = UpdateZoneConfig {
            authority: Pubkey::new_from_array([1; 32]),
            zone_config: Pubkey::new_from_array([1; 32]),
            data: UpdateZoneConfigIxData {
                authority: Pubkey::new_from_array([1u8; 32]),
                co_signer: Pubkey::new_from_array([2u8; 32]),
                max_proposal_lifetime: 3600,
                auditor_keys: vec![[3u8; 33]],
                merge_authorities: vec![Pubkey::new_from_array([4u8; 32])],
            },
        }
        .instruction();

        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data[0], tag::UPDATE_ZONE_CONFIG);
        assert_eq!(ix.accounts.len(), 2);
        // authority signs.
        assert!(ix.accounts[0].is_signer);
    }
}
