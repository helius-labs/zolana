mod zone_config {
    use zolana_squads_interface::{state::ZoneConfig, types::Address};

    #[test]
    fn round_trip_and_size() {
        let config = ZoneConfig::new(
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
            3_600,
            vec![[3u8; 33]],
            vec![
                Address::new_from_array([4u8; 32]),
                Address::new_from_array([5u8; 32]),
            ],
        );
        let bytes = config.serialize().expect("serialize");
        assert_eq!(bytes.len(), ZoneConfig::account_size(1, 2));
        assert_eq!(bytes.first().copied(), Some(ZoneConfig::DISCRIMINATOR));
        let decoded = ZoneConfig::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, config);
    }
}

mod proposal {
    use zolana_squads_interface::state::Proposal;
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip_and_size() {
        let proposal = Proposal::new(
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
            Address::new_from_array([3u8; 32]),
            [4u8; 32],
            [5u8; 88],
            1_234_567,
            Address::new_from_array([6u8; 32]),
        );
        let bytes = proposal.serialize().expect("serialize");
        assert_eq!(bytes.len(), Proposal::SIZE);
        assert_eq!(bytes.len(), Proposal::account_size());
        assert_eq!(bytes.first().copied(), Some(Proposal::DISCRIMINATOR));
        let decoded = Proposal::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, proposal);
    }
}

mod viewing_key_account {
    use zolana_squads_interface::constants::OWNER_KIND_KEYPAIR;
    use zolana_squads_interface::state::ViewingKeyAccount;
    use zolana_squads_interface::types::Address;

    fn sample(recovery: usize, auditor: usize) -> ViewingKeyAccount {
        ViewingKeyAccount {
            discriminator: ViewingKeyAccount::DISCRIMINATOR,
            owner: Address::new_from_array([1u8; 32]),
            state: 0,
            encryption_scheme: 1,
            owner_kind: OWNER_KIND_KEYPAIR,
            shared_viewing_key: [2u8; 33],
            shared_viewing_key_commitment: [3u8; 32],
            key_nonce: 7,
            nullifier_pubkey: [4u8; 32],
            key_ciphertext_ephemeral: [5u8; 33],
            encrypted_nullifier_secret: [6u8; 31],
            recovery_keys: vec![[7u8; 33]; recovery],
            recovery_key_ciphertexts: vec![[8u8; 32]; recovery],
            auditor_keys: vec![[9u8; 33]; auditor],
            auditor_key_ciphertexts: vec![[10u8; 32]; auditor],
        }
    }

    #[test]
    fn round_trip_and_size() {
        let account = sample(2, 1);
        let bytes = account.serialize().expect("serialize");
        assert_eq!(bytes.len(), ViewingKeyAccount::account_size(2, 1));
        assert_eq!(
            bytes.first().copied(),
            Some(ViewingKeyAccount::DISCRIMINATOR)
        );
        let decoded = ViewingKeyAccount::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, account);
    }
}

mod key_update_proposal {
    use zolana_squads_interface::state::{KeyOperation, KeyUpdateProposal};
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip_and_size() {
        let proposal = KeyUpdateProposal::new(
            5,
            Address::new_from_array([1u8; 32]),
            vec![
                KeyOperation {
                    op: 0,
                    index: 0,
                    key: [2u8; 33],
                },
                KeyOperation {
                    op: 2,
                    index: 1,
                    key: [3u8; 33],
                },
            ],
            vec![[4u8; 32], [5u8; 32], [6u8; 32]],
            9_999,
            Address::new_from_array([7u8; 32]),
            Address::new_from_array([8u8; 32]),
        );
        let bytes = proposal.serialize().expect("serialize");
        assert_eq!(bytes.len(), KeyUpdateProposal::account_size(2, 3));
        assert_eq!(
            bytes.first().copied(),
            Some(KeyUpdateProposal::DISCRIMINATOR)
        );
        let decoded = KeyUpdateProposal::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, proposal);
    }
}
