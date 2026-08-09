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

    #[test]
    fn key_rotation_commitment_binds_policy_and_nonce() {
        let account = sample(2, 1);
        let commitment = account
            .key_rotation_commitment()
            .expect("key rotation commitment");
        assert_eq!(
            commitment,
            [
                19, 168, 245, 150, 1, 180, 242, 109, 4, 95, 102, 170, 162, 243, 26, 166, 231, 74,
                200, 2, 97, 191, 26, 105, 103, 155, 53, 137, 207, 251, 87, 157,
            ]
        );

        let mut mutations = Vec::new();

        let mut changed = account.clone();
        changed.owner = Address::new_from_array([11u8; 32]);
        mutations.push(changed);

        let mut changed = account.clone();
        changed.shared_viewing_key_commitment[31] ^= 1;
        mutations.push(changed);

        let mut changed = account.clone();
        changed.nullifier_pubkey[31] ^= 1;
        mutations.push(changed);

        let mut changed = account.clone();
        changed.state ^= 1;
        mutations.push(changed);

        let mut changed = account.clone();
        changed.owner_kind ^= 1;
        mutations.push(changed);

        let mut changed = account.clone();
        changed.encryption_scheme ^= 1;
        mutations.push(changed);

        let mut changed = account.clone();
        changed.key_nonce += 1;
        mutations.push(changed);

        for changed in mutations {
            assert_ne!(
                changed
                    .key_rotation_commitment()
                    .expect("changed commitment"),
                commitment
            );
        }

        // Ciphertexts and recipient lists are deliberately absent: rotating
        // them is what the key-encryption proof authorizes.
        let mut ciphertext_only = account;
        ciphertext_only.encrypted_nullifier_secret[0] ^= 1;
        ciphertext_only.recovery_key_ciphertexts[0][0] ^= 1;
        assert_eq!(
            ciphertext_only
                .key_rotation_commitment()
                .expect("ciphertext-independent commitment"),
            commitment
        );
    }
}

mod key_update_proposal {
    use zolana_squads_interface::state::{KeyOperation, KeyUpdateProposal, OpenKeyUpdateProposal};
    use zolana_squads_interface::types::Address;

    #[test]
    fn round_trip_and_size() {
        let mut proposal = KeyUpdateProposal::from(OpenKeyUpdateProposal {
            domain: 5,
            target: Address::new_from_array([1u8; 32]),
            key_nonce: 11,
            operations: vec![
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
            expiry: 9_999,
            executor: Address::new_from_array([7u8; 32]),
            rent_payer: Address::new_from_array([8u8; 32]),
        });
        proposal.new_key_ciphertexts = vec![[4u8; 32], [5u8; 32], [6u8; 32]];
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
