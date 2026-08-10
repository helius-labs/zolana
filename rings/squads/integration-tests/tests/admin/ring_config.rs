use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_squads_interface::{
    error::SquadsRingError,
    instruction::{
        builders::{CreateRingConfig, UpdateRingConfig},
        CreateRingConfigIxData, UpdateRingConfigIxData,
    },
    state::ring_config::SquadsRingConfig,
    RING_CONFIG_PDA_SEED,
};

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

fn auditor_key(seed: u8) -> [u8; 33] {
    [seed; 33]
}

#[test]
fn create_ring_config_happy_path() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    test.install_upgradeable_deploy(Some(&creator.pubkey()))
        .expect("install loader-v3 deployment");

    let ring_config = ring_config_pda(&program_id);
    let authority = Pubkey::new_from_array([7u8; 32]);
    let co_signer = Pubkey::new_from_array([8u8; 32]);
    let auditor = auditor_key(9);
    let merge_authorities = vec![
        Pubkey::new_from_array([10u8; 32]),
        Pubkey::new_from_array([11u8; 32]),
    ];

    let ix = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority,
            co_signer,
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor],
            merge_authorities: merge_authorities.clone(),
        },
    }
    .instruction();

    test.send(&[ix], &[&creator]).expect("create_ring_config");

    let data = test.account_data(&ring_config).expect("ring_config exists");
    let config = SquadsRingConfig::deserialize(&data).expect("deserialize ring_config");

    assert_eq!(config.discriminator, SquadsRingConfig::DISCRIMINATOR);
    assert_eq!(config.authority.to_bytes(), authority.to_bytes());
    assert_eq!(config.co_signer.to_bytes(), co_signer.to_bytes());
    assert_eq!(config.max_proposal_lifetime, 3_600);
    assert_eq!(config.auditor_keys, vec![auditor]);
    assert_eq!(
        config
            .merge_authorities
            .iter()
            .map(|a| a.to_bytes())
            .collect::<Vec<_>>(),
        merge_authorities
            .iter()
            .map(|a| a.to_bytes())
            .collect::<Vec<_>>(),
    );
}

#[test]
fn create_ring_config_rejects_non_upgrade_authority() {
    let mut test = SquadsRingTest::new().expect("boot");
    let deployer = Keypair::new();
    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    test.install_upgradeable_deploy(Some(&deployer.pubkey()))
        .expect("install loader-v3 deployment");

    let ring_config = ring_config_pda(&test.program_id);
    let ix = CreateRingConfig {
        creator: attacker.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: attacker.pubkey(),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor_key(9)],
            merge_authorities: vec![],
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("non-upgrade-authority must not initialize the singleton");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidInitializationAuthority as u32,
    );
    assert!(test.account_data(&ring_config).is_none());
}

#[test]
fn create_ring_config_rejects_wrong_auditor_count() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    test.install_upgradeable_deploy(Some(&creator.pubkey()))
        .expect("install loader-v3 deployment");

    let ring_config = ring_config_pda(&program_id);

    // Two auditor keys instead of the required one.
    let ix = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: Pubkey::new_from_array([7u8; 32]),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor_key(1), auditor_key(2)],
            merge_authorities: vec![],
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&creator])
        .expect_err("expected InvalidAuditorKeyCount");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidAuditorKeyCount as u32,
    );
    assert_eq!(custom_code(&err), 8026);
}

#[test]
fn update_ring_config_happy_path() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    test.install_upgradeable_deploy(Some(&creator.pubkey()))
        .expect("install loader-v3 deployment");

    let ring_config = ring_config_pda(&program_id);

    let authority = Keypair::new();
    let auditor = auditor_key(9);

    let create = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: authority.pubkey(),
            co_signer: Pubkey::new_from_array([8u8; 32]),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor],
            merge_authorities: vec![Pubkey::new_from_array([10u8; 32])],
        },
    }
    .instruction();
    test.send(&[create], &[&creator])
        .expect("create_ring_config");

    // The update instruction has no fee payer, so a merge-authority count
    // change that grows the account would fail rent exemption with
    // InvalidAccountSize. The count stays constant to avoid a resize.
    let new_co_signer = Pubkey::new_from_array([21u8; 32]);
    let new_merge = vec![Pubkey::new_from_array([22u8; 32])];
    let update = UpdateRingConfig {
        authority: authority.pubkey(),
        ring_config,
        data: UpdateRingConfigIxData {
            authority: authority.pubkey(),
            co_signer: new_co_signer,
            max_proposal_lifetime: 7_200,
            auditor_keys: vec![auditor],
            merge_authorities: new_merge.clone(),
        },
    }
    .instruction();
    test.send(&[update], &[&authority])
        .expect("update_ring_config");

    let data = test.account_data(&ring_config).expect("ring_config exists");
    let config = SquadsRingConfig::deserialize(&data).expect("deserialize ring_config");
    assert_eq!(config.co_signer.to_bytes(), new_co_signer.to_bytes());
    assert_eq!(config.max_proposal_lifetime, 7_200);
    assert_eq!(
        config
            .merge_authorities
            .iter()
            .map(|a| a.to_bytes())
            .collect::<Vec<_>>(),
        new_merge.iter().map(|a| a.to_bytes()).collect::<Vec<_>>(),
    );
}

#[test]
fn update_ring_config_rejects_when_frozen() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    test.install_upgradeable_deploy(Some(&creator.pubkey()))
        .expect("install loader-v3 deployment");

    let ring_config = ring_config_pda(&program_id);
    let authority = Keypair::new();
    let auditor = auditor_key(9);

    let create = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: authority.pubkey(),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[create], &[&creator])
        .expect("create_ring_config");

    // Setting authority to default freezes the config.
    let freeze = UpdateRingConfig {
        authority: authority.pubkey(),
        ring_config,
        data: UpdateRingConfigIxData {
            authority: Pubkey::default(),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[freeze], &[&authority])
        .expect("freeze ring_config");

    // The frozen check runs before the authority comparison, so any update on a
    // frozen config is rejected with ConfigFrozen.
    let again = UpdateRingConfig {
        authority: authority.pubkey(),
        ring_config,
        data: UpdateRingConfigIxData {
            authority: authority.pubkey(),
            co_signer: Pubkey::new_from_array([99u8; 32]),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![auditor],
            merge_authorities: vec![],
        },
    }
    .instruction();
    let err = test
        .send(&[again], &[&authority])
        .expect_err("expected ConfigFrozen");
    assert_eq!(custom_code(&err), SquadsRingError::ConfigFrozen as u32);
    assert_eq!(custom_code(&err), 8025);
}
