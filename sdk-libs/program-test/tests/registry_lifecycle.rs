use light_program_test::{
    registry_sdk::{
        decode_anchor_account, epoch_pda, forester_epoch_pda, forester_pda, protocol_config_pda,
        EpochPda, ForesterEpochPda, ForesterPda, ProtocolConfigPda,
    },
    ForesterConfig, PoolTestRig, ProtocolConfig, RigError,
};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(mut r) => {
            r.airdrop(&r.payer.pubkey(), 5_000_000_000).ok();
            match r.load_registry() {
                Ok(()) => Some(r),
                Err(RigError::MissingProgram(_)) => {
                    eprintln!("skipping registry lifecycle test: light_registry.so missing");
                    None
                }
                Err(e) => panic!("load_registry failed: {e}"),
            }
        }
        Err(RigError::MissingProgram(_)) => {
            eprintln!("skipping registry lifecycle test: shielded_pool_program.so missing");
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

fn decode_account<T: borsh::BorshDeserialize>(rig: &PoolTestRig, pubkey: Pubkey) -> T {
    let data = rig.account_data(&pubkey).expect("account data");
    decode_anchor_account(&data).expect("anchor account decode")
}

fn err_string<T>(result: Result<T, RigError>) -> String {
    match result {
        Ok(_) => panic!("instruction must fail"),
        Err(err) => format!("{err}"),
    }
}

fn assert_fails<T>(result: Result<T, RigError>, label: &str) -> String {
    let msg = err_string(result);
    assert!(!msg.is_empty(), "{label} returned an empty error");
    msg
}

#[test]
fn registry_setup_persists_pdas_and_finalize_is_phase_gated() {
    let Some(mut rig) = rig() else {
        return;
    };

    let governance_authority = Keypair::new();
    rig.airdrop(&governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop governance authority");

    let config = ProtocolConfig {
        registration_phase_length: 5,
        active_phase_length: 100,
        ..ProtocolConfig::default()
    };
    rig.initialize_protocol_config(&governance_authority, config)
        .expect("initialize_protocol_config");

    let (protocol_config_key, protocol_config_bump) = protocol_config_pda();
    let protocol_config_account: ProtocolConfigPda = decode_account(&rig, protocol_config_key);
    assert_eq!(
        protocol_config_account.authority,
        governance_authority.pubkey().to_bytes()
    );
    assert_eq!(protocol_config_account.bump, protocol_config_bump);
    assert_eq!(protocol_config_account.config, config);

    let forester = Keypair::new();
    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");
    let forester_config = ForesterConfig { fee: 42 };
    rig.register_forester(
        &governance_authority,
        &forester.pubkey(),
        forester_config,
        Some(3),
    )
    .expect("register_forester");

    let (forester_key, _) = forester_pda(&forester.pubkey());
    let forester_account: ForesterPda = decode_account(&rig, forester_key);
    assert_eq!(forester_account.authority, forester.pubkey().to_bytes());
    assert_eq!(forester_account.config.fee, 42);
    assert_eq!(forester_account.active_weight, 3);

    rig.register_forester_epoch(&forester, 0)
        .expect("register_forester_epoch");

    let (epoch_key, _) = epoch_pda(0);
    let epoch_account: EpochPda = decode_account(&rig, epoch_key);
    assert_eq!(epoch_account.epoch, 0);
    assert_eq!(epoch_account.protocol_config, config);
    assert_eq!(epoch_account.registered_weight, 3);

    let (forester_epoch_key, _) = forester_epoch_pda(&forester_key, 0);
    let forester_epoch_account: ForesterEpochPda = decode_account(&rig, forester_epoch_key);
    assert_eq!(
        forester_epoch_account.authority,
        forester.pubkey().to_bytes()
    );
    assert_eq!(forester_epoch_account.weight, 3);
    assert_eq!(forester_epoch_account.forester_index, 0);
    assert_eq!(
        forester_epoch_account.epoch_active_phase_start_slot,
        config.registration_phase_length
    );
    assert_eq!(forester_epoch_account.total_epoch_weight, None);

    let msg = assert_fails(
        rig.finalize_registration(&forester, 0),
        "finalize before active phase",
    );
    assert!(
        msg.contains("Custom(6009)")
            || msg.contains("Custom(6023)")
            || msg.contains("InvalidEpoch")
            || msg.contains("GetCurrentActiveEpochFailed"),
        "unexpected finalize-before-active error: {msg}"
    );

    rig.warp_to_slot(config.registration_phase_length + 1)
        .expect("warp to active phase");
    rig.svm.expire_blockhash();
    rig.finalize_registration(&forester, 0)
        .expect("finalize_registration");

    let forester_epoch_account: ForesterEpochPda = decode_account(&rig, forester_epoch_key);
    assert_eq!(forester_epoch_account.total_epoch_weight, Some(3));
    assert_eq!(forester_epoch_account.finalize_counter, 1);
}

#[test]
fn registry_rejects_wrong_authority_and_duplicate_registration() {
    let Some(mut rig) = rig() else {
        return;
    };

    let governance_authority = Keypair::new();
    let wrong_authority = Keypair::new();
    rig.airdrop(&governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop governance authority");
    rig.airdrop(&wrong_authority.pubkey(), 1_000_000_000)
        .expect("airdrop wrong authority");

    rig.initialize_protocol_config(&governance_authority, ProtocolConfig::default())
        .expect("initialize_protocol_config");

    let forester = Keypair::new();
    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");

    assert_fails(
        rig.register_forester(
            &wrong_authority,
            &forester.pubkey(),
            ForesterConfig::default(),
            Some(1),
        ),
        "register with wrong governance authority",
    );

    rig.register_forester(
        &governance_authority,
        &forester.pubkey(),
        ForesterConfig::default(),
        Some(1),
    )
    .expect("register_forester");

    assert_fails(
        rig.register_forester(
            &governance_authority,
            &forester.pubkey(),
            ForesterConfig::default(),
            Some(1),
        ),
        "duplicate forester registration",
    );

    rig.register_forester_epoch(&forester, 0)
        .expect("register_forester_epoch");
    assert_fails(
        rig.register_forester_epoch(&forester, 0),
        "duplicate forester epoch registration",
    );
}

#[test]
fn registry_rejects_missing_config_and_low_weight_epoch_registration() {
    let Some(mut rig) = rig() else {
        return;
    };

    let governance_authority = Keypair::new();
    rig.airdrop(&governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop governance authority");
    let forester = Keypair::new();

    assert_fails(
        rig.register_forester(
            &governance_authority,
            &forester.pubkey(),
            ForesterConfig::default(),
            Some(1),
        ),
        "register forester before protocol config",
    );

    let config = ProtocolConfig {
        min_weight: 5,
        ..ProtocolConfig::default()
    };
    rig.initialize_protocol_config(&governance_authority, config)
        .expect("initialize_protocol_config");

    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");
    rig.register_forester(
        &governance_authority,
        &forester.pubkey(),
        ForesterConfig::default(),
        Some(config.min_weight - 1),
    )
    .expect("register low-weight forester");

    let msg = assert_fails(
        rig.register_forester_epoch(&forester, 0),
        "register low-weight forester for epoch",
    );
    assert!(
        msg.contains("Custom(6006)") || msg.contains("WeightInsuffient"),
        "unexpected low-weight registration error: {msg}"
    );
}

#[test]
fn registry_updates_protocol_config_and_forester_state() {
    let Some(mut rig) = rig() else {
        return;
    };

    let governance_authority = Keypair::new();
    let new_governance_authority = Keypair::new();
    rig.airdrop(&governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop governance authority");
    rig.airdrop(&new_governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop new governance authority");

    let initial_config = ProtocolConfig::default();
    rig.initialize_protocol_config(&governance_authority, initial_config)
        .expect("initialize_protocol_config");

    let updated_config = ProtocolConfig {
        min_weight: 2,
        registration_phase_length: 50,
        report_work_phase_length: 50,
        ..initial_config
    };
    rig.update_protocol_config(
        &governance_authority,
        Some(&new_governance_authority),
        Some(updated_config),
    )
    .expect("update_protocol_config");

    let (protocol_config_key, _) = protocol_config_pda();
    let protocol_config_account: ProtocolConfigPda = decode_account(&rig, protocol_config_key);
    assert_eq!(
        protocol_config_account.authority,
        new_governance_authority.pubkey().to_bytes()
    );
    assert_eq!(protocol_config_account.config, updated_config);

    let invalid_config = ProtocolConfig {
        min_weight: 0,
        ..updated_config
    };
    let msg = assert_fails(
        rig.update_protocol_config(
            &new_governance_authority,
            Some(&new_governance_authority),
            Some(invalid_config),
        ),
        "update protocol config with invalid values",
    );
    assert!(
        msg.contains("Custom(6020)") || msg.contains("InvalidConfigUpdate"),
        "unexpected invalid-config error: {msg}"
    );

    let forester = Keypair::new();
    let replacement_forester = Keypair::new();
    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");
    rig.airdrop(&replacement_forester.pubkey(), 1_000_000_000)
        .expect("airdrop replacement forester");
    rig.register_forester(
        &new_governance_authority,
        &forester.pubkey(),
        ForesterConfig { fee: 1 },
        Some(updated_config.min_weight),
    )
    .expect("register_forester");

    rig.update_forester_pda_weight(&new_governance_authority, &forester.pubkey(), 8)
        .expect("update forester weight");
    let (forester_key, _) = forester_pda(&forester.pubkey());
    let forester_account: ForesterPda = decode_account(&rig, forester_key);
    assert_eq!(forester_account.active_weight, 8);

    assert_fails(
        rig.update_forester_pda_weight(&governance_authority, &forester.pubkey(), 9),
        "update forester weight with old governance authority",
    );

    rig.update_forester_pda(
        &forester,
        &forester.pubkey(),
        Some(&replacement_forester),
        Some(ForesterConfig { fee: 9 }),
    )
    .expect("update forester pda");
    let forester_account: ForesterPda = decode_account(&rig, forester_key);
    assert_eq!(
        forester_account.authority,
        replacement_forester.pubkey().to_bytes()
    );
    assert_eq!(forester_account.config.fee, 9);

    assert_fails(
        rig.update_forester_pda(
            &forester,
            &forester.pubkey(),
            Some(&forester),
            Some(ForesterConfig { fee: 10 }),
        ),
        "update forester pda with old authority",
    );
}

#[test]
fn registry_report_work_is_phase_gated_and_idempotent() {
    let Some(mut rig) = rig() else {
        return;
    };

    let governance_authority = Keypair::new();
    rig.airdrop(&governance_authority.pubkey(), 1_000_000_000)
        .expect("airdrop governance authority");
    let config = ProtocolConfig {
        slot_length: 1,
        registration_phase_length: 2,
        active_phase_length: 10,
        report_work_phase_length: 3,
        ..ProtocolConfig::default()
    };
    rig.initialize_protocol_config(&governance_authority, config)
        .expect("initialize_protocol_config");

    let forester = Keypair::new();
    rig.airdrop(&forester.pubkey(), 1_000_000_000)
        .expect("airdrop forester");
    rig.register_forester(
        &governance_authority,
        &forester.pubkey(),
        ForesterConfig::default(),
        Some(1),
    )
    .expect("register_forester");
    rig.register_forester_epoch(&forester, 0)
        .expect("register_forester_epoch");

    rig.warp_to_slot(config.registration_phase_length + 1)
        .expect("warp to active phase");
    rig.finalize_registration(&forester, 0)
        .expect("finalize_registration");

    let msg = assert_fails(
        rig.report_work(&forester, 0),
        "report work before report phase",
    );
    assert!(
        msg.contains("Custom(6011)") || msg.contains("NotInActivePhase"),
        "unexpected early report-work error: {msg}"
    );

    rig.warp_to_slot(config.registration_phase_length + config.active_phase_length)
        .expect("warp to report phase");
    rig.svm.expire_blockhash();
    rig.report_work(&forester, 0).expect("report_work");

    let (forester_key, _) = forester_pda(&forester.pubkey());
    let (forester_epoch_key, _) = forester_epoch_pda(&forester_key, 0);
    let forester_epoch_account: ForesterEpochPda = decode_account(&rig, forester_epoch_key);
    assert!(forester_epoch_account.has_reported_work);

    let (epoch_key, _) = epoch_pda(0);
    let epoch_account: EpochPda = decode_account(&rig, epoch_key);
    assert_eq!(epoch_account.total_work, 0);

    rig.svm.expire_blockhash();
    let msg = assert_fails(rig.report_work(&forester, 0), "duplicate report work");
    assert!(
        msg.contains("Custom(6012)") || msg.contains("ForesterAlreadyReportedWork"),
        "unexpected duplicate report-work error: {msg}"
    );
}
