use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_program_error::ProgramError;
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{CreateProtocolConfig, CreateZoneConfig, UpdateProtocolConfigData},
    pda,
};
use zolana_mollusk_harness::{
    expect_err_atomic, mollusk_pubkey, sweep_account_matrix, AccountMutation, Expected,
};
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::litesvm_asserts::{assert_custom, assert_pool_error, assert_pool_error_at};

use crate::{
    common::{program_test, tree_account_size},
    mollusk::{pause_tree_fixture, protocol_config_fixture},
    support::Pool,
};

#[test]
fn duplicate_protocol_config_creation_is_rejected() {
    let mut rpc = program_test();
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");

    let err = rpc
        .create_protocol_config(&authority)
        .expect_err("duplicate config must fail");
    assert_custom(err, SystemError::AccountAlreadyInUse as u32);
}

#[test]
fn protocol_config_rejects_a_signer_that_names_other_authorities() {
    let mut rpc = program_test();
    let signer = Keypair::new();
    rpc.airdrop(&signer.pubkey(), 1_000_000_000)
        .expect("fund signer");
    let named = Keypair::new().pubkey().to_bytes();
    let ix = CreateProtocolConfig {
        authority: signer.pubkey(),
        protocol_authority: named.into(),
        tree_creation_authority: named.into(),
        tree_creation_is_permissionless: false,
        forester_authority: named.into(),
        zone_creation_authority: named.into(),
        zone_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();

    let err = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&signer])
        .expect_err("mismatched authority must fail");
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
    assert!(rpc.account_data(&pda::protocol_config()).is_none());
}

#[test]
fn tree_creation_rejects_unconfigured_authority() {
    let mut pool = Pool::initialized();
    let impostor = pool.funded_signer(1_000_000_000);

    let err = pool
        .rpc
        .create_tree(tree_account_size(), &impostor)
        .expect_err("impostor tree creation must fail");
    assert_pool_error_at(err, 1, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn pause_tree_rejects_unconfigured_authority_atomically() {
    let mut pool = Pool::initialized();
    let impostor = pool.funded_signer(1_000_000_000);

    let err = pool
        .rpc
        .pause_tree(&impostor, &pool.tree, true)
        .expect_err("impostor pause must fail");
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

#[test]
fn undersized_tree_creation_is_rejected() {
    let mut pool = Pool::initialized();

    let err = pool
        .rpc
        .create_tree(10_000, &pool.authority)
        .expect_err("undersized tree must fail");
    assert_pool_error_at(err, 1, ShieldedPoolError::InvalidTreeAccounts);
}

#[test]
fn pause_requires_a_protocol_config() {
    let mut rpc = program_test();
    let signer = Keypair::new();
    rpc.airdrop(&signer.pubkey(), 1_000_000_000)
        .expect("fund signer");
    let tree = Keypair::new();
    let err = rpc
        .pause_tree(&signer, &tree, true)
        .expect_err("pause without config must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn protocol_authority_rotation_revokes_old_authority() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");

    let err = pool
        .rpc
        .send_protocol_config_update(
            &old,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect_err("old authority must be revoked");
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn zone_config_owner_rotation_revokes_old_authority() {
    let mut rpc = program_test();
    rpc.load_zone_test_program()
        .expect("load zone test program");
    let admin = Keypair::new();
    rpc.create_protocol_config_permissionless(&admin)
        .expect("create permissionless protocol config");
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let zone_config = rpc
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create zone config");
    rpc.update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");
    let next = Keypair::new();
    rpc.update_zone_config_owner(&authority, &zone_config, &next)
        .expect("rotate zone config owner");

    let err = rpc
        .update_zone_config(&authority, &zone_config, true)
        .expect_err("old zone authority must be revoked");
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn zone_config_rejects_a_noncanonical_zone_authority_account() {
    let mut rpc = program_test();
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let mut ix = CreateZoneConfig {
        payer: payer.pubkey(),
        program_id: ZONE_TEST_PROGRAM_ID.into(),
        authority: payer.pubkey().to_bytes().into(),
        zone_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("derive zone config PDA");
    ix.accounts.get_mut(2).expect("zone config account").pubkey = payer.pubkey();

    let err = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&payer])
        .expect_err("noncanonical zone config must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidZoneConfig);
}

#[test]
fn mollusk_protocol_config_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = protocol_config_fixture();
    // Metas: [0] authority (signer, fee payer), [1] config PDA, [2] system
    // program. Signer and mutability cells have stable named errors; the
    // remaining downgrades shift the account shape, so only deterministic
    // atomic rejection is pinned.
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 0 } => {
            Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
        }
        AccountMutation::Readonly { index: 1 } => Expected::Err(ProgramError::Custom(u32::from(
            AccountError::AccountNotMutable,
        ))),
        _ => Expected::Rejected,
    });
}

#[test]
fn protocol_config_requires_system_program_exactly_and_atomically() {
    let (mollusk, valid, accounts) = protocol_config_fixture();
    let wrong_system = Pubkey::new_unique();
    let mut wrong_system_ix = valid;
    wrong_system_ix
        .accounts
        .get_mut(2)
        .expect("system program meta")
        .pubkey = mollusk_pubkey(&wrong_system);
    let mut wrong_system_accounts = accounts;
    *wrong_system_accounts
        .get_mut(2)
        .expect("system program account") = (
        mollusk_pubkey(&wrong_system),
        MolluskAccount {
            lamports: 1,
            data: Vec::new(),
            owner: MolluskPubkey::new_from_array([0; 32]),
            executable: false,
            rent_epoch: 0,
        },
    );

    expect_err_atomic(
        &mollusk,
        &wrong_system_ix,
        &wrong_system_accounts,
        ProgramError::IncorrectProgramId,
    );
}

#[test]
fn mollusk_pause_tree_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = pause_tree_fixture();
    // Metas: [0] authority (signer), [1] protocol config, [2] tree. Signer
    // and tree-mutability cells have stable named errors. Pause only reads
    // the config, so downgrading the builder's over-declared writable flag
    // on it must keep succeeding. The remaining downgrades shift the account
    // shape, so only deterministic atomic rejection is pinned.
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 0 } => {
            Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
        }
        AccountMutation::Readonly { index: 1 } => Expected::Success,
        AccountMutation::Readonly { index: 2 } => Expected::Err(ProgramError::Custom(u32::from(
            AccountError::AccountNotMutable,
        ))),
        _ => Expected::Rejected,
    });
}

#[test]
fn pause_tree_rejects_wrong_authority_exactly_and_atomically() {
    let (mollusk, valid, accounts) = pause_tree_fixture();
    let wrong_authority = Pubkey::new_unique();
    let mut wrong_authority_ix = valid;
    wrong_authority_ix
        .accounts
        .first_mut()
        .expect("authority meta")
        .pubkey = mollusk_pubkey(&wrong_authority);
    let mut wrong_authority_accounts = accounts;
    *wrong_authority_accounts
        .first_mut()
        .expect("authority account") = (
        mollusk_pubkey(&wrong_authority),
        MolluskAccount {
            lamports: 1_000_000_000,
            data: Vec::new(),
            owner: MolluskPubkey::new_from_array([0; 32]),
            executable: false,
            rent_epoch: 0,
        },
    );

    expect_err_atomic(
        &mollusk,
        &wrong_authority_ix,
        &wrong_authority_accounts,
        ProgramError::Custom(ShieldedPoolError::UnauthorizedCaller as u32),
    );
}

#[test]
fn pause_tree_rejects_wrong_config_owner_exactly_and_atomically() {
    let (mollusk, valid, accounts) = pause_tree_fixture();
    let mut wrong_config_accounts = accounts;
    wrong_config_accounts
        .get_mut(1)
        .expect("config account")
        .1
        .owner = MolluskPubkey::new_from_array([0x55; 32]);

    expect_err_atomic(
        &mollusk,
        &valid,
        &wrong_config_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidProtocolConfig as u32),
    );
}
