use solana_account::Account as MolluskAccount;
use solana_keypair::Keypair;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        CreateAssetCounter, CreateProtocolConfig, CreateProtocolConfigData, CreateTree,
        CreateZoneConfig, UpdateProtocolConfigData,
    },
    pda,
    state::address_tree_params,
};
use zolana_program_test::{system_create_account_ix, Rejection, Rpc, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::mollusk::{
    empty_placeholder_account, expect_err_exact, mollusk_pubkey, sweep_account_matrix,
    AccountMutation, Expected,
};
use zolana_tree::InitAddressTreeAccountsInstructionData;

use shielded_pool_tests::support::{
    fixtures::Pool,
    mollusk::{pause_tree_fixture, protocol_config_fixture},
    runtime::{program_test, tree_account_size},
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
    Rejection::custom(SystemError::AccountAlreadyInUse as u32).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller)
        .at(1)
        .assert_litesvm(err);
}

#[test]
fn pause_tree_rejects_unconfigured_authority_atomically() {
    let mut pool = Pool::initialized();
    let impostor = pool.funded_signer(1_000_000_000);

    let err = pool
        .rpc
        .pause_tree(&impostor, &pool.tree, true)
        .expect_err("impostor pause must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts)
        .at(1)
        .assert_litesvm(err);
}

#[test]
fn oversized_tree_creation_is_rejected() {
    let mut pool = Pool::initialized();

    let err = pool
        .rpc
        .create_tree(tree_account_size() + 8, &pool.authority)
        .expect_err("oversized tree must fail");
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts)
        .at(1)
        .assert_litesvm(err);
}

#[test]
fn tree_creation_rejects_an_unsigned_authority() {
    let mut pool = Pool::initialized();
    let tree = Keypair::new();
    let mut create = CreateTree {
        authority: pool.authority.pubkey(),
        tree: tree.pubkey(),
    }
    .instruction();
    // Same authority address, but its meta carries no signature.
    create
        .accounts
        .first_mut()
        .expect("authority meta")
        .is_signer = false;

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[create], &[])
        .expect_err("unsigned authority must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
}

#[test]
fn tree_creation_rejects_non_canonical_nullifier_params() {
    let mut pool = Pool::initialized();
    let canonical = address_tree_params();
    let wrong_root_history = InitAddressTreeAccountsInstructionData {
        root_history_capacity: canonical.root_history_capacity + 1,
        ..canonical
    };
    // batch/zkp ratio of 1 instead of the canonical zkp batch count.
    let wrong_zkp_ratio = InitAddressTreeAccountsInstructionData {
        input_queue_zkp_batch_size: canonical.input_queue_batch_size,
        ..canonical
    };

    for params in [wrong_root_history, wrong_zkp_ratio] {
        let payer = pool.rpc.payer.pubkey();
        let tree = Keypair::new();
        let rent = pool
            .rpc
            .get_minimum_balance_for_rent_exemption(tree_account_size() as usize)
            .expect("rent");
        let alloc = system_create_account_ix(
            &payer,
            &tree.pubkey(),
            rent,
            tree_account_size(),
            &pda::shielded_pool_program_id(),
        );
        let create = CreateTree {
            authority: pool.authority.pubkey(),
            tree: tree.pubkey(),
        }
        .instruction_with_nullifier_params(params);

        let err = pool
            .rpc
            .create_and_send_default_payer_transaction(&[alloc, create], &[&tree, &pool.authority])
            .expect_err("non-canonical nullifier params must fail");
        Rejection::pool(ShieldedPoolError::InvalidTreeAccounts)
            .at(1)
            .assert_litesvm(err);
    }
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
    Rejection::pool(ShieldedPoolError::InvalidProtocolConfig).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::InvalidZoneConfig).assert_litesvm(err);
}

#[test]
fn mollusk_protocol_config_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = protocol_config_fixture();
    // Metas: [0] authority (signer, fee payer), [1] config PDA, [2] system
    // program. Signer and mutability cells have stable named errors. The
    // Remove cells shift the account shape and Readonly{0} demotes the fee
    // payer (its failure point depends on the runtime's fee handling), so
    // those cells pin deterministic rejection rather than a named variant.
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
fn protocol_config_requires_system_program_exactly() {
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
            owner: Pubkey::new_from_array([0; 32]),
            executable: false,
            rent_epoch: 0,
        },
    );

    expect_err_exact(
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
    // shape, so only deterministic rejection is pinned.
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
fn pause_tree_rejects_wrong_authority_exactly() {
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
            owner: Pubkey::new_from_array([0; 32]),
            executable: false,
            rent_epoch: 0,
        },
    );

    expect_err_exact(
        &mollusk,
        &wrong_authority_ix,
        &wrong_authority_accounts,
        ProgramError::Custom(ShieldedPoolError::UnauthorizedCaller as u32),
    );
}

#[test]
fn pause_tree_rejects_a_payload_that_is_not_exactly_one_byte() {
    let (mollusk, valid, accounts) = pause_tree_fixture();

    // Tag byte only: zero payload bytes.
    let mut empty_payload = valid.clone();
    empty_payload.data.truncate(1);
    expect_err_exact(
        &mollusk,
        &empty_payload,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );

    // Two payload bytes.
    let mut two_byte_payload = valid;
    two_byte_payload.data.push(0);
    expect_err_exact(
        &mollusk,
        &two_byte_payload,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );
}

#[test]
fn protocol_config_creation_rejects_a_non_canonical_pda() {
    let (mollusk, valid, accounts) = protocol_config_fixture();
    let noncanonical = Pubkey::new_unique();
    let mut noncanonical_ix = valid;
    noncanonical_ix
        .accounts
        .get_mut(1)
        .expect("config meta")
        .pubkey = mollusk_pubkey(&noncanonical);
    let mut noncanonical_accounts = accounts;
    *noncanonical_accounts.get_mut(1).expect("config account") =
        (mollusk_pubkey(&noncanonical), empty_placeholder_account());

    expect_err_exact(
        &mollusk,
        &noncanonical_ix,
        &noncanonical_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidPda as u32),
    );
}

#[test]
fn protocol_config_creation_rejects_a_payload_of_the_wrong_size() {
    let (mollusk, valid, accounts) = protocol_config_fixture();
    // Tag byte + exactly the fixed struct size.
    assert_eq!(
        valid.data.len(),
        1 + core::mem::size_of::<CreateProtocolConfigData>()
    );

    let mut truncated = valid.clone();
    truncated.data.pop();
    expect_err_exact(
        &mollusk,
        &truncated,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );

    let mut extended = valid;
    extended.data.push(0);
    expect_err_exact(
        &mollusk,
        &extended,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );
}

#[test]
fn pause_tree_rejects_wrong_config_owner_exactly() {
    let (mollusk, valid, accounts) = pause_tree_fixture();
    let mut wrong_config_accounts = accounts;
    wrong_config_accounts
        .get_mut(1)
        .expect("config account")
        .1
        .owner = Pubkey::new_from_array([0x55; 32]);

    expect_err_exact(
        &mollusk,
        &valid,
        &wrong_config_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidProtocolConfig as u32),
    );
}

#[test]
fn tree_creation_rejects_an_account_not_owned_by_the_pool() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let tree = Keypair::new();
    let rent = pool
        .rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size() as usize)
        .expect("rent");
    // Allocate the tree account owned by the system program, not the pool.
    let alloc = system_create_account_ix(
        &payer,
        &tree.pubkey(),
        rent,
        tree_account_size(),
        &Pubkey::default(),
    );
    let create = CreateTree {
        authority: pool.authority.pubkey(),
        tree: tree.pubkey(),
    }
    .instruction();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[alloc, create], &[&tree, &pool.authority])
        .expect_err("tree account with a foreign owner must fail");
    Rejection::custom(u32::from(AccountError::AccountOwnedByWrongProgram))
        .at(1)
        .assert_litesvm(err);
}

#[test]
fn tree_creation_rejects_double_initialization() {
    let mut pool = Pool::initialized();
    let tree_before = pool
        .rpc
        .account_data(&pool.tree.pubkey())
        .expect("tree data");
    let create_again = CreateTree {
        authority: pool.authority.pubkey(),
        tree: pool.tree.pubkey(),
    }
    .instruction();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[create_again], &[&pool.authority])
        .expect_err("re-initializing an existing tree must fail");
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts).assert_litesvm(err);
    assert_eq!(
        pool.rpc.account_data(&pool.tree.pubkey()).expect("tree"),
        tree_before,
        "rejected re-init must leave the tree untouched"
    );
}

#[test]
fn tree_creation_rejects_trailing_instruction_bytes() {
    let mut pool = Pool::initialized();
    let payer = pool.rpc.payer.pubkey();
    let tree = Keypair::new();
    let rent = pool
        .rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size() as usize)
        .expect("rent");
    let alloc = system_create_account_ix(
        &payer,
        &tree.pubkey(),
        rent,
        tree_account_size(),
        &pda::shielded_pool_program_id(),
    );
    let mut create = CreateTree {
        authority: pool.authority.pubkey(),
        tree: tree.pubkey(),
    }
    .instruction();
    create.data.push(0xFF);

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[alloc, create], &[&tree, &pool.authority])
        .expect_err("trailing instruction bytes must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData)
        .at(1)
        .assert_litesvm(err);
}

#[test]
fn zone_config_creation_rejects_an_unsigned_zone_config() {
    let mut rpc = program_test();
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    // Direct SPP call: the zone config account IS the zone's `zone_auth` PDA,
    // and its signature (which only the zone program's `invoke_signed` can
    // supply) is the sole proof the zone program authorized the creation.
    // With the flag cleared the pool rejects the config itself as
    // `InvalidZoneConfig` — not a generic missing-signer error.
    let mut ix = CreateZoneConfig {
        payer: authority.pubkey(),
        program_id: ZONE_TEST_PROGRAM_ID.into(),
        authority: authority.pubkey().to_bytes().into(),
        zone_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("build create zone config");
    ix.accounts.get_mut(2).expect("zone config meta").is_signer = false;

    let err = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&authority])
        .expect_err("unsigned zone config must fail");
    Rejection::pool(ShieldedPoolError::InvalidZoneConfig).assert_litesvm(err);
}

#[test]
fn zone_config_creation_rejects_an_unconfigured_payer_when_permissioned() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let impostor = pool.funded_signer(1_000_000_000);

    // The protocol config is permissioned (the default), so a payer that is
    // not the zone-creation authority must be rejected even though the zone
    // program signs for the config PDA.
    let err = pool
        .rpc
        .create_zone_config(&impostor, &impostor.pubkey(), true)
        .expect_err("impostor zone creation must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
}

#[test]
fn zone_owner_rotation_rejects_a_mismatched_co_signer() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_config = pool
        .rpc
        .create_zone_config(&pool.authority, &pool.authority.pubkey(), true)
        .expect("create zone config");
    let impostor = pool.funded_signer(1_000_000_000);
    let next = Keypair::new();

    let mut ix = zolana_interface::instruction::UpdateZoneConfigOwner {
        authority: pool.authority.pubkey(),
        zone_config,
        new_authority: next.pubkey().to_bytes().into(),
    }
    .instruction();
    // A signer that is not the instruction's named new authority.
    ix.accounts.get_mut(2).expect("new authority meta").pubkey = impostor.pubkey();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority, &impostor])
        .expect_err("mismatched rotation co-signer must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

#[test]
fn zone_owner_rotation_rejects_an_unsigned_co_signer() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_config = pool
        .rpc
        .create_zone_config(&pool.authority, &pool.authority.pubkey(), true)
        .expect("create zone config");
    let next = Keypair::new();

    let mut ix = zolana_interface::instruction::UpdateZoneConfigOwner {
        authority: pool.authority.pubkey(),
        zone_config,
        new_authority: next.pubkey().to_bytes().into(),
    }
    .instruction();
    ix.accounts
        .get_mut(2)
        .expect("new authority meta")
        .is_signer = false;

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("unsigned rotation co-signer must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
}

#[test]
fn zone_update_rejects_a_cosplay_config_account() {
    let mut pool = Pool::initialized();
    let impostor_config = Pubkey::new_unique();
    pool.rpc
        .airdrop(&impostor_config, 1_000_000)
        .expect("fund impostor config");

    let ix = zolana_interface::instruction::UpdateZoneConfig {
        authority: pool.authority.pubkey(),
        zone_config: impostor_config,
        zone_authority_transact_is_enabled: false,
    }
    .instruction();
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("a non-config account in the config slot must fail");
    Rejection::pool(ShieldedPoolError::InvalidZoneConfig).assert_litesvm(err);
}

#[test]
fn asset_counter_creation_rejects_a_non_canonical_pda() {
    let mut rpc = program_test();
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let mut ix = CreateAssetCounter {
        authority: authority.pubkey(),
    }
    .instruction();
    // Swap the canonical counter PDA for an attacker-chosen address (with an
    // attacker-supplied bump this is the anti-cosplay guard).
    ix.accounts.get_mut(2).expect("counter meta").pubkey = Pubkey::new_unique();

    let err = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&authority])
        .expect_err("non-canonical counter PDA must fail");
    Rejection::pool(ShieldedPoolError::InvalidPda).assert_litesvm(err);
}
