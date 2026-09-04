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
        CreateAssetCounter, CreateProtocolConfig, CreateProtocolConfigData, CreateRingConfig,
        CreateTree, UpdateProtocolConfigData,
    },
    pda,
    state::{default_tree_fees, nullifier_tree_params, RingConfig},
};
use zolana_program_test::{next_tree_id, Rejection, RING_TEST_PROGRAM_ID};
use zolana_test_utils::mollusk::{
    empty_placeholder_account, expect_err_exact, mollusk_pubkey, sweep_account_matrix,
    AccountMutation, Expected,
};
use zolana_tree::NullifierTreeInitParams;

use shielded_pool_tests::support::{
    fixtures::Pool,
    mollusk::{pause_tree_fixture, protocol_config_fixture},
    runtime::program_test,
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
        ring_creation_authority: named.into(),
        ring_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
        fee_authority: named.into(),
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
        .create_tree(&impostor)
        .expect_err("impostor tree creation must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
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

fn create_tree_steps(pool: &Pool, tree_id: u16) -> CreateTree {
    CreateTree {
        payer: pool.rpc.payer.pubkey(),
        authority: pool.authority.pubkey(),
        tree_id,
        nullifier_params: nullifier_tree_params(),
        fees: default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .expect("default tree fees"),
    }
}

#[test]
fn tree_creation_rejects_a_skipped_tree_id() {
    let mut pool = Pool::initialized();
    let skipped = next_tree_id(&pool.rpc).expect("next tree id") + 1;
    let create = create_tree_steps(&pool, skipped);

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&create.instructions(), &[&pool.authority])
        .expect_err("skipping a tree id must fail");
    Rejection::pool(ShieldedPoolError::InvalidTreeId).assert_litesvm(err);
    assert!(pool.rpc.account_data(&create.tree()).is_none());
}

#[test]
fn tree_creation_rejects_a_non_canonical_tree_address() {
    let mut pool = Pool::initialized();
    let tree_id = next_tree_id(&pool.rpc).expect("next tree id");
    let mut step = create_tree_steps(&pool, tree_id).allocation_step();
    step.accounts.get_mut(3).expect("tree meta").pubkey = pda::tree(tree_id + 1);

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[step], &[&pool.authority])
        .expect_err("a tree address derived from another id must fail");
    Rejection::pool(ShieldedPoolError::InvalidPda).assert_litesvm(err);
}

#[test]
fn partially_allocated_tree_is_not_usable() {
    let mut pool = Pool::initialized();
    let tree_id = next_tree_id(&pool.rpc).expect("next tree id");
    let create = create_tree_steps(&pool, tree_id);
    let steps = create.instructions();
    pool.rpc
        .create_and_send_default_payer_transaction(
            steps.get(..2).expect("allocation steps"),
            &[&pool.authority],
        )
        .expect("allocation steps");

    let depositor = pool.funded_signer(1_000_000_000);
    let err = pool
        .rpc
        .deposit_sol(&create.tree(), &depositor, 1_000_000, [1; 32], [2; 32])
        .expect_err("a tree that is still allocating must reject deposits");
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts).assert_litesvm(err);
}

#[test]
fn tree_creation_rejects_an_unsigned_authority() {
    let mut pool = Pool::initialized();
    let tree_id = next_tree_id(&pool.rpc).expect("next tree id");
    let mut create = create_tree_steps(&pool, tree_id).allocation_step();
    create
        .accounts
        .get_mut(1)
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
    let canonical = nullifier_tree_params();
    // Derives 101 roots instead of the account layout's canonical 100.
    let wrong_zkp_ratio = NullifierTreeInitParams {
        input_queue_batch_size: canonical.input_queue_batch_size
            + canonical.input_queue_zkp_batch_size,
        ..canonical
    };

    let err = pool
        .rpc
        .create_tree_with_nullifier_params(&pool.authority, wrong_zkp_ratio)
        .expect_err("non-canonical nullifier params must fail");
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts).assert_litesvm(err);
}

#[test]
fn pause_requires_a_protocol_config() {
    let mut rpc = program_test();
    let signer = Keypair::new();
    rpc.airdrop(&signer.pubkey(), 1_000_000_000)
        .expect("fund signer");
    let err = rpc
        .pause_tree(&signer, &pda::tree(0), true)
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
fn ring_config_owner_rotation_revokes_old_authority() {
    let mut rpc = program_test();
    rpc.load_ring_test_program()
        .expect("load ring test program");
    let admin = Keypair::new();
    rpc.create_protocol_config_permissionless(&admin)
        .expect("create permissionless protocol config");
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let ring_config = rpc
        .create_ring_config(&payer, &authority.pubkey(), true)
        .expect("create ring config");
    rpc.update_ring_config(&authority, &ring_config, false, false)
        .expect("disable ring authority transact");
    let next = Keypair::new();
    rpc.update_ring_config_owner(&authority, &ring_config, &next)
        .expect("rotate ring config owner");

    let err = rpc
        .update_ring_config(&authority, &ring_config, true, false)
        .expect_err("old ring authority must be revoked");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
}

#[test]
fn ring_config_rejects_a_noncanonical_ring_authority_account() {
    let mut rpc = program_test();
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let mut ix = CreateRingConfig {
        payer: payer.pubkey(),
        program_id: RING_TEST_PROGRAM_ID.into(),
        authority: payer.pubkey().to_bytes().into(),
        ring_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("derive ring config PDA");
    ix.accounts.get_mut(2).expect("ring config account").pubkey = payer.pubkey();

    let err = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&payer])
        .expect_err("noncanonical ring config must fail");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(err);
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
fn tree_creation_rejects_double_initialization() {
    let mut pool = Pool::initialized();
    let tree_before = pool.rpc.account_data(&pool.tree).expect("tree data");
    let create_again = create_tree_steps(&pool, 0).allocation_step();
    assert_eq!(pda::tree(0), pool.tree);

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[create_again], &[&pool.authority])
        .expect_err("re-initializing an existing tree must fail");
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts).assert_litesvm(err);
    assert_eq!(
        pool.rpc.account_data(&pool.tree).expect("tree"),
        tree_before,
        "rejected re-init must leave the tree untouched"
    );
}

#[test]
fn tree_creation_rejects_trailing_instruction_bytes() {
    let mut pool = Pool::initialized();
    let tree_id = next_tree_id(&pool.rpc).expect("next tree id");
    let mut create = create_tree_steps(&pool, tree_id).allocation_step();
    create.data.push(0xFF);

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[create], &[&pool.authority])
        .expect_err("trailing instruction bytes must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

#[test]
fn ring_config_creation_rejects_an_unsigned_ring_config() {
    let mut rpc = program_test();
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    // Direct SPP call: the ring config account IS the ring's `ring_auth` PDA,
    // and its signature (which only the ring program's `invoke_signed` can
    // supply) is the sole proof the ring program authorized the creation.
    // With the flag cleared the pool rejects the config itself as
    // `InvalidRingConfig` — not a generic missing-signer error.
    let mut ix = CreateRingConfig {
        payer: authority.pubkey(),
        program_id: RING_TEST_PROGRAM_ID.into(),
        authority: authority.pubkey().to_bytes().into(),
        ring_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("build create ring config");
    ix.accounts.get_mut(2).expect("ring config meta").is_signer = false;

    let err = rpc
        .create_and_send_default_payer_transaction(&[ix], &[&authority])
        .expect_err("unsigned ring config must fail");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(err);
}

#[test]
fn ring_config_creation_rejects_an_unconfigured_payer_when_permissioned() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let impostor = pool.funded_signer(1_000_000_000);

    // The protocol config is permissioned (the default), so a payer that is
    // not the ring-creation authority must be rejected even though the ring
    // program signs for the config PDA.
    let err = pool
        .rpc
        .create_ring_config(&impostor, &impostor.pubkey(), true)
        .expect_err("impostor ring creation must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
}

#[test]
fn ring_owner_rotation_binds_the_new_owner_to_the_co_signing_account() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_config = pool
        .rpc
        .create_ring_config(&pool.authority, &pool.authority.pubkey(), true)
        .expect("create ring config");
    let impostor = pool.funded_signer(1_000_000_000);
    let next = Keypair::new();

    let mut ix = zolana_interface::instruction::UpdateRingConfigOwner {
        authority: pool.authority.pubkey(),
        ring_config,
        new_authority: next.pubkey().to_bytes().into(),
    }
    .instruction();
    // PR172 removed the payload field: the new authority is read only from the
    // co-signing account, so swapping in the impostor rotates to the impostor
    // (there is no payload/account mismatch class left to reject).
    ix.accounts.get_mut(2).expect("new authority meta").pubkey = impostor.pubkey();

    pool.rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority, &impostor])
        .expect("rotation to the co-signing account succeeds");
    let bytes = pool.rpc.account_data(&ring_config).expect("ring config");
    let config: &RingConfig = bytemuck::from_bytes(&bytes);
    assert_eq!(config.authority.to_bytes(), impostor.pubkey().to_bytes());
}

#[test]
fn ring_owner_rotation_rejects_an_unsigned_co_signer() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_config = pool
        .rpc
        .create_ring_config(&pool.authority, &pool.authority.pubkey(), true)
        .expect("create ring config");
    let next = Keypair::new();

    let mut ix = zolana_interface::instruction::UpdateRingConfigOwner {
        authority: pool.authority.pubkey(),
        ring_config,
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
fn ring_update_rejects_a_cosplay_config_account() {
    let mut pool = Pool::initialized();
    let impostor_config = Pubkey::new_unique();
    pool.rpc
        .airdrop(&impostor_config, 1_000_000)
        .expect("fund impostor config");

    let ix = zolana_interface::instruction::UpdateRingConfig {
        authority: pool.authority.pubkey(),
        ring_config: impostor_config,
        ring_authority_transact_is_enabled: false,
        paused: false,
    }
    .instruction();
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("a non-config account in the config slot must fail");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(err);
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
