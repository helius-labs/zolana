use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::instruction::UpdateProtocolConfigData;
use zolana_program_test::{TransactionOutcome, ZolanaProgramTest};

// Per-op CU ceilings, pinned at roughly 3x the consumption observed on the
// current build (measured 2026-07 via `last_transaction_trace`; each constant
// records its observed value). All ceilings sit strictly below the 200k
// budget LiteSVM enforces on these single-instruction transactions, so a
// regression trips the ceiling assert instead of aborting the whole
// transaction at the enforced budget (which would make the ceiling
// unfalsifiable).
const CREATE_PROTOCOL_CONFIG_CU_CEILING: u64 = 15_000; // observed 5_538

// Worst of the seven protocol-config updates below (observed 179-240).
const CONFIG_UPDATE_CU_CEILING: u64 = 750;
const CREATE_TREE_CU_CEILING: u64 = 50_000; // observed 16_129 across the allocation steps
const PAUSE_TREE_CU_CEILING: u64 = 800; // observed 250-251
const CREATE_ASSET_COUNTER_CU_CEILING: u64 = 14_000; // observed 4_600
const CREATE_SPL_INTERFACE_CU_CEILING: u64 = 23_000; // observed 7_706
const DEPOSIT_SOL_CU_CEILING: u64 = 90_000; // observed 38_393
const DEPOSIT_SPL_CU_CEILING: u64 = 100_000; // observed 39_424
const CREATE_RING_CONFIG_CU_CEILING: u64 = 20_000; // observed 6_658
const UPDATE_RING_CONFIG_CU_CEILING: u64 = 450; // observed 141
const RING_DEPOSIT_SOL_CU_CEILING: u64 = 120_000; // observed 47_441
const UPDATE_RING_CONFIG_OWNER_CU_CEILING: u64 = 700; // observed 218
const SET_RING_ACTIVATION_CU_CEILING: u64 = 700;

#[track_caller]
fn assert_last_under(test: &ZolanaProgramTest, operation: &str, limit: u64) {
    let trace = test
        .last_transaction_trace()
        .unwrap_or_else(|| panic!("missing transaction trace for {operation}"));
    assert_eq!(
        trace.outcome,
        TransactionOutcome::Succeeded,
        "{operation} failed:\n{}",
        trace.diagnostic()
    );
    assert!(
        trace.compute_units_consumed > 0,
        "{operation} reported zero compute units"
    );
    assert!(
        trace.compute_units_consumed <= limit,
        "{operation} consumed {} CU (limit {limit})\n{}",
        trace.compute_units_consumed,
        trace.diagnostic()
    );
}

#[test]
fn proofless_instruction_families_stay_within_transaction_budgets() {
    let mut test = ZolanaProgramTest::new().expect("program test");
    // PDA bump search cost moves with the address, fixed keypairs pin the metered CU.
    let authority = Keypair::new_from_array([1; 32]);
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    assert_last_under(
        &test,
        "create protocol config",
        CREATE_PROTOCOL_CONFIG_CU_CEILING,
    );

    for (name, update) in [
        (
            "update tree permission",
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        ),
        (
            "update ring permission",
            UpdateProtocolConfigData::RingActivationPermissionless(true),
        ),
        (
            "update SPL permission",
            UpdateProtocolConfigData::SplInterfaceCreationPermissionless(true),
        ),
        (
            "update tree authority",
            UpdateProtocolConfigData::TreeCreationAuthority(authority.pubkey().to_bytes().into()),
        ),
        (
            "update forester authority",
            UpdateProtocolConfigData::ForesterAuthority(authority.pubkey().to_bytes().into()),
        ),
        (
            "update ring authority",
            UpdateProtocolConfigData::RingCreationAuthority(authority.pubkey().to_bytes().into()),
        ),
        (
            "update protocol authority",
            UpdateProtocolConfigData::ProtocolAuthority(authority.pubkey().to_bytes().into()),
        ),
    ] {
        test.send_protocol_config_update(&authority, update)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_last_under(&test, name, CONFIG_UPDATE_CU_CEILING);
    }

    let tree = test.create_tree(&authority).expect("create tree");
    assert_last_under(&test, "create tree", CREATE_TREE_CU_CEILING);
    test.pause_tree(&authority, &tree, true)
        .expect("pause tree");
    assert_last_under(&test, "pause tree", PAUSE_TREE_CU_CEILING);
    test.pause_tree(&authority, &tree, false)
        .expect("unpause tree");
    assert_last_under(&test, "unpause tree", PAUSE_TREE_CU_CEILING);

    let mint = test
        .create_mint_from(
            &Keypair::new_from_array([2; 32]),
            ZolanaProgramTest::token_program_id(),
        )
        .expect("create mint");
    test.create_asset_counter(&authority)
        .expect("create asset counter");
    assert_last_under(
        &test,
        "create asset counter",
        CREATE_ASSET_COUNTER_CU_CEILING,
    );
    test.create_spl_interface(&authority, &mint)
        .expect("create SPL interface");
    assert_last_under(
        &test,
        "create SPL interface",
        CREATE_SPL_INTERFACE_CU_CEILING,
    );

    let depositor = Keypair::new_from_array([3; 32]);
    test.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund depositor");
    test.deposit_sol(&tree, &depositor, 1_000_000, [1; 32])
        .expect("deposit SOL");
    assert_last_under(&test, "deposit SOL", DEPOSIT_SOL_CU_CEILING);

    let user_token = test
        .create_token_account(&mint, &depositor.pubkey())
        .expect("create token account");
    test.mint_to(&mint, &user_token, 1_000)
        .expect("mint tokens");
    let data = ZolanaProgramTest::spl_shield_data(1_000, [3; 32], &mint, &user_token);
    test.deposit(&tree, &depositor, &data).expect("deposit SPL");
    assert_last_under(&test, "deposit SPL", DEPOSIT_SPL_CU_CEILING);

    test.load_ring_test_program()
        .expect("load ring test program");
    let ring_config = test
        .create_ring_config(&authority, &authority.pubkey())
        .expect("create ring config");
    assert_last_under(&test, "create ring config", CREATE_RING_CONFIG_CU_CEILING);
    // The ring owns only `paused`; governance owns activation and the
    // authority-transact rail, so the rail toggle is a separate instruction.
    test.update_ring_config(&authority, &ring_config, false)
        .expect("update ring config");
    assert_last_under(&test, "update ring config", UPDATE_RING_CONFIG_CU_CEILING);
    test.set_ring_activation(&authority, &ring_config, true, false)
        .expect("deactivate the authority rail");
    assert_last_under(&test, "set ring activation", SET_RING_ACTIVATION_CU_CEILING);
    test.set_ring_activation(&authority, &ring_config, true, true)
        .expect("re-enable the authority rail");

    let ring_data = test.ring_sol_shield_data(1_000_000, [5; 32], [6; 32]);
    test.ring_deposit(&tree, &depositor, &ring_data)
        .expect("ring deposit SOL");
    assert_last_under(&test, "ring deposit SOL", RING_DEPOSIT_SOL_CU_CEILING);

    let next_ring_owner = Keypair::new_from_array([4; 32]);
    test.update_ring_config_owner(&authority, &ring_config, &next_ring_owner)
        .expect("rotate ring config owner");
    assert_last_under(
        &test,
        "update ring config owner",
        UPDATE_RING_CONFIG_OWNER_CU_CEILING,
    );
}
