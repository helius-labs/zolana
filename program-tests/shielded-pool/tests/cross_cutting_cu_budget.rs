use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{instruction::UpdateProtocolConfigData, state::tree_account_size};
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
const CREATE_TREE_CU_CEILING: u64 = 1_800; // observed 581
const PAUSE_TREE_CU_CEILING: u64 = 800; // observed 250-251
const CREATE_ASSET_COUNTER_CU_CEILING: u64 = 14_000; // observed 4_600
const CREATE_SPL_INTERFACE_CU_CEILING: u64 = 23_000; // observed 7_638
const DEPOSIT_SOL_CU_CEILING: u64 = 90_000; // observed 38_393
const DEPOSIT_SPL_CU_CEILING: u64 = 100_000; // observed 39_424
const CREATE_RING_CONFIG_CU_CEILING: u64 = 20_000; // observed 6_658
const UPDATE_RING_CONFIG_CU_CEILING: u64 = 450; // observed 141
const RING_DEPOSIT_SOL_CU_CEILING: u64 = 120_000; // observed 47_441
const UPDATE_RING_CONFIG_OWNER_CU_CEILING: u64 = 700; // observed 218

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
    let authority = Keypair::new();
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
            UpdateProtocolConfigData::RingCreationPermissionless(true),
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

    let tree = test
        .create_tree(tree_account_size() as u64, &authority)
        .expect("create tree");
    assert_last_under(&test, "create tree", CREATE_TREE_CU_CEILING);
    test.pause_tree(&authority, &tree, true)
        .expect("pause tree");
    assert_last_under(&test, "pause tree", PAUSE_TREE_CU_CEILING);
    test.pause_tree(&authority, &tree, false)
        .expect("unpause tree");
    assert_last_under(&test, "unpause tree", PAUSE_TREE_CU_CEILING);

    let mint = test.create_mint().expect("create mint");
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

    let depositor = Keypair::new();
    test.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund depositor");
    test.deposit_sol(&tree.pubkey(), &depositor, 1_000_000, [1; 32], [2; 32])
        .expect("deposit SOL");
    assert_last_under(&test, "deposit SOL", DEPOSIT_SOL_CU_CEILING);

    let user_token = test
        .create_token_account(&mint, &depositor.pubkey())
        .expect("create token account");
    test.mint_to(&mint, &user_token, 1_000)
        .expect("mint tokens");
    let data = ZolanaProgramTest::spl_shield_data(1_000, [3; 32], [4; 32], &mint, &user_token);
    test.deposit(&tree.pubkey(), &depositor, &data)
        .expect("deposit SPL");
    assert_last_under(&test, "deposit SPL", DEPOSIT_SPL_CU_CEILING);

    test.load_ring_test_program()
        .expect("load ring test program");
    let ring_config = test
        .create_ring_config(&authority, &authority.pubkey(), true)
        .expect("create ring config");
    assert_last_under(&test, "create ring config", CREATE_RING_CONFIG_CU_CEILING);
    test.update_ring_config(&authority, &ring_config, false, false)
        .expect("update ring config");
    assert_last_under(&test, "update ring config", UPDATE_RING_CONFIG_CU_CEILING);
    test.update_ring_config(&authority, &ring_config, true, false)
        .expect("re-enable ring config");

    let ring_data = test.ring_sol_shield_data(1_000_000, [5; 32], [6; 32]);
    test.ring_deposit(&tree.pubkey(), &depositor, &ring_data)
        .expect("ring deposit SOL");
    assert_last_under(&test, "ring deposit SOL", RING_DEPOSIT_SOL_CU_CEILING);

    let next_ring_owner = Keypair::new();
    test.update_ring_config_owner(&authority, &ring_config, &next_ring_owner)
        .expect("rotate ring config owner");
    assert_last_under(
        &test,
        "update ring config owner",
        UPDATE_RING_CONFIG_OWNER_CU_CEILING,
    );
}
