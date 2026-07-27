use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{instruction::UpdateProtocolConfigData, state::tree_account_size};
use zolana_program_test::{TransactionOutcome, ZolanaProgramTest};

// Per-family CU ceilings, pinned strictly below the 200k budget LiteSVM
// enforces on these single-instruction transactions. A regression that grows
// past a ceiling fails the ceiling assert (instead of aborting the whole
// transaction at the enforced budget, which would make the ceiling
// unfalsifiable). Each ceiling carries roughly 2x headroom over measured
// consumption: admin/config ops run 0.2k-6.3k, the SPL interface creation
// 12.1k, and the deposit family 39.5k-48.9k.
const ADMIN_CU_CEILING: u64 = 15_000;
const SPL_INTERFACE_CU_CEILING: u64 = 30_000;
const DEPOSIT_CU_CEILING: u64 = 100_000;

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
    assert_last_under(&test, "create protocol config", ADMIN_CU_CEILING);

    for (name, update) in [
        (
            "update tree permission",
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        ),
        (
            "update zone permission",
            UpdateProtocolConfigData::ZoneCreationPermissionless(true),
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
            "update zone authority",
            UpdateProtocolConfigData::ZoneCreationAuthority(authority.pubkey().to_bytes().into()),
        ),
        (
            "update protocol authority",
            UpdateProtocolConfigData::ProtocolAuthority(authority.pubkey().to_bytes().into()),
        ),
    ] {
        test.send_protocol_config_update(&authority, update)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_last_under(&test, name, ADMIN_CU_CEILING);
    }

    let tree = test
        .create_tree(tree_account_size() as u64, &authority)
        .expect("create tree");
    assert_last_under(&test, "create tree", ADMIN_CU_CEILING);
    test.pause_tree(&authority, &tree, true)
        .expect("pause tree");
    assert_last_under(&test, "pause tree", ADMIN_CU_CEILING);
    test.pause_tree(&authority, &tree, false)
        .expect("unpause tree");
    assert_last_under(&test, "unpause tree", ADMIN_CU_CEILING);

    let mint = test.create_mint().expect("create mint");
    test.create_asset_counter(&authority)
        .expect("create asset counter");
    assert_last_under(&test, "create asset counter", ADMIN_CU_CEILING);
    test.create_spl_interface(&authority, &mint)
        .expect("create SPL interface");
    assert_last_under(&test, "create SPL interface", SPL_INTERFACE_CU_CEILING);

    let depositor = Keypair::new();
    test.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund depositor");
    test.deposit_sol(&tree.pubkey(), &depositor, 1_000_000, [1; 32], [2; 32])
        .expect("deposit SOL");
    assert_last_under(&test, "deposit SOL", DEPOSIT_CU_CEILING);

    let user_token = test
        .create_token_account(&mint, &depositor.pubkey())
        .expect("create token account");
    test.mint_to(&mint, &user_token, 1_000)
        .expect("mint tokens");
    let data = ZolanaProgramTest::spl_shield_data(1_000, [3; 32], [4; 32], &mint, &user_token);
    test.deposit(&tree.pubkey(), &depositor, &data)
        .expect("deposit SPL");
    assert_last_under(&test, "deposit SPL", DEPOSIT_CU_CEILING);

    test.load_zone_test_program()
        .expect("load zone test program");
    let zone_config = test
        .create_zone_config(&authority, &authority.pubkey(), true)
        .expect("create zone config");
    assert_last_under(&test, "create zone config", ADMIN_CU_CEILING);
    test.update_zone_config(&authority, &zone_config, false)
        .expect("update zone config");
    assert_last_under(&test, "update zone config", ADMIN_CU_CEILING);
    test.update_zone_config(&authority, &zone_config, true)
        .expect("re-enable zone config");

    let zone_data = test.zone_sol_shield_data(1_000_000, [5; 32], [6; 32]);
    test.zone_deposit(&tree.pubkey(), &depositor, &zone_data)
        .expect("zone deposit SOL");
    assert_last_under(&test, "zone deposit SOL", DEPOSIT_CU_CEILING);

    let next_zone_owner = Keypair::new();
    test.update_zone_config_owner(&authority, &zone_config, &next_zone_owner)
        .expect("rotate zone config owner");
    assert_last_under(&test, "update zone config owner", ADMIN_CU_CEILING);
}
