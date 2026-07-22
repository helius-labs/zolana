use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{instruction::UpdateProtocolConfigData, state::tree_account_size};
use zolana_program_test::{TransactionOutcome, ZolanaProgramTest};

const SINGLE_INSTRUCTION_LIMIT: u64 = 200_000;
const CREATE_TREE_TRANSACTION_LIMIT: u64 = 400_000;

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
    assert_last_under(&test, "create protocol config", SINGLE_INSTRUCTION_LIMIT);

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
        assert_last_under(&test, name, SINGLE_INSTRUCTION_LIMIT);
    }

    let tree = test
        .create_tree(tree_account_size() as u64, &authority)
        .expect("create tree");
    assert_last_under(&test, "create tree", CREATE_TREE_TRANSACTION_LIMIT);
    test.pause_tree(&authority, &tree, true)
        .expect("pause tree");
    assert_last_under(&test, "pause tree", SINGLE_INSTRUCTION_LIMIT);
    test.pause_tree(&authority, &tree, false)
        .expect("unpause tree");
    assert_last_under(&test, "unpause tree", SINGLE_INSTRUCTION_LIMIT);

    let mint = test.create_mint().expect("create mint");
    test.create_asset_counter(&authority)
        .expect("create asset counter");
    assert_last_under(&test, "create asset counter", SINGLE_INSTRUCTION_LIMIT);
    test.create_spl_interface(&authority, &mint)
        .expect("create SPL interface");
    assert_last_under(&test, "create SPL interface", SINGLE_INSTRUCTION_LIMIT);

    let depositor = Keypair::new();
    test.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund depositor");
    test.deposit_sol(&tree.pubkey(), &depositor, 1_000_000, [1; 32], [2; 31])
        .expect("deposit SOL");
    assert_last_under(&test, "deposit SOL", SINGLE_INSTRUCTION_LIMIT);

    let user_token = test
        .create_token_account(&mint, &depositor.pubkey())
        .expect("create token account");
    test.mint_to(&mint, &user_token, 1_000)
        .expect("mint tokens");
    let data = ZolanaProgramTest::spl_shield_data(1_000, [3; 32], [4; 31]);
    test.deposit_spl(&tree.pubkey(), &depositor, &user_token, &mint, &data)
        .expect("deposit SPL");
    assert_last_under(&test, "deposit SPL", SINGLE_INSTRUCTION_LIMIT);

    test.load_zone_test_program()
        .expect("load zone test program");
    let zone_config = test
        .create_zone_config(&authority, &authority.pubkey(), true)
        .expect("create zone config");
    assert_last_under(&test, "create zone config", SINGLE_INSTRUCTION_LIMIT);
    test.update_zone_config(&authority, &zone_config, false)
        .expect("update zone config");
    assert_last_under(&test, "update zone config", SINGLE_INSTRUCTION_LIMIT);
    test.update_zone_config(&authority, &zone_config, true)
        .expect("re-enable zone config");

    let zone_data = test.zone_sol_shield_data(1_000_000, [5; 32], [6; 31]);
    test.zone_deposit(&tree.pubkey(), &depositor, &zone_data)
        .expect("zone deposit SOL");
    assert_last_under(&test, "zone deposit SOL", SINGLE_INSTRUCTION_LIMIT);

    let next_zone_owner = Keypair::new();
    test.update_zone_config_owner(&authority, &zone_config, &next_zone_owner)
        .expect("rotate zone config owner");
    assert_last_under(&test, "update zone config owner", SINGLE_INSTRUCTION_LIMIT);
}
