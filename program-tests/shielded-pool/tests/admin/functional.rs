use mollusk_svm::result::Check;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{CreateTree, UpdateProtocolConfigData},
    pda,
    state::{
        default_tree_fees,
        discriminator::{RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        nullifier_tree_params, tree_creation_lamports, ProtocolConfig, RingConfig,
        TREE_ALLOCATION_STEP,
    },
    NULLIFIER_PDA_SIZE, PROGRAM_ID_PUBKEY,
};
use zolana_program_test::{ZolanaProgramTest, RING_TEST_PROGRAM_ID};
use zolana_test_utils::litesvm_asserts::litesvm_assert_protocol_config;
use zolana_test_utils::mollusk::snapshot_instruction_accounts;
use zolana_test_utils::nullifier_pda::tree_fees;
use zolana_tree::{INITIALIZED, PAUSED};

use shielded_pool_tests::support::{
    fixtures::Pool,
    mollusk::{pause_tree_fixture, protocol_config_fixture, setup_mollusk},
    runtime::{program_test, tree_account_size},
};

fn account_named<'a>(accounts: &'a [(Pubkey, Account)], key: &Pubkey) -> &'a Account {
    &accounts
        .iter()
        .find(|(account_key, _)| account_key == key)
        .expect("account present in set")
        .1
}

#[derive(Debug, PartialEq, Eq)]
struct RingConfigState {
    authority: Pubkey,
    enabled: bool,
    paused: bool,
    bump: u8,
}

fn read_ring_config(rpc: &ZolanaProgramTest, address: &Pubkey) -> RingConfigState {
    let bytes = rpc.account_data(address).expect("ring config account");
    assert_eq!(bytes.len(), RingConfig::SIZE);
    assert_eq!(bytes.first(), Some(&RING_CONFIG));
    let config: &RingConfig = bytemuck::from_bytes(&bytes);
    RingConfigState {
        authority: Pubkey::new_from_array(config.authority.to_bytes()),
        enabled: config.enabled(),
        paused: config.is_paused(),
        bump: config.bump,
    }
}

#[test]
fn protocol_config_creation_initializes_complete_state() {
    let mut rpc = program_test();
    let authority = Keypair::new();
    let config = rpc
        .create_protocol_config(&authority)
        .expect("create protocol config");
    litesvm_assert_protocol_config(&rpc, &config, &authority.pubkey());
    let account = rpc.svm.get_account(&config).expect("config account");
    assert_eq!(
        account.owner, rpc.program_id,
        "config account owner must be the shielded-pool program"
    );
}

#[test]
fn protocol_config_creation_changes_only_the_config_and_fee_payer() {
    let (mollusk, instruction, accounts) = protocol_config_fixture();
    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let fee_payer = instruction.accounts.first().expect("fee payer meta").pubkey;
    let config = instruction.accounts.get(1).expect("config meta").pubkey;
    let system = instruction.accounts.get(2).expect("system meta").pubkey;

    // The only account besides the config and the fee payer is byte-for-byte
    // unchanged.
    assert_eq!(
        account_named(&result.resulting_accounts, &system),
        account_named(&accounts, &system),
        "system program account must be unchanged"
    );

    // The fee payer only funds rent: data and owner unchanged, and the removed
    // lamports are exactly the created config account's balance.
    let payer_before = account_named(&accounts, &fee_payer);
    let payer_after = account_named(&result.resulting_accounts, &fee_payer);
    assert_eq!(payer_after.data, payer_before.data);
    assert_eq!(payer_after.owner, payer_before.owner);
    let config_after = account_named(&result.resulting_accounts, &config);
    assert_eq!(
        payer_before.lamports - payer_after.lamports,
        config_after.lamports,
        "fee payer lamports must move exactly into the config account"
    );
    assert_eq!(config_after.data.len(), ProtocolConfig::SIZE);
}

#[test]
fn tree_creation_changes_only_the_tree_account() {
    let mut test = program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let payer = test.payer.pubkey();
    let create = CreateTree {
        payer,
        authority: authority.pubkey(),
        tree_id: 0,
        nullifier_params: nullifier_tree_params(),
        fees: default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .expect("default tree fees"),
    };
    let ix = create.allocation_step();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot_instruction_accounts(&ix, (&PROGRAM_ID_PUBKEY, program_id), |key| {
        test.svm.get_account(key)
    });

    let result = mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    assert_eq!(
        account_named(&result.resulting_accounts, &authority.pubkey()),
        account_named(&accounts, &authority.pubkey()),
        "create_tree must not change the authority"
    );
    let config_before = account_named(&accounts, &pda::protocol_config());
    let config_after = account_named(&result.resulting_accounts, &pda::protocol_config());
    let expected_config = ProtocolConfig {
        next_tree_id: 1,
        ..*bytemuck::from_bytes::<ProtocolConfig>(&config_before.data)
    };
    assert_eq!(
        (
            config_after.lamports,
            config_after.owner,
            bytemuck::from_bytes::<ProtocolConfig>(&config_after.data),
        ),
        (
            config_before.lamports,
            config_before.owner,
            &expected_config
        ),
        "create_tree must only advance next_tree_id"
    );

    let tree_rent = test
        .svm
        .minimum_balance_for_rent_exemption(tree_account_size() as usize);
    let nullifier_pda_rent = test
        .svm
        .minimum_balance_for_rent_exemption(NULLIFIER_PDA_SIZE);
    let expected_lamports =
        tree_creation_lamports(&nullifier_tree_params(), tree_rent, nullifier_pda_rent)
            .expect("tree funding");
    let tree_after = account_named(&result.resulting_accounts, &create.tree());
    assert_eq!(
        tree_after,
        &Account {
            lamports: expected_lamports,
            data: vec![0u8; TREE_ALLOCATION_STEP],
            owner: PROGRAM_ID_PUBKEY,
            executable: false,
            rent_epoch: tree_after.rent_epoch,
        },
        "first step allocates a zeroed 10 KiB chunk funded with rent plus working capital"
    );
    let payer_before = account_named(&accounts, &payer);
    let payer_after = account_named(&result.resulting_accounts, &payer);
    assert_eq!(
        payer_before.lamports - payer_after.lamports,
        expected_lamports,
        "payer funds exactly the tree"
    );
}

#[test]
fn tree_creation_completes_in_three_steps_and_advances_next_tree_id() {
    let mut pool = Pool::initialized();
    let next_tree_id = zolana_program_test::next_tree_id(&pool.rpc).expect("next tree id");
    assert_eq!(next_tree_id, 1);
    let create = CreateTree {
        payer: pool.rpc.payer.pubkey(),
        authority: pool.authority.pubkey(),
        tree_id: next_tree_id,
        nullifier_params: nullifier_tree_params(),
        fees: default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .expect("default tree fees"),
    };
    let steps = create.instructions();
    assert_eq!(steps.len(), 3);

    let (partial, last) = steps.split_at(2);
    pool.rpc
        .create_and_send_default_payer_transaction(partial, &[&pool.authority])
        .expect("first two allocation steps");
    let tree = pool.rpc.account_data(&create.tree()).expect("partial tree");
    assert_eq!(tree.len(), 2 * TREE_ALLOCATION_STEP);
    assert!(tree.iter().all(|byte| *byte == 0));
    assert_eq!(
        zolana_program_test::next_tree_id(&pool.rpc).expect("next tree id"),
        2
    );

    pool.rpc
        .create_and_send_default_payer_transaction(last, &[&pool.authority])
        .expect("final allocation and init step");
    let tree = pool.rpc.account_data(&create.tree()).expect("tree");
    assert_eq!(tree.len(), tree_account_size() as usize);
    assert_eq!(tree.first(), Some(&TREE_ACCOUNT_DISCRIMINATOR));
    assert_eq!(tree.get(1), Some(&INITIALIZED));
    assert_eq!(tree.get(2..4), Some(&next_tree_id.to_le_bytes()[..]));
    assert_eq!(
        tree_fees(&pool.rpc, &create.tree()).expect("tree fees"),
        (create.fees, 0)
    );
    assert_eq!(
        zolana_program_test::next_tree_id(&pool.rpc).expect("next tree id"),
        2
    );
    assert_eq!(create.tree(), pda::tree(next_tree_id));
}

#[test]
fn pause_tree_changes_only_the_tree_state_byte() {
    let (mollusk, instruction, accounts) = pause_tree_fixture();
    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let authority = instruction.accounts.first().expect("authority meta").pubkey;
    let config = instruction.accounts.get(1).expect("config meta").pubkey;
    let tree = instruction.accounts.get(2).expect("tree meta").pubkey;

    for key in [authority, config] {
        assert_eq!(
            account_named(&result.resulting_accounts, &key),
            account_named(&accounts, &key),
            "pause_tree must not change account {key}"
        );
    }

    let tree_before = account_named(&accounts, &tree);
    let tree_after = account_named(&result.resulting_accounts, &tree);
    assert_eq!(tree_after.lamports, tree_before.lamports);
    assert_eq!(tree_after.owner, tree_before.owner);
    // TreeAccountLayout: discriminator at byte 0, state at byte 1.
    assert_eq!(tree_before.data.get(1), Some(&INITIALIZED));
    let mut expected = tree_before.data.clone();
    *expected.get_mut(1).expect("state byte") = PAUSED;
    assert_eq!(
        tree_after.data, expected,
        "pause_tree must change only the tree state byte"
    );
}

#[test]
fn protocol_authority_rotation_updates_all_authority_fields() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");

    let config_data = pool
        .rpc
        .account_data(&pda::protocol_config())
        .expect("protocol config");
    let config: &ProtocolConfig = bytemuck::from_bytes(&config_data);
    for authority in [
        config.protocol_authority,
        config.tree_creation_authority,
        config.forester_authority,
        config.ring_creation_authority,
    ] {
        assert_eq!(authority.to_bytes(), next.pubkey().to_bytes());
    }
}

#[test]
fn new_protocol_authority_can_update_config() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");

    pool.rpc
        .send_protocol_config_update(
            &next,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect("new authority updates config");
}

#[test]
fn new_tree_creation_authority_can_create_tree() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");
    pool.rpc
        .send_protocol_config_update(
            &next,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect("new authority updates config");

    pool.rpc
        .create_tree(&next)
        .expect("new authority creates tree");
}

#[test]
fn ring_config_creation_initializes_complete_state() {
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
    assert_eq!(
        read_ring_config(&rpc, &ring_config),
        RingConfigState {
            authority: authority.pubkey(),
            enabled: true,
            paused: false,
            bump: pda::ring_auth(&Pubkey::new_from_array(RING_TEST_PROGRAM_ID)).1,
        }
    );
}

#[test]
fn ring_config_update_changes_enabled_state() {
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
    assert_eq!(
        read_ring_config(&rpc, &ring_config),
        RingConfigState {
            authority: authority.pubkey(),
            enabled: false,
            paused: false,
            bump: pda::ring_auth(&Pubkey::new_from_array(RING_TEST_PROGRAM_ID)).1,
        }
    );
}

#[test]
fn ring_config_owner_rotation_updates_authority() {
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
    assert_eq!(
        read_ring_config(&rpc, &ring_config).authority,
        next.pubkey()
    );
}

#[test]
fn new_ring_config_authority_can_update_config() {
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

    rpc.update_ring_config(&next, &ring_config, true, false)
        .expect("new ring authority updates config");
    assert!(read_ring_config(&rpc, &ring_config).enabled);
}
