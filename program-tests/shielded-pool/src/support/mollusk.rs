//! Shielded-pool Mollusk fixtures, snapshotted from a green LiteSVM state.
//! Harness-generic execution and assertion helpers live in
//! `zolana_test_utils::mollusk`.

use mollusk_svm::Mollusk;
use solana_account::Account as MolluskAccount;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{ClaimTreeLamports, CreateProtocolConfig, Deposit, PauseTree, SetTreeFees},
    state::TreeFeeSchedule,
    PROGRAM_ID_PUBKEY, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::mollusk::{
    mollusk_instruction, mollusk_with_program, snapshot_instruction_accounts,
};

use crate::support::runtime;

/// The SBF deploy directory: `$CARGO_TARGET_DIR/deploy` when the target dir is
/// overridden, else the workspace default.
fn sbf_dir() -> String {
    match std::env::var("CARGO_TARGET_DIR") {
        Ok(dir) => format!("{dir}/deploy"),
        Err(_) => concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").to_string(),
    }
}

pub fn setup_mollusk() -> (Mollusk, Pubkey) {
    mollusk_with_program(
        &sbf_dir(),
        SHIELDED_POOL_PROGRAM_ID,
        "shielded_pool_program",
    )
}

/// The snapshot or result account stored under `key`.
pub fn account_named<'a>(
    accounts: &'a [(Pubkey, MolluskAccount)],
    key: &Pubkey,
) -> &'a MolluskAccount {
    &accounts
        .iter()
        .find(|(account_key, _)| account_key == key)
        .expect("account present in set")
        .1
}

/// A System-owned account with no data, for impostor and recipient slots.
pub fn system_account(lamports: u64) -> MolluskAccount {
    MolluskAccount {
        lamports,
        data: Vec::new(),
        owner: Pubkey::new_from_array([0; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

fn snapshot(
    test: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: Pubkey,
) -> Vec<(Pubkey, MolluskAccount)> {
    snapshot_instruction_accounts(ix, (&PROGRAM_ID_PUBKEY, program_id), |key| {
        test.svm.get_account(key)
    })
}

pub fn deposit_fixture() -> (Mollusk, Instruction, Vec<(Pubkey, MolluskAccount)>) {
    let mut test = runtime::program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = test.create_tree(&authority).expect("create tree");
    let depositor = Keypair::new();
    test.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund depositor");
    let data = ZolanaProgramTest::sol_shield_data(1_000_000, [8u8; 32]);
    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        deposits: vec![data],
    }
    .instruction()
    .expect("build deposit instruction");
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}

pub fn protocol_config_fixture() -> (Mollusk, Instruction, Vec<(Pubkey, MolluskAccount)>) {
    let mut test = runtime::program_test();
    let payer = Keypair::new();
    let authority = Keypair::new();
    test.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    test.set_upgrade_authority(Some(&authority.pubkey()))
        .expect("install upgradeable program metadata");
    let authority_address = authority.pubkey().to_bytes().into();
    let ix = CreateProtocolConfig {
        fee_payer: payer.pubkey(),
        initialization_authority: authority.pubkey(),
        protocol_authority: authority_address,
        tree_creation_authority: authority_address,
        tree_creation_is_permissionless: false,
        forester_authority: authority_address,
        ring_creation_authority: authority_address,
        ring_activation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
        fee_authority: authority_address,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}

pub const SET_TREE_FEES_FIXTURE_SCHEDULE: TreeFeeSchedule = TreeFeeSchedule {
    fee_per_nullifier: 400,
    append_reimbursement: 10_000,
    close_reimbursement: 340,
};

pub fn set_tree_fees_fixture() -> (Mollusk, Instruction, Vec<(Pubkey, MolluskAccount)>) {
    let mut test = runtime::program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = test.create_tree(&authority).expect("create tree");
    let ix = SetTreeFees {
        authority: authority.pubkey(),
        tree,
        fees: SET_TREE_FEES_FIXTURE_SCHEDULE,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}

pub const CLAIM_TREE_LAMPORTS_FIXTURE_SURPLUS: u64 = 1_000_000_000;

pub fn claim_tree_lamports_fixture() -> (Mollusk, Instruction, Vec<(Pubkey, MolluskAccount)>) {
    let mut test = runtime::program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = test.create_tree(&authority).expect("create tree");
    test.airdrop(&tree, CLAIM_TREE_LAMPORTS_FIXTURE_SURPLUS)
        .expect("fund tree surplus");
    let recipient = Pubkey::new_unique();
    test.airdrop(&recipient, 1_000_000_000)
        .expect("fund recipient");
    let ix = ClaimTreeLamports {
        authority: authority.pubkey(),
        tree,
        recipient,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}

pub fn pause_tree_fixture() -> (Mollusk, Instruction, Vec<(Pubkey, MolluskAccount)>) {
    let mut test = runtime::program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = test.create_tree(&authority).expect("create tree");
    let ix = PauseTree {
        authority: authority.pubkey(),
        tree,
        paused: true,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}
