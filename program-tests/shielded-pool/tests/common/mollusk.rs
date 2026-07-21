//! Shielded-pool Mollusk fixtures, snapshotted from a green LiteSVM state.
//! Harness-generic execution and assertion helpers live in
//! `zolana_mollusk_harness`.

use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_instruction::Instruction as MolluskInstruction;
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use mollusk_svm::Mollusk;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{CreateProtocolConfig, Deposit, PauseTree},
    PROGRAM_ID_PUBKEY, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_mollusk_harness::{
    mollusk_instruction, mollusk_with_program, snapshot_instruction_accounts,
};
use zolana_program_test::ZolanaProgramTest;

use crate::common;

const SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");

pub fn setup_mollusk() -> (Mollusk, MolluskPubkey) {
    mollusk_with_program(SBF_DIR, SHIELDED_POOL_PROGRAM_ID, "shielded_pool_program")
}

fn snapshot(
    test: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: MolluskPubkey,
) -> Vec<(MolluskPubkey, MolluskAccount)> {
    snapshot_instruction_accounts(ix, (&PROGRAM_ID_PUBKEY, program_id), |key| {
        test.svm.get_account(key)
    })
}

pub fn deposit_fixture() -> (
    Mollusk,
    MolluskInstruction,
    Vec<(MolluskPubkey, MolluskAccount)>,
) {
    let mut test = common::program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = test
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let depositor = Keypair::new();
    test.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund depositor");
    let data = ZolanaProgramTest::sol_shield_data(1_000_000, [8u8; 32], [8u8; 31]);
    let ix = Deposit {
        tree: tree.pubkey(),
        depositor: depositor.pubkey(),
        spl: None,
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        amount: data.amount,
        utxo_data: data.utxo_data,
        memo: None,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}

pub fn protocol_config_fixture() -> (
    Mollusk,
    MolluskInstruction,
    Vec<(MolluskPubkey, MolluskAccount)>,
) {
    let mut test = common::program_test();
    let authority = Keypair::new();
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    let authority_address = authority.pubkey().to_bytes().into();
    let ix = CreateProtocolConfig {
        authority: authority.pubkey(),
        protocol_authority: authority_address,
        tree_creation_authority: authority_address,
        tree_creation_is_permissionless: false,
        forester_authority: authority_address,
        zone_creation_authority: authority_address,
        zone_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}

pub fn pause_tree_fixture() -> (
    Mollusk,
    MolluskInstruction,
    Vec<(MolluskPubkey, MolluskAccount)>,
) {
    let mut test = common::program_test();
    let authority = Keypair::new();
    test.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = test
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    let ix = PauseTree {
        authority: authority.pubkey(),
        tree: tree.pubkey(),
        paused: true,
    }
    .instruction();
    let (mollusk, program_id) = setup_mollusk();
    let accounts = snapshot(&test, &ix, program_id);
    (mollusk, mollusk_instruction(&ix), accounts)
}
