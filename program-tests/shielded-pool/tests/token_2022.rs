#[path = "common/setup.rs"]
mod common;

use solana_signer::Signer;
use zolana_interface::instruction::Deposit;
use zolana_program_test::{test_blinding, ZolanaProgramTest};

#[test]
fn token_2022_interface_and_proofless_deposit_settle() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = solana_keypair::Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    rpc.ensure_asset_counter(&authority).expect("asset counter");

    let token_program = ZolanaProgramTest::token_2022_program_id();
    let mint = rpc
        .create_mint_with_program(token_program)
        .expect("create Token-2022 mint");
    let (_, vault) = rpc
        .create_spl_interface_with_program(&authority, &mint, token_program)
        .expect("create Token-2022 interface");
    let payer = rpc.payer.insecure_clone();
    let source = rpc
        .create_token_account_with_program(&mint, &payer.pubkey(), token_program)
        .expect("create Token-2022 source");
    rpc.mint_to_with_program(&mint, &source, 1_000, token_program)
        .expect("mint Token-2022 balance");

    let deposit = ZolanaProgramTest::spl_shield_data_with_program(
        400,
        [1u8; 32],
        test_blinding(7),
        &mint,
        &source,
        token_program,
    );
    let ix = Deposit {
        tree: tree.pubkey(),
        depositor: payer.pubkey(),
        deposits: vec![deposit],
    }
    .instruction()
    .expect("build Token-2022 deposit");

    rpc.create_and_send_default_payer_transaction(&[ix], &[])
        .expect("settle Token-2022 deposit");
    assert_eq!(rpc.token_balance(&source), Some(600));
    assert_eq!(rpc.token_balance(&vault), Some(400));
    let vault_account = rpc.svm.get_account(&vault).expect("vault account");
    assert_eq!(vault_account.owner, token_program);
}
