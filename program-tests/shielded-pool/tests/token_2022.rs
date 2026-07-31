#[path = "common/setup.rs"]
mod common;

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::{transfer_fee::instruction::initialize_transfer_fee_config, ExtensionType},
    instruction::{initialize_account3, initialize_mint2},
    pod::{PodAccount, PodMint},
};
use zolana_interface::{error::ShieldedPoolError, instruction::Deposit};
use zolana_program_test::{system_create_account_ix, test_blinding, Rejection, ZolanaProgramTest};

fn create_transfer_fee_mint(
    rpc: &mut ZolanaProgramTest,
    transfer_fee_basis_points: u16,
    maximum_fee: u64,
) -> Pubkey {
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let mint = Keypair::new();
    let mint_len =
        ExtensionType::try_calculate_account_len::<PodMint>(&[ExtensionType::TransferFeeConfig])
            .expect("transfer-fee mint length");
    let payer = rpc.payer.insecure_clone();
    let create_ix = system_create_account_ix(
        &payer.pubkey(),
        &mint.pubkey(),
        rpc.svm.minimum_balance_for_rent_exemption(mint_len),
        mint_len as u64,
        &token_program,
    );
    let init_fee_ix = initialize_transfer_fee_config(
        &token_program,
        &mint.pubkey(),
        Some(&payer.pubkey()),
        Some(&payer.pubkey()),
        transfer_fee_basis_points,
        maximum_fee,
    )
    .expect("initialize transfer fee config");
    let init_mint_ix = initialize_mint2(&token_program, &mint.pubkey(), &payer.pubkey(), None, 9)
        .expect("initialize transfer-fee mint");

    rpc.create_and_send_default_payer_transaction(
        &[create_ix, init_fee_ix, init_mint_ix],
        &[&mint],
    )
    .expect("create transfer-fee mint");
    mint.pubkey()
}

fn create_transfer_fee_token_account(
    rpc: &mut ZolanaProgramTest,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let account = Keypair::new();
    let account_len =
        ExtensionType::try_calculate_account_len::<PodAccount>(&[ExtensionType::TransferFeeAmount])
            .expect("transfer-fee token-account length");
    let create_ix = system_create_account_ix(
        &rpc.payer.pubkey(),
        &account.pubkey(),
        rpc.svm.minimum_balance_for_rent_exemption(account_len),
        account_len as u64,
        &token_program,
    );
    let init_ix = initialize_account3(&token_program, &account.pubkey(), mint, owner)
        .expect("initialize transfer-fee token account");

    rpc.create_and_send_default_payer_transaction(&[create_ix, init_ix], &[&account])
        .expect("create transfer-fee token account");
    account.pubkey()
}

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

#[test]
fn transfer_fee_deposit_is_rejected_when_vault_receives_less_than_nominal_amount() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    rpc.ensure_asset_counter(&authority).expect("asset counter");

    // One percent of 400 is 4.
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let mint = create_transfer_fee_mint(&mut rpc, 100, u64::MAX);
    let (_, vault) = rpc
        .create_spl_interface_with_program(&authority, &mint, token_program)
        .expect("create transfer-fee interface");
    let payer = rpc.payer.insecure_clone();
    let source = create_transfer_fee_token_account(&mut rpc, &mint, &payer.pubkey());
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
    .expect("build transfer-fee deposit");
    let state_root_before = rpc.state_root(&tree.pubkey()).expect("state root");

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("396 credited for a nominal 400 deposit must be rejected");
    Rejection::pool(ShieldedPoolError::PublicSettlementFailed).assert_litesvm(error);

    // The failed instruction rolls back both the fee-bearing transfer and the
    // shielded-state append.
    assert_eq!(rpc.token_balance(&source), Some(1_000));
    assert_eq!(rpc.token_balance(&vault), Some(0));
    assert_eq!(
        rpc.state_root(&tree.pubkey()).expect("state root"),
        state_root_before
    );
}
