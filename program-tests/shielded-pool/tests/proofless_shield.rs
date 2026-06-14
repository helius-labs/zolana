//! Proofless SOL deposit coverage.

mod common;

use common::{assert_instruction_error, assert_pool_error, program_test, program_test_with_tree};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{
    encode_instruction, tag, CpiSignerData, ProoflessShieldIxData,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{proofless_event_for_wallet, ZolanaProgramTest};
use zolana_transaction::Wallet;

fn funded_depositor(program_test: &mut ZolanaProgramTest) -> Keypair {
    let depositor = Keypair::new();
    program_test
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("airdrop");
    depositor
}

fn assert_invalid_amount_shape(
    program_test: &mut ZolanaProgramTest,
    tree: &Keypair,
    depositor: &Keypair,
    data: &ProoflessShieldIxData,
) {
    assert_pool_error(
        program_test
            .proofless_shield(tree, depositor, data)
            .unwrap_err(),
        ShieldedPoolError::InvalidTransactShape,
    );
}

#[test]
fn sol_deposit_succeeds_and_event_is_faithful() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [3u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_sol_shield_data(750_000_000, &recipient, &seed, 0)
        .expect("wallet deposit data");

    let root_before = program_test.state_root(&tree.pubkey()).expect("root");
    let event = program_test
        .proofless_shield(&tree, &depositor, &data)
        .expect("deposit");

    assert_eq!(event.amount, 750_000_000);
    assert_eq!(event.asset, [0u8; 32]);
    assert_eq!(event.owner_utxo_hash, data.owner_utxo_hash);
    assert_eq!(event.view_tag, data.view_tag);
    assert_eq!(event.salt, data.salt);
    assert_ne!(
        program_test.state_root(&tree.pubkey()).expect("root"),
        root_before,
        "leaf must be appended"
    );

    assert_eq!(
        program_test.indexer().root(),
        program_test.state_root(&tree.pubkey()).expect("root")
    );
    let by_tag: Vec<_> = program_test
        .indexer()
        .fetch_by_view_tag(&data.view_tag)
        .collect();
    assert_eq!(by_tag.len(), 1, "recipient view tag locates the deposit");
    assert_eq!(by_tag[0].owner_utxo_hash, data.owner_utxo_hash);
    assert!(
        recipient
            .sync_proofless_deposit(&proofless_event_for_wallet(&event))
            .expect("wallet discovery"),
        "recipient wallet must discover the deposit"
    );
    assert_eq!(recipient.utxos.len(), 1);
    assert_eq!(recipient.utxos[0].hash, event.utxo_hash);
    assert_eq!(recipient.utxos[0].utxo.amount, event.amount);
}

#[test]
fn rejects_bad_amount_shapes() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);
    let indexed_before = program_test.indexer().utxos().len();

    let mut both = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    both.public_spl_amount = Some(5);
    assert_invalid_amount_shape(&mut program_test, &tree, &depositor, &both);

    let mut none = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    none.public_sol_amount = None;
    assert_invalid_amount_shape(&mut program_test, &tree, &depositor, &none);

    let zero = ZolanaProgramTest::sol_shield_data(0, [1u8; 32]);
    assert_invalid_amount_shape(&mut program_test, &tree, &depositor, &zero);

    let mut sol_zero_with_spl = ZolanaProgramTest::spl_shield_data(5, [1u8; 32]);
    sol_zero_with_spl.public_sol_amount = Some(0);
    assert_invalid_amount_shape(&mut program_test, &tree, &depositor, &sol_zero_with_spl);

    let mut spl_zero_with_sol = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    spl_zero_with_sol.public_spl_amount = Some(0);
    assert_invalid_amount_shape(&mut program_test, &tree, &depositor, &spl_zero_with_sol);

    assert_eq!(program_test.indexer().utxos().len(), indexed_before);
}

#[test]
fn rejects_program_owned_proofless_with_wrong_signer() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);

    let mut data = ZolanaProgramTest::sol_shield_data(1_000_000, [3u8; 32]);
    data.cpi_signer = Some(CpiSignerData {
        program_id: [9u8; 32],
        bump: 255,
    });
    let accounts = vec![
        AccountMeta::new(tree.pubkey(), false),
        AccountMeta::new(depositor.pubkey(), true),
        AccountMeta::new_readonly(depositor.pubkey(), true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(program_test.cpi_authority(), false),
        AccountMeta::new(depositor.pubkey(), false),
        AccountMeta::new_readonly(program_test.program_id, false),
    ];
    let err = program_test
        .proofless_shield_with_accounts(accounts, &depositor, &data)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_program_data_without_cpi_signer() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);

    let mut with_program_data_hash = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    with_program_data_hash.program_data_hash = Some([2u8; 32]);
    let err = program_test
        .proofless_shield(&tree, &depositor, &with_program_data_hash)
        .expect_err("program_data_hash");
    assert_pool_error(err, ShieldedPoolError::InvalidTransactShape);

    let mut with_program_data = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    with_program_data.program_data = Some(vec![4, 5]);
    let err = program_test
        .proofless_shield(&tree, &depositor, &with_program_data)
        .expect_err("program_data");
    assert_pool_error(err, ShieldedPoolError::InvalidTransactShape);
}

fn sol_accounts(
    program_test: &ZolanaProgramTest,
    tree: &Pubkey,
    depositor: &Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*tree, false),
        AccountMeta::new(*depositor, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(program_test.cpi_authority(), false),
        AccountMeta::new(*depositor, false),
        AccountMeta::new_readonly(program_test.program_id, false),
    ]
}

fn send_raw(
    program_test: &mut ZolanaProgramTest,
    depositor: &Keypair,
    accounts: Vec<AccountMeta>,
) -> Result<(), zolana_program_test::ProgramTestError> {
    let data = encode_instruction(
        tag::PROOFLESS_SHIELD,
        &ZolanaProgramTest::sol_shield_data(1_000_000, [8u8; 32]),
    );
    let ix = Instruction {
        program_id: program_test.program_id,
        accounts,
        data,
    };
    program_test
        .create_and_send_default_payer_transaction(&[ix], &[depositor])
        .map(|_| ())
}

#[test]
fn rejects_account_shape_violations() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);
    let tree_pk = tree.pubkey();
    let dep_pk = depositor.pubkey();

    let mut missing_program = sol_accounts(&program_test, &tree_pk, &dep_pk);
    missing_program.pop();
    assert_pool_error(
        send_raw(&mut program_test, &depositor, missing_program).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut wrong_vault = sol_accounts(&program_test, &tree_pk, &dep_pk);
    wrong_vault[3] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_pool_error(
        send_raw(&mut program_test, &depositor, wrong_vault).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut extra = sol_accounts(&program_test, &tree_pk, &dep_pk);
    extra.insert(5, AccountMeta::new_readonly(Pubkey::new_unique(), false));
    assert_pool_error(
        send_raw(&mut program_test, &depositor, extra).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut foreign_source = sol_accounts(&program_test, &tree_pk, &dep_pk);
    foreign_source[4] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_pool_error(
        send_raw(&mut program_test, &depositor, foreign_source).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut foreign_tree = sol_accounts(&program_test, &tree_pk, &dep_pk);
    foreign_tree[0] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_pool_error(
        send_raw(&mut program_test, &depositor, foreign_tree).unwrap_err(),
        ShieldedPoolError::InvalidTreeAccounts,
    );
}

#[test]
fn rejects_deposit_into_paused_tree_until_unpaused() {
    let Some((mut program_test, authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);

    // Distinct owner hashes keep litesvm from deduping the second transaction
    // as a replay of the first rejected signature.
    program_test
        .pause_tree(&authority, &tree, true)
        .expect("pause");
    let err = program_test
        .proofless_shield_sol(&tree, &depositor, 1_000_000, [2u8; 32])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::TreePaused);

    program_test
        .pause_tree(&authority, &tree, false)
        .expect("unpause");
    program_test
        .proofless_shield_sol(&tree, &depositor, 1_000_000, [5u8; 32])
        .expect("deposit after unpause");
}

#[test]
fn rejects_unaffordable_deposit() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);

    let err = program_test
        .proofless_shield_sol(&tree, &depositor, 100_000_000_000, [3u8; 32])
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("insufficient lamports"),
        "expected the system transfer to fail, got: {msg}"
    );
}

#[test]
fn repeat_deposits_create_distinct_leaves() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);

    // A fresh blockhash keeps the byte-identical second transaction from being
    // deduped as already processed.
    let data = ZolanaProgramTest::sol_shield_data(1_000_000, [4u8; 32]);
    let root0 = program_test.state_root(&tree.pubkey()).expect("root");
    program_test
        .proofless_shield(&tree, &depositor, &data)
        .expect("d1");
    let root1 = program_test.state_root(&tree.pubkey()).expect("root");
    program_test.svm.expire_blockhash();
    program_test
        .proofless_shield(&tree, &depositor, &data)
        .expect("d2");
    let root2 = program_test.state_root(&tree.pubkey()).expect("root");
    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
    assert_eq!(program_test.indexer().utxos().len(), 2);
    assert_eq!(program_test.indexer().root(), root2);
}

#[test]
fn rejects_truncated_instruction_data() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);
    let ix = Instruction {
        program_id: program_test.program_id,
        accounts: sol_accounts(&program_test, &tree.pubkey(), &depositor.pubkey()),
        data: vec![tag::PROOFLESS_SHIELD, 1, 2, 3],
    };
    let err = program_test
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidInstructionData);
}

#[test]
fn rejects_direct_emit_event() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let ix = Instruction {
        program_id: program_test.program_id,
        accounts: vec![AccountMeta::new_readonly(program_test.payer.pubkey(), true)],
        data: vec![tag::EMIT_EVENT],
    };
    let err = program_test
        .create_and_send_default_payer_transaction(&[ix], &[])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn rejects_not_enough_accounts() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut program_test);
    let mut accounts = sol_accounts(&program_test, &tree.pubkey(), &depositor.pubkey());
    accounts.drain(2..5);
    assert_instruction_error(
        send_raw(&mut program_test, &depositor, accounts).unwrap_err(),
        "NotEnoughAccountKeys",
    );
}
