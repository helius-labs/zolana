//! Proofless SOL deposit steps. Faithful port of `tests/proofless_shield.rs`.

use cucumber::{given, then, when};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{
    tag, CpiSignerData, ProoflessShieldAccounts, ProoflessShieldIxData, PUBLIC_AMOUNT_WITHDRAW_SOL,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::asserts::assert_proofless_shield;
use zolana_transaction::Wallet;

use crate::common::assert_pool_error;
use crate::PoolWorld;

use shielded_pool_program::error::ShieldedPoolError;

fn sol_accounts(
    program_test: &ZolanaProgramTest,
    tree: &Pubkey,
    depositor: &Pubkey,
) -> Vec<AccountMeta> {
    let mut accounts = ProoflessShieldAccounts::sol(*tree, *depositor).account_metas();
    accounts[3] = AccountMeta::new(program_test.cpi_authority(), false);
    accounts[5] = AccountMeta::new_readonly(program_test.program_id, false);
    accounts
}

/// Send a raw proofless-shield transaction with the given accounts, capturing
/// the result into `last_error`. Mirrors the original `send_raw` helper.
fn send_raw(world: &mut PoolWorld, accounts: Vec<AccountMeta>) {
    let depositor = world.depositor().insecure_clone();
    let program_id = world.rig().program_id;
    let mut data = vec![tag::PROOFLESS_SHIELD];
    data.extend_from_slice(
        &ZolanaProgramTest::sol_shield_data(1_000_000, [8u8; 32])
            .serialize()
            .expect("proofless ix data serialization is infallible"),
    );
    let ix = Instruction {
        program_id,
        accounts,
        data,
    };
    let result = world
        .rig()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .map(|_| ());
    world.last_error = result.err();
}

fn assert_invalid_amount_shape(world: &mut PoolWorld, data: &ProoflessShieldIxData) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let err = world
        .rig()
        .proofless_shield(&tree, &depositor, data)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidTransactShape);
}

// === success ===

#[when(expr = "the depositor shields {int} lamports to a fresh recipient")]
fn shield_sol(world: &mut PoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [3u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet deposit data");
    let root_before = world.rig().state_root(&tree).expect("root");
    let depositor = world.depositor().insecure_clone();
    let event = world
        .rig()
        .proofless_shield(&tree, &depositor, &data)
        .expect("deposit");

    assert_proofless_shield(
        world.rig(),
        &tree,
        &event,
        &data,
        amount,
        [0u8; 32],
        root_before,
        &mut recipient,
    );
    world.last_event = Some(event);
    world.recipient = Some(recipient);
}

#[then(expr = "the recipient owns {int} UTXO")]
fn recipient_owns(world: &mut PoolWorld, count: usize) {
    assert_eq!(world.recipient().utxos.len(), count);
}

// === bad amount shapes ===

#[given(expr = "the indexer UTXO count is recorded")]
fn record_indexer(world: &mut PoolWorld) {
    world.indexed_before = Some(world.rig().indexer().utxos().len());
}

#[when(expr = "the depositor shields with no public amount")]
fn shield_no_amount(world: &mut PoolWorld) {
    let mut none = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    none.public_amount = None;
    assert_invalid_amount_shape(world, &none);
}

#[when(expr = "the depositor shields zero lamports")]
fn shield_zero_sol(world: &mut PoolWorld) {
    let zero = ZolanaProgramTest::sol_shield_data(0, [1u8; 32]);
    assert_invalid_amount_shape(world, &zero);
}

#[when(expr = "the depositor shields zero SPL tokens")]
fn shield_zero_spl(world: &mut PoolWorld) {
    let zero_spl = ZolanaProgramTest::spl_shield_data(0, [1u8; 32]);
    assert_invalid_amount_shape(world, &zero_spl);
}

#[when(expr = "the depositor shields in withdraw mode")]
fn shield_withdraw_mode(world: &mut PoolWorld) {
    let mut withdraw_mode = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    withdraw_mode.public_amount_mode = PUBLIC_AMOUNT_WITHDRAW_SOL;
    assert_invalid_amount_shape(world, &withdraw_mode);
}

#[when(expr = "the depositor shields in an unknown mode")]
fn shield_unknown_mode(world: &mut PoolWorld) {
    let mut unknown_mode = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    unknown_mode.public_amount_mode = 9;
    assert_invalid_amount_shape(world, &unknown_mode);
}

#[then(expr = "the indexer UTXO count is unchanged")]
fn indexer_unchanged(world: &mut PoolWorld) {
    let before = world.indexed_before.expect("indexer count recorded");
    assert_eq!(world.rig().indexer().utxos().len(), before);
}

// === program-owned / cpi-signer shapes ===

#[when(expr = "a program-owned proofless deposit is sent with the wrong signer")]
fn program_owned_wrong_signer(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();

    let mut data = ZolanaProgramTest::sol_shield_data(1_000_000, [3u8; 32]);
    data.cpi_signer = Some(CpiSignerData {
        program_id: [9u8; 32],
        bump: 255,
    });
    let mut accounts = sol_accounts(world.rig(), &tree, &depositor.pubkey());
    accounts.insert(2, AccountMeta::new_readonly(depositor.pubkey(), true));
    let err = world
        .rig()
        .proofless_shield_with_accounts(accounts, &depositor, &data)
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the depositor shields with a program data hash but no cpi signer")]
fn shield_program_data_hash(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let mut data = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    data.program_data_hash = Some([2u8; 32]);
    let err = world
        .rig()
        .proofless_shield(&tree, &depositor, &data)
        .expect_err("program_data_hash");
    world.last_error = Some(err);
}

#[then(expr = "the deposit with program data hash is rejected as an invalid transact shape")]
fn rejected_program_data_hash(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidTransactShape);
}

#[when(expr = "the depositor shields with program data but no cpi signer")]
fn shield_program_data(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let mut data = ZolanaProgramTest::sol_shield_data(1_000, [1u8; 32]);
    data.program_data = Some(vec![4, 5]);
    let err = world
        .rig()
        .proofless_shield(&tree, &depositor, &data)
        .expect_err("program_data");
    world.last_error = Some(err);
}

#[then(expr = "the deposit with program data is rejected as an invalid transact shape")]
fn rejected_program_data(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidTransactShape);
}

// === account shape violations ===

#[when(expr = "the depositor shields with the program account missing")]
fn shape_missing_program(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rig(), &tree, &dep);
    accounts.pop();
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with the wrong vault")]
fn shape_wrong_vault(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rig(), &tree, &dep);
    accounts[3] = AccountMeta::new(Pubkey::new_unique(), false);
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with an extra account")]
fn shape_extra_account(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rig(), &tree, &dep);
    accounts.insert(5, AccountMeta::new_readonly(Pubkey::new_unique(), false));
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with a foreign source account")]
fn shape_foreign_source(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rig(), &tree, &dep);
    accounts[4] = AccountMeta::new(Pubkey::new_unique(), false);
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with a foreign tree account")]
fn shape_foreign_tree(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rig(), &tree, &dep);
    accounts[0] = AccountMeta::new(Pubkey::new_unique(), false);
    send_raw(world, accounts);
}

// === paused tree ===

#[when(expr = "the authority pauses the tree")]
fn pause_tree(world: &mut PoolWorld) {
    let authority = world.authority().insecure_clone();
    let tree = world.tree().insecure_clone();
    world
        .rig()
        .pause_tree(&authority, &tree, true)
        .expect("pause");
}

#[when(expr = "the depositor shields {int} lamports into the paused tree")]
fn shield_into_paused(world: &mut PoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let err = world
        .rig()
        .proofless_shield_sol(&tree, &depositor, amount, [2u8; 32])
        .unwrap_err();
    world.last_error = Some(err);
}

#[then(expr = "the deposit is rejected because the tree is paused")]
fn rejected_paused(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::TreePaused);
}

#[when(expr = "the authority unpauses the tree")]
fn unpause_tree(world: &mut PoolWorld) {
    let authority = world.authority().insecure_clone();
    let tree = world.tree().insecure_clone();
    world
        .rig()
        .pause_tree(&authority, &tree, false)
        .expect("unpause");
}

#[then(expr = "the depositor can shield {int} lamports after unpause")]
fn shield_after_unpause(world: &mut PoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    world
        .rig()
        .proofless_shield_sol(&tree, &depositor, amount, [5u8; 32])
        .expect("deposit after unpause");
}

// === unaffordable ===

#[when(expr = "the depositor shields {int} lamports it cannot afford")]
fn shield_unaffordable(world: &mut PoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let err = world
        .rig()
        .proofless_shield_sol(&tree, &depositor, amount, [3u8; 32])
        .unwrap_err();
    world.last_error = Some(err);
}

#[then(expr = "the deposit fails with insufficient lamports")]
fn rejected_insufficient(world: &mut PoolWorld) {
    let err = world.last_error();
    let msg = format!("{err}");
    assert!(
        msg.contains("insufficient lamports"),
        "expected the system transfer to fail, got: {msg}"
    );
}

// === repeat deposits ===

#[when(expr = "the depositor shields {int} lamports twice with the same data")]
fn repeat_deposits(world: &mut PoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let data = ZolanaProgramTest::sol_shield_data(amount, [4u8; 32]);
    let root0 = world.rig().state_root(&tree).expect("root");
    world
        .rig()
        .proofless_shield(&tree, &depositor, &data)
        .expect("d1");
    let root1 = world.rig().state_root(&tree).expect("root");
    world.rig().svm.expire_blockhash();
    world
        .rig()
        .proofless_shield(&tree, &depositor, &data)
        .expect("d2");
    let root2 = world.rig().state_root(&tree).expect("root");
    world.indexed_roots = vec![root0, root1, root2];
}

#[then(expr = "the two deposits create distinct leaves and the indexer tracks them")]
fn distinct_leaves(world: &mut PoolWorld) {
    let roots = world.indexed_roots.clone();
    assert_ne!(roots[0], roots[1]);
    assert_ne!(roots[1], roots[2]);
    assert_eq!(world.rig().indexer().utxos().len(), 2);
    assert_eq!(world.rig().indexer().root(), roots[2]);
}

// === truncated instruction data ===

#[when(expr = "the depositor sends truncated instruction data")]
fn truncated_data(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let accounts = sol_accounts(world.rig(), &tree, &dep);
    let program_id = world.rig().program_id;
    let depositor = world.depositor().insecure_clone();
    let ix = Instruction {
        program_id,
        accounts,
        data: vec![tag::PROOFLESS_SHIELD, 1, 2, 3],
    };
    let err = world
        .rig()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    world.last_error = Some(err);
}

// === direct emit event ===

#[when(expr = "the payer invokes emit-event directly")]
fn direct_emit_event(world: &mut PoolWorld) {
    let program_id = world.rig().program_id;
    let ix = Instruction {
        program_id,
        accounts: Vec::new(),
        data: vec![tag::EMIT_EVENT],
    };
    let outcome = world
        .rig()
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("emit_event no-op");
    assert!(outcome.events.is_empty(), "direct emit_event was indexed");
}

// === not enough accounts ===

#[when(expr = "the depositor shields with too few accounts")]
fn too_few_accounts(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rig(), &tree, &dep);
    accounts.drain(2..5);
    send_raw(world, accounts);
}
