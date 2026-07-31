//! Proofless SOL deposit steps.

use cucumber::{then, when};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{tag, DepositAssetKind, DepositEntry, DepositIxData},
    pda,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_test_utils::litesvm_asserts::litesvm_assert_deposit;
use zolana_transaction::{AssetRegistry, LocalWalletAuthority, Wallet};

use crate::{common::assert_pool_error, ShieldedPoolWorld};

fn sol_accounts(
    program_test: &ZolanaProgramTest,
    tree: &Pubkey,
    depositor: &Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*tree, false),
        AccountMeta::new(*depositor, true),
        AccountMeta::new_readonly(program_test.program_id, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(pda::sol_interface(), false),
    ]
}

fn send_raw(world: &mut ShieldedPoolWorld, accounts: Vec<AccountMeta>) {
    let depositor = world.depositor().insecure_clone();
    let program_id = world.rpc().program_id;
    let mut data = vec![tag::DEPOSIT];
    data.extend_from_slice(
        &DepositIxData {
            assets: vec![DepositAssetKind::Sol],
            deposits: vec![DepositEntry {
                asset_index: 0,
                view_tag: [0u8; 32],
                owner: [8u8; 32],
                blinding: test_blinding(8),
                amount: 1_000_000,
                utxo_data: None,
                memo: None,
            }],
        }
        .serialize()
        .expect("proofless ix data serialization is infallible"),
    );
    let ix = Instruction {
        program_id,
        accounts,
        data,
    };
    let result = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .map(|_| ());
    world.last_error = result.err();
}

// === success ===

#[when(expr = "the depositor shields {int} lamports to a fresh recipient")]
fn shield_sol(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let keypair = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let seed = test_blinding(3);
    let mut data = ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient.identity, &seed, 0)
        .expect("wallet deposit data");
    // Exercise the proofless memo end-to-end: instruction data -> emitted event
    // -> recipient wallet discovery.
    data.memo = Some(b"shielded memo".to_vec());
    let root_before = world.rpc().state_root(&tree).expect("root");
    let depositor = world.depositor().insecure_clone();
    let event = world
        .rpc()
        .deposit(&tree, &depositor, &data)
        .expect("deposit");

    litesvm_assert_deposit(
        world.rpc(),
        &tree,
        &event,
        &data,
        amount,
        [0u8; 32],
        root_before,
        &LocalWalletAuthority::new(Pubkey::default(), &keypair),
        &mut recipient,
    );
    world.last_proofless_view = Some(event);
    world.recipient = Some(recipient);
}

#[then(expr = "the recipient owns {int} UTXO")]
fn recipient_owns(world: &mut ShieldedPoolWorld, count: usize) {
    assert_eq!(world.recipient().utxos.len(), count);
}

#[then(expr = "a proofless deposit event is emitted")]
fn event_emitted(world: &mut ShieldedPoolWorld) {
    assert!(world.last_proofless_view.is_some());
}

// === account shape violations ===

#[when(expr = "the depositor shields with the program account missing")]
fn shape_missing_program(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rpc(), &tree, &dep);
    accounts.remove(2);
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with the wrong vault")]
fn shape_wrong_vault(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rpc(), &tree, &dep);
    accounts[4] = AccountMeta::new(Pubkey::new_unique(), false);
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with an extra account")]
fn shape_extra_account(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rpc(), &tree, &dep);
    accounts.push(AccountMeta::new_readonly(Pubkey::new_unique(), false));
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with a read-only depositor")]
fn shape_readonly_depositor(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rpc(), &tree, &dep);
    accounts[1] = AccountMeta::new_readonly(dep, true);
    send_raw(world, accounts);
}

#[when(expr = "the depositor shields with a foreign tree account")]
fn shape_foreign_tree(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rpc(), &tree, &dep);
    accounts[0] = AccountMeta::new(Pubkey::new_unique(), false);
    send_raw(world, accounts);
}

// === paused tree ===

#[when(expr = "the authority pauses the tree")]
fn pause_tree(world: &mut ShieldedPoolWorld) {
    let authority = world.authority().insecure_clone();
    let tree = world.tree().insecure_clone();
    world
        .rpc()
        .pause_tree(&authority, &tree, true)
        .expect("pause");
}

#[when(expr = "the depositor shields {int} lamports into the paused tree")]
fn shield_into_paused(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let err = world
        .rpc()
        .deposit_sol(&tree, &depositor, amount, [2u8; 32], test_blinding(2))
        .unwrap_err();
    world.last_error = Some(err);
}

#[then(expr = "the deposit is rejected because the tree is paused")]
fn rejected_paused(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::TreePaused);
}

#[when(expr = "the authority unpauses the tree")]
fn unpause_tree(world: &mut ShieldedPoolWorld) {
    let authority = world.authority().insecure_clone();
    let tree = world.tree().insecure_clone();
    world
        .rpc()
        .pause_tree(&authority, &tree, false)
        .expect("unpause");
}

#[then(expr = "the depositor can shield {int} lamports after unpause")]
fn shield_after_unpause(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    world
        .rpc()
        .deposit_sol(&tree, &depositor, amount, [5u8; 32], test_blinding(5))
        .expect("deposit after unpause");
}

// === unaffordable ===

#[when(expr = "the depositor shields {int} lamports it cannot afford")]
fn shield_unaffordable(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let err = world
        .rpc()
        .deposit_sol(&tree, &depositor, amount, [3u8; 32], test_blinding(3))
        .unwrap_err();
    world.last_error = Some(err);
}

#[then(expr = "the deposit fails with insufficient lamports")]
fn rejected_insufficient(world: &mut ShieldedPoolWorld) {
    let err = world.last_error();
    let msg = format!("{err}");
    assert!(
        msg.contains("insufficient lamports"),
        "expected the system transfer to fail, got: {msg}"
    );
}

// === repeat deposits ===

#[when(expr = "the depositor shields {int} lamports twice with the same data")]
fn repeat_deposits(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let data = ZolanaProgramTest::sol_shield_data(amount, [4u8; 32], test_blinding(4));
    let root0 = world.rpc().state_root(&tree).expect("root");
    world.rpc().deposit(&tree, &depositor, &data).expect("d1");
    let root1 = world.rpc().state_root(&tree).expect("root");
    world.rpc().svm.expire_blockhash();
    world.rpc().deposit(&tree, &depositor, &data).expect("d2");
    let root2 = world.rpc().state_root(&tree).expect("root");
    world.state_roots = vec![root0, root1, root2];
}

#[then(expr = "the two deposits create distinct leaves and the indexer tracks them")]
fn distinct_leaves(world: &mut ShieldedPoolWorld) {
    let roots = world.state_roots.clone();
    assert_ne!(roots[0], roots[1]);
    assert_ne!(roots[1], roots[2]);
    assert_eq!(world.rpc().indexer().utxos().len(), 2);
    assert_eq!(world.rpc().indexer().root(), roots[2]);
}

// === truncated instruction data ===

#[when(expr = "the depositor sends truncated instruction data")]
fn truncated_data(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let accounts = sol_accounts(world.rpc(), &tree, &dep);
    let program_id = world.rpc().program_id;
    let depositor = world.depositor().insecure_clone();
    let ix = Instruction {
        program_id,
        accounts,
        data: vec![tag::DEPOSIT, 1, 2, 3],
    };
    let err = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    world.last_error = Some(err);
}

// === direct emit event ===

#[when(expr = "the payer invokes emit-event directly")]
fn direct_emit_event(world: &mut ShieldedPoolWorld) {
    let program_id = world.rpc().program_id;
    let ix = Instruction {
        program_id,
        accounts: Vec::new(),
        data: vec![tag::EMIT_EVENT],
    };
    let outcome = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("emit_event no-op");
    assert!(outcome.events.is_empty(), "direct emit_event was indexed");
}

// === not enough accounts ===

#[when(expr = "the depositor shields with too few accounts")]
fn too_few_accounts(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let dep = world.depositor().pubkey();
    let mut accounts = sol_accounts(world.rpc(), &tree, &dep);
    accounts.truncate(3);
    send_raw(world, accounts);
}
