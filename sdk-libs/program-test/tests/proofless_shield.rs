//! Proofless SOL deposit coverage.

mod common;

use common::{assert_instruction_error, assert_pool_error, rig, rig_with_tree};
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
use zolana_program_test::{proofless_event_for_wallet, PoolIndexer, PoolTestRig};
use zolana_transaction::Wallet;

type ProoflessMutation = Box<dyn Fn(&mut ProoflessShieldIxData)>;
type ProoflessMutationEntry = (&'static str, ProoflessMutation);

fn funded_depositor(rig: &mut PoolTestRig) -> Keypair {
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("airdrop");
    depositor
}

#[test]
fn sol_deposit_succeeds_and_event_is_faithful() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [3u8; BLINDING_LEN];
    let (data, blinding) = PoolTestRig::wallet_sol_shield_data(750_000_000, &recipient, &seed, 0)
        .expect("wallet deposit data");

    let root_before = rig.state_root(&tree.pubkey()).expect("root");
    let event = rig
        .proofless_shield(&tree, &depositor, &data)
        .expect("deposit");

    assert_eq!(event.amount, 750_000_000);
    assert_eq!(event.asset, [0u8; 32]);
    assert_eq!(event.owner_utxo_hash, data.owner_utxo_hash);
    assert_eq!(event.view_tag, data.view_tag);
    assert_eq!(event.salt, data.salt);
    assert_ne!(
        rig.state_root(&tree.pubkey()).expect("root"),
        root_before,
        "leaf must be appended"
    );

    let mut indexer = PoolIndexer::new();
    indexer
        .record_proofless_shield(&event)
        .expect("record proofless event");
    let by_tag: Vec<_> = indexer.fetch_by_view_tag(&data.view_tag).collect();
    assert_eq!(by_tag.len(), 1, "recipient view tag locates the deposit");
    assert_eq!(by_tag[0].owner_utxo_hash, data.owner_utxo_hash);
    assert!(
        recipient
            .sync_proofless_deposit(&proofless_event_for_wallet(&event), blinding)
            .expect("wallet discovery"),
        "recipient wallet must discover the deposit"
    );
    assert_eq!(recipient.utxos.len(), 1);
    assert_eq!(recipient.utxos[0].hash, event.utxo_hash);
    assert_eq!(recipient.utxos[0].utxo.amount, event.amount);
}

#[test]
fn rejects_bad_amount_shapes() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);

    let mut both = PoolTestRig::sol_shield_data(1_000, [1u8; 32]);
    both.public_spl_amount = Some(5);
    assert_pool_error(
        rig.proofless_shield(&tree, &depositor, &both).unwrap_err(),
        ShieldedPoolError::InvalidTransactShape,
    );

    let mut none = PoolTestRig::sol_shield_data(1_000, [1u8; 32]);
    none.public_sol_amount = None;
    assert_pool_error(
        rig.proofless_shield(&tree, &depositor, &none).unwrap_err(),
        ShieldedPoolError::InvalidTransactShape,
    );

    let zero = PoolTestRig::sol_shield_data(0, [1u8; 32]);
    assert_pool_error(
        rig.proofless_shield(&tree, &depositor, &zero).unwrap_err(),
        ShieldedPoolError::InvalidTransactShape,
    );
}

#[test]
fn rejects_program_owned_proofless_with_wrong_signer() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);

    let mut data = PoolTestRig::sol_shield_data(1_000_000, [3u8; 32]);
    data.cpi_signer = Some(CpiSignerData {
        program_id: [9u8; 32],
        bump: 255,
    });
    let accounts = vec![
        AccountMeta::new(tree.pubkey(), false),
        AccountMeta::new(depositor.pubkey(), true),
        AccountMeta::new_readonly(depositor.pubkey(), true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(rig.cpi_authority(), false),
        AccountMeta::new(depositor.pubkey(), false),
        AccountMeta::new_readonly(rig.program_id, false),
    ];
    let err = rig
        .proofless_shield_with_accounts(accounts, &depositor, &data)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_program_data_without_cpi_signer() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);

    let mutations: Vec<ProoflessMutationEntry> = vec![
        (
            "program_data_hash",
            Box::new(|d| d.program_data_hash = Some([2u8; 32])),
        ),
        (
            "program_data",
            Box::new(|d| d.program_data = Some(vec![4, 5])),
        ),
    ];
    for (name, mutate) in mutations {
        let mut data = PoolTestRig::sol_shield_data(1_000, [1u8; 32]);
        mutate(&mut data);
        let err = rig
            .proofless_shield(&tree, &depositor, &data)
            .expect_err(name);
        assert_pool_error(err, ShieldedPoolError::InvalidTransactShape);
    }
}

fn sol_accounts(rig: &PoolTestRig, tree: &Pubkey, depositor: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*tree, false),
        AccountMeta::new(*depositor, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(rig.cpi_authority(), false),
        AccountMeta::new(*depositor, false),
        AccountMeta::new_readonly(rig.program_id, false),
    ]
}

fn send_raw(
    rig: &mut PoolTestRig,
    depositor: &Keypair,
    accounts: Vec<AccountMeta>,
) -> Result<(), zolana_program_test::RigError> {
    let data = encode_instruction(
        tag::PROOFLESS_SHIELD,
        &PoolTestRig::sol_shield_data(1_000_000, [8u8; 32]),
    );
    let ix = Instruction {
        program_id: rig.program_id,
        accounts,
        data,
    };
    let payer = rig.payer.insecure_clone();
    let payer_pk = payer.pubkey();
    let blockhash = rig.svm.latest_blockhash();
    let msg = solana_message::Message::new(&[ix], Some(&payer_pk));
    let tx = solana_transaction::Transaction::new(&[&payer, depositor], msg, blockhash);
    rig.svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| zolana_program_test::RigError::Litesvm(format!("send_transaction: {e:?}")))
}

#[test]
fn rejects_account_shape_violations() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);
    let tree_pk = tree.pubkey();
    let dep_pk = depositor.pubkey();

    let mut missing_program = sol_accounts(&rig, &tree_pk, &dep_pk);
    missing_program.pop();
    assert_pool_error(
        send_raw(&mut rig, &depositor, missing_program).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut wrong_vault = sol_accounts(&rig, &tree_pk, &dep_pk);
    wrong_vault[3] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_pool_error(
        send_raw(&mut rig, &depositor, wrong_vault).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut extra = sol_accounts(&rig, &tree_pk, &dep_pk);
    extra.insert(5, AccountMeta::new_readonly(Pubkey::new_unique(), false));
    assert_pool_error(
        send_raw(&mut rig, &depositor, extra).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut foreign_source = sol_accounts(&rig, &tree_pk, &dep_pk);
    foreign_source[4] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_pool_error(
        send_raw(&mut rig, &depositor, foreign_source).unwrap_err(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );

    let mut foreign_tree = sol_accounts(&rig, &tree_pk, &dep_pk);
    foreign_tree[0] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_pool_error(
        send_raw(&mut rig, &depositor, foreign_tree).unwrap_err(),
        ShieldedPoolError::InvalidTreeAccounts,
    );
}

#[test]
fn rejects_deposit_into_paused_tree_until_unpaused() {
    let Some((mut rig, authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);

    // Distinct owner hashes keep litesvm from deduping the second transaction
    // as a replay of the first rejected signature.
    rig.pause_tree(&authority, &tree, true).expect("pause");
    let err = rig
        .proofless_shield_sol(&tree, &depositor, 1_000_000, [2u8; 32])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::TreePaused);

    rig.pause_tree(&authority, &tree, false).expect("unpause");
    rig.proofless_shield_sol(&tree, &depositor, 1_000_000, [5u8; 32])
        .expect("deposit after unpause");
}

#[test]
fn rejects_unaffordable_deposit() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);

    let err = rig
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
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);

    // A fresh blockhash keeps the byte-identical second transaction from being
    // deduped as already processed.
    let data = PoolTestRig::sol_shield_data(1_000_000, [4u8; 32]);
    let root0 = rig.state_root(&tree.pubkey()).expect("root");
    rig.proofless_shield(&tree, &depositor, &data).expect("d1");
    let root1 = rig.state_root(&tree.pubkey()).expect("root");
    rig.svm.expire_blockhash();
    rig.proofless_shield(&tree, &depositor, &data).expect("d2");
    let root2 = rig.state_root(&tree.pubkey()).expect("root");
    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
}

#[test]
fn rejects_truncated_instruction_data() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);
    let ix = Instruction {
        program_id: rig.program_id,
        accounts: sol_accounts(&rig, &tree.pubkey(), &depositor.pubkey()),
        data: vec![tag::PROOFLESS_SHIELD, 1, 2, 3],
    };
    let payer = rig.payer.insecure_clone();
    let payer_pk = payer.pubkey();
    let blockhash = rig.svm.latest_blockhash();
    let msg = solana_message::Message::new(&[ix], Some(&payer_pk));
    let tx = solana_transaction::Transaction::new(&[&payer, &depositor], msg, blockhash);
    let err = rig
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| zolana_program_test::RigError::Litesvm(format!("{e:?}")))
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidInstructionData);
}

#[test]
fn rejects_direct_emit_event() {
    let Some(mut rig) = rig() else {
        return;
    };
    let payer = rig.payer.insecure_clone();
    let ix = Instruction {
        program_id: rig.program_id,
        accounts: vec![AccountMeta::new_readonly(payer.pubkey(), true)],
        data: vec![tag::EMIT_EVENT],
    };
    let payer_pk = payer.pubkey();
    let blockhash = rig.svm.latest_blockhash();
    let msg = solana_message::Message::new(&[ix], Some(&payer_pk));
    let tx = solana_transaction::Transaction::new(&[&payer], msg, blockhash);
    let err = rig
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| zolana_program_test::RigError::Litesvm(format!("{e:?}")))
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn rejects_not_enough_accounts() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = funded_depositor(&mut rig);
    // Settlement accounts missing entirely, trailing callee still present:
    // [tree, signer, program]. (Dropping the tail instead trips the
    // self-CPI callee check first — case 10.)
    let mut accounts = sol_accounts(&rig, &tree.pubkey(), &depositor.pubkey());
    accounts.drain(2..5);
    assert_instruction_error(
        send_raw(&mut rig, &depositor, accounts).unwrap_err(),
        "NotEnoughAccountKeys",
    );
}
