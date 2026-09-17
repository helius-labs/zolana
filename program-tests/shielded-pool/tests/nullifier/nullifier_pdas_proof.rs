use shielded_pool_tests::support::transact::{current_tree_roots, proof_env, Pool};

use num_bigint::BigUint;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{PublicInputs, PublicTransfers, STATE_TREE_HEIGHT};
use zolana_hasher::{primitives::solana_owner_identity, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{instruction_data::transact::TransactIxData, Transact},
    pda,
    state::TreeFeeSchedule,
    NullifierPda,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{Rejection, Rpc, TransactionTrace};
use zolana_test_utils::{
    nullifier_pda::{
        assert_nullifier_pda, assert_tree_lamports_after_spend, forester_fee_for_inputs,
        nullifier_pda_addresses, nullifier_pda_rent, nullifier_queue_next_index, tree_fees,
        tree_fees_from, tree_id,
    },
    transact::{
        build_transfer_prover_inputs, change_and_dummy_outputs,
        derive_test_transfer_output_blindings, dummy_input, external_data_hash, fe, inline_outputs,
        input_utxo, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes,
        prove_and_verify_transfer, set_output_owner_tags, single_tree_slots, sol_public_slots,
        spend_input, test_private_tx_blinding, SpendInputArgs, TransferProverInputsArgs,
        TEST_BLINDING_SEED,
    },
};
use zolana_transaction::{instructions::transact::PrivateTxHash, SOL_MINT};

const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

fn proof_env_with_fee(fee_per_nullifier: u64) -> Pool {
    let mut env = proof_env();
    let authority = env.authority.insecure_clone();
    env.rpc
        .set_tree_fees(
            &authority,
            &env.tree,
            TreeFeeSchedule {
                fee_per_nullifier,
                ..TreeFeeSchedule::default()
            },
        )
        .expect("set nullifier fee");
    env
}

fn build_valid_transact_ix(env: &mut Pool) -> TransactIxData {
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = PublicKey::from_ed25519(&payer_bytes);
    let owner_pk_hash = owner_public_key
        .owner_proof_input_hash()
        .expect("owner pk hash");
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let event = env
        .rpc
        .deposit_sol(&env.tree, &payer, 0, owner_field)
        .expect("proofless zero deposit");
    let utxo = env
        .rpc
        .indexed_deposit_utxo(&event, owner_public_key)
        .expect("indexed deposit UTXO");
    let blinding = utxo.blinding;
    assert_eq!((utxo.asset, utxo.amount), (SOL_MINT, 0));

    let tree_id = env.tree_id;
    let utxo_hash = utxo
        .hash(&nullifier_pk, &zero, &zero, tree_id)
        .expect("utxo hash");
    let (utxo_root_index, utxo_root, nullifier_root) = current_tree_roots(&env.rpc, &env.tree);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");

    let tree_slots = single_tree_slots(tree_id, utxo_root, nullifier_root);
    let (dummy, dummy_nullifier) = dummy_input(&[2u8; 31], &nf_tree, tree_id).expect("dummy input");
    let real_input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        tree_id,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");

    // Slot 0 is a real zero-amount change output owned by the payer and slots
    // 1-2 are dummies naming it: the payer is this transaction's only signer
    // and `AssertDummyTags` refuses a dummy tag that names only the payer.
    let change_nullifier_key = NullifierKey::from_secret([11u8; 31]);
    let change_nullifier_pk = change_nullifier_key
        .pubkey()
        .expect("change output nullifier pubkey");
    let mut outputs = change_and_dummy_outputs(
        utxo.owner,
        change_nullifier_pk,
        [1u8; 31],
        &[[2u8; 31], [3u8; 31]],
        tree_id,
    )
    .expect("change and dummy outputs");
    let output_hashes = derive_test_transfer_output_blindings(&nullifier, &mut outputs)
        .expect("derive output blindings");

    let mut transact_ix_data = new_transact_ix_data(
        vec![input_utxo(nullifier), input_utxo(dummy_nullifier)],
        utxo_root_index,
        Vec::new(),
        inline_outputs(&output_hashes, &[payer_bytes; 3]),
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    set_output_owner_tags(
        &mut outputs,
        &owner_pk_hashes,
        &[change_nullifier_pk, zero, zero],
    );

    let external_hash = external_data_hash(&transact_ix_data, &[]).expect("external data hash");
    let private_tx_blinding = test_private_tx_blinding(&nullifier).expect("private tx blinding");
    let change_output_hash = *output_hashes.first().expect("change output hash");
    let private_tx = PrivateTxHash::new(
        &[utxo_hash, zero],
        &[change_output_hash, zero, zero],
        &external_hash,
        &private_tx_blinding,
    )
    .hash()
    .expect("private tx hash");
    let signer_hashes = [
        solana_owner_identity(&payer_bytes).expect("payer identity"),
        zero,
        zero,
    ];
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let public_input_hash = PublicInputs {
        nullifiers: &[nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        tree_slots: &tree_slots,
        output_tree_id: tree_id,
        private_tx: &private_tx,
        external_data_hash: &external_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &zero,
        input_flags: &fe(1),
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![real_input, dummy],
        outputs,
        tree_slots,
        output_tree_id: tree_id,
        blinding_seed: TEST_BLINDING_SEED,
        external_data_hash: external_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes.to_vec(),
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "transact")
            .expect("prove transact");
    transact_ix_data.private_tx_hash = private_tx;
    transact_ix_data
}

fn transact_instruction(env: &Pool, data: TransactIxData) -> solana_instruction::Instruction {
    Transact {
        payer: env.rpc.payer.pubkey(),
        input_trees: vec![env.tree],
        output_tree: env.tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
}

fn nullifiers_of(data: &TransactIxData) -> Vec<[u8; 32]> {
    data.inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect()
}

fn tree_account(env: &Pool) -> Account {
    env.rpc.svm.get_account(&env.tree).expect("tree account")
}

fn payer_lamports(env: &Pool) -> u64 {
    env.rpc
        .svm
        .get_account(&env.rpc.payer.pubkey())
        .expect("payer account")
        .lamports
}

#[track_caller]
fn assert_transact_frame(env: &Pool, trace: &TransactionTrace, nullifiers: &[[u8; 32]]) {
    let tree = env.tree;
    let payer = env.rpc.payer.pubkey();
    let mut changed: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .collect();
    changed.sort();
    let mut expected: Vec<Pubkey> = nullifier_pda_addresses(&tree, nullifiers)
        .into_iter()
        .chain([tree, payer])
        .collect();
    expected.sort();
    assert_eq!(
        changed, expected,
        "transact changes only the payer, the tree and the new nullifier PDAs"
    );
    let forester_fee = forester_fee_for_inputs(&tree_account(env), &tree, nullifiers.len() as u64)
        .expect("forester fee");
    let system_invocations = trace
        .logs
        .iter()
        .filter(|line| line.as_str() == "Program 11111111111111111111111111111111 invoke [2]")
        .count();
    assert_eq!(
        system_invocations,
        nullifiers.len() + usize::from(forester_fee != 0),
        "one CPI per nullifier, plus one transfer only when the tree charges a fee"
    );
}

#[test]
fn transact_creates_one_nullifier_pda_per_input() {
    assert_creates_nullifier_pdas(0);
}

#[test]
fn transact_collects_fee_with_unfunded_nullifier_pdas() {
    assert_creates_nullifier_pdas(123);
}

fn assert_creates_nullifier_pdas(fee_per_nullifier: u64) {
    let mut env = proof_env_with_fee(fee_per_nullifier);
    let tree = env.tree;
    let data = build_valid_transact_ix(&mut env);
    let nullifiers = nullifiers_of(&data);
    let queue_next_before = nullifier_queue_next_index(&env.rpc, &tree).expect("queue index");
    let tree_before = tree_account(&env);
    let payer_before = payer_lamports(&env);

    env.rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data)], &[])
        .expect("transact with a valid proof");

    for (nullifier, offset) in nullifiers.iter().zip(0..) {
        assert_nullifier_pda(&env.rpc, &tree, nullifier, queue_next_before + offset)
            .expect("nullifier PDA stores its queue index and canonical bump");
    }
    assert_tree_lamports_after_spend(&env.rpc, &tree, &tree_before, nullifiers.len() as u64)
        .expect("tree lamports");
    let forester_fee = forester_fee_for_inputs(&tree_before, &tree, nullifiers.len() as u64)
        .expect("forester fee");
    assert_eq!(
        payer_before,
        payer_lamports(&env) + LAMPORTS_PER_SIGNATURE + forester_fee,
        "payer pays the transaction fee and the forester fee; nullifier PDA rent comes from the tree"
    );
    let (fees_before, fee_balance_before) =
        tree_fees_from(&tree_before, &tree).expect("tree fees before");
    assert_eq!(
        tree_fees(&env.rpc, &tree).expect("tree fees after"),
        (fees_before, fee_balance_before + forester_fee),
        "transact credits exactly the collected fee to the fee balance"
    );
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("transact trace")
        .clone();
    assert_transact_frame(&env, &trace, &nullifiers);
}

#[test]
fn transact_rejects_a_nullifier_queued_by_an_earlier_transaction() {
    let mut env = proof_env();
    let tree = env.tree;
    let data = build_valid_transact_ix(&mut env);
    let nullifiers = nullifiers_of(&data);
    let queue_next_before = nullifier_queue_next_index(&env.rpc, &tree).expect("queue index");

    env.rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data.clone())], &[])
        .expect("first spend");
    let tree_after_first = tree_account(&env);

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data)], &[])
        .expect_err("replaying a queued nullifier must be rejected");
    Rejection::pool(ShieldedPoolError::NullifierAlreadyQueued).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("replay trace")
        .assert_rolled_back_except(&[env.rpc.payer.pubkey()]);
    assert_eq!(
        tree_account(&env),
        tree_after_first,
        "rejected replay leaves the tree untouched"
    );
    for (nullifier, offset) in nullifiers.iter().zip(0..) {
        assert_nullifier_pda(&env.rpc, &tree, nullifier, queue_next_before + offset)
            .expect("first spend's nullifier PDA unchanged");
    }
}

#[test]
fn transact_tops_up_prefunded_nullifier_pdas() {
    assert_tops_up_prefunded_nullifier_pdas(0);
}

#[test]
fn transact_collects_fee_with_prefunded_nullifier_pdas() {
    assert_tops_up_prefunded_nullifier_pdas(123);
}

fn assert_tops_up_prefunded_nullifier_pdas(fee_per_nullifier: u64) {
    let mut env = proof_env_with_fee(fee_per_nullifier);
    let tree = env.tree;
    let payer = env.rpc.payer.pubkey();
    let data = build_valid_transact_ix(&mut env);
    let nullifiers = nullifiers_of(&data);
    let nullifier_pdas = nullifier_pda_addresses(&tree, &nullifiers);
    let rent = nullifier_pda_rent(&env.rpc).expect("nullifier PDA rent");
    let underfunded = env
        .rpc
        .get_minimum_balance_for_rent_exemption(0)
        .expect("empty account rent");
    assert!(
        underfunded < rent,
        "the smallest rent-exempt donation must stay below the nullifier PDA rent"
    );
    let overfunded = rent + 1_000;
    let prefunds = [underfunded, overfunded];
    for (nullifier_pda, prefund) in nullifier_pdas.iter().zip(prefunds) {
        env.rpc
            .create_and_send_default_payer_transaction(
                &[solana_system_interface::instruction::transfer(
                    &payer,
                    nullifier_pda,
                    prefund,
                )],
                &[],
            )
            .expect("prefund nullifier PDA");
    }
    let queue_next_before = nullifier_queue_next_index(&env.rpc, &tree).expect("queue index");
    let tree_before = tree_account(&env);
    let payer_before = payer_lamports(&env);

    env.rpc
        .create_and_send_default_payer_transaction(&[transact_instruction(&env, data)], &[])
        .expect("transact with prefunded nullifier PDAs");

    let (first_nullifier, second_nullifier) = match nullifiers.as_slice() {
        [first, second] => (first, second),
        other => panic!("expected two nullifiers, got {other:?}"),
    };
    assert_nullifier_pda(&env.rpc, &tree, first_nullifier, queue_next_before)
        .expect("underfunded nullifier PDA topped up to exactly its rent");
    let (overfunded_nullifier_pda, _) = pda::nullifier_pda(&tree, second_nullifier);
    let overfunded_account = env
        .rpc
        .svm
        .get_account(&overfunded_nullifier_pda)
        .expect("overfunded nullifier PDA account");
    let expected_overfunded = Account {
        lamports: overfunded,
        data: borsh::to_vec(&NullifierPda {
            queue_index: queue_next_before + 1,
            tree_id: tree_id(&env.rpc, &tree).expect("tree id"),
        })
        .expect("serialize expected nullifier PDA"),
        owner: pda::shielded_pool_program_id(),
        executable: false,
        rent_epoch: overfunded_account.rent_epoch,
    };
    assert_eq!(
        overfunded_account, expected_overfunded,
        "overfunded nullifier PDA keeps its surplus and is initialized in place"
    );

    let forester_fee = forester_fee_for_inputs(&tree_before, &tree, nullifiers.len() as u64)
        .expect("forester fee");
    let tree_after = tree_account(&env);
    assert_eq!(
        (
            tree_after.lamports,
            tree_after.owner,
            tree_after.data.len(),
            tree_after.executable,
        ),
        (
            tree_before.lamports + forester_fee - (rent - underfunded),
            tree_before.owner,
            tree_before.data.len(),
            tree_before.executable,
        ),
        "tree funds only the missing rent of the underfunded nullifier PDA"
    );
    assert_eq!(
        payer_before,
        payer_lamports(&env) + LAMPORTS_PER_SIGNATURE + forester_fee,
        "payer pays the transaction fee and the forester fee"
    );
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("transact trace")
        .clone();
    assert_transact_frame(&env, &trace, &nullifiers);
}
