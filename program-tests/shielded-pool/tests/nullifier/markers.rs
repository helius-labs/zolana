use shielded_pool_tests::support::fixtures::Pool;

use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData, TransactProof},
        CloseNullifierMarkers, Transact,
    },
    pda,
    state::{
        tree_account_size, ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE, ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
    },
    NullifierMarker, NULLIFIER_MARKER_SIZE, N_PUBLIC_SLOTS,
};
use zolana_program_test::{Rejection, Rpc, TransactionTrace};
use zolana_test_utils::{
    nullifier_marker::{
        assert_nullifier_marker, assert_nullifier_markers_absent, marker_addresses,
        nullifier_marker_rent, tree_close_before_index,
    },
    transact::{eddsa_input_utxo, fe, inline_output},
};
use zolana_tree::{TreeAccount, TreeAccountLayout, UTXO_TREE_HEIGHT};

const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
const TRANSACT_MARKER_OFFSET: usize = 5;

fn transfer_ix_data(n_in: u64, n_out: u64) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(n_in as u8, n_out as u8, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: (1..=n_in).map(|n| eddsa_input_utxo(fe(n), 0)).collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: (11..11 + n_out)
            .map(|n| inline_output(fe(n), fe(n)))
            .collect(),
        messages: Vec::new(),
    }
}

fn nullifiers_of(data: &TransactIxData) -> Vec<[u8; 32]> {
    data.inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect()
}

fn transact_instruction(env: &Pool, data: TransactIxData) -> Instruction {
    Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
}

fn close_instruction(env: &Pool, nullifiers: Vec<[u8; 32]>) -> Instruction {
    CloseNullifierMarkers {
        tree: env.tree.pubkey(),
        nullifiers,
    }
    .instruction()
}

fn marker_rent(env: &Pool) -> u64 {
    nullifier_marker_rent(&env.rpc).expect("nullifier marker rent")
}

fn tree_rent(env: &Pool) -> u64 {
    env.rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size())
        .expect("tree rent")
}

fn tree_account(env: &Pool) -> Account {
    env.rpc
        .svm
        .get_account(&env.tree.pubkey())
        .expect("tree account")
}

fn funded_system_account(env: &mut Pool) -> Pubkey {
    let account = Pubkey::new_unique();
    env.rpc
        .airdrop(&account, 1_000_000)
        .expect("fund system account");
    account
}

fn write_marker_account(
    env: &mut Pool,
    nullifier: &[u8; 32],
    marker: NullifierMarker,
    lamports: u64,
) -> Pubkey {
    let (address, _) = pda::nullifier_marker(&env.tree.pubkey(), nullifier);
    env.rpc
        .svm
        .set_account(
            address,
            Account {
                lamports,
                data: borsh::to_vec(&marker).expect("serialize nullifier marker"),
                owner: pda::shielded_pool_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write nullifier marker fixture");
    address
}

fn queue_marker(env: &mut Pool, nullifier: &[u8; 32], queue_index: u64) -> Pubkey {
    let (_, bump) = pda::nullifier_marker(&env.tree.pubkey(), nullifier);
    let rent = marker_rent(env);
    write_marker_account(env, nullifier, NullifierMarker { queue_index, bump }, rent)
}

fn queue_markers(env: &mut Pool, nullifiers: &[[u8; 32]], first_queue_index: u64) -> Vec<Pubkey> {
    nullifiers
        .iter()
        .zip(first_queue_index..)
        .map(|(nullifier, queue_index)| queue_marker(env, nullifier, queue_index))
        .collect()
}

fn set_close_before_index(env: &mut Pool, close_before_index: u64) {
    let tree = env.tree.pubkey();
    let mut account = tree_account(env);
    {
        let mut on_chain =
            TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
        on_chain
            .nullifer_tree()
            .get_metadata_mut()
            .close_before_index = close_before_index;
    }
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write tree watermark fixture");
    assert_eq!(
        tree_close_before_index(&env.rpc, &tree).expect("close_before_index"),
        close_before_index,
        "watermark fixture"
    );
}

fn set_synthetic_watermark_and_zero_root(
    env: &mut Pool,
    close_before_index: u64,
    root_index: usize,
) {
    const NULLIFIER_ZKP_BATCHES: usize =
        (ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE / ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE) as usize;
    type Layout = TreeAccountLayout<
        UTXO_TREE_HEIGHT,
        { ADDRESS_TREE_ROOT_HISTORY_CAPACITY as usize },
        NULLIFIER_ZKP_BATCHES,
    >;

    let tree = env.tree.pubkey();
    let mut account = tree_account(env);
    let layout: &mut Layout = wincode::deserialize_mut(&mut account.data)
        .expect("load tree layout for reclaimable fixture");
    layout.nullifier.metadata.close_before_index = close_before_index;
    *layout
        .nullifier
        .root_history
        .data
        .get_mut(root_index)
        .expect("fixture root index") = [0u8; 32];
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write reclaimable root fixture");
}

fn set_tree_lamports(env: &mut Pool, lamports: u64) {
    let tree = env.tree.pubkey();
    let mut account = tree_account(env);
    account.lamports = lamports;
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write tree lamports fixture");
}

#[track_caller]
fn expect_transact_rejection(env: &mut Pool, ix: Instruction, expected: Rejection) {
    let tree_before = tree_account(env);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect_err("transact must be rejected");
    expected.at(1).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("rejected transact trace")
        .assert_rolled_back_except(&[env.rpc.payer.pubkey()]);
    assert_eq!(
        tree_account(env),
        tree_before,
        "rejected transact must leave the tree untouched"
    );
}

#[track_caller]
fn expect_close_rejection(env: &mut Pool, ix: Instruction, expected: Rejection) {
    let tree_before = tree_account(env);
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("close must be rejected");
    expected.assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("rejected close trace")
        .assert_rolled_back_except(&[env.rpc.payer.pubkey()]);
    assert_eq!(
        tree_account(env),
        tree_before,
        "rejected close must leave the tree untouched"
    );
}

#[track_caller]
fn assert_close_markers(
    env: &Pool,
    trace: &TransactionTrace,
    tree_before: &Account,
    nullifiers: &[[u8; 32]],
) {
    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.pubkey();
    let rent = marker_rent(env);
    let markers = marker_addresses(&tree, nullifiers);

    let mut expected_tree = tree_before.clone();
    expected_tree.lamports += rent * nullifiers.len() as u64;
    assert_eq!(
        tree_account(env),
        expected_tree,
        "close moves exactly the marker rent into the tree and touches no tree byte"
    );
    assert_nullifier_markers_absent(&env.rpc, &tree, nullifiers).expect("markers closed");

    let mut changed: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .collect();
    changed.sort();
    let mut expected_changed: Vec<Pubkey> = markers.iter().copied().chain([tree, payer]).collect();
    expected_changed.sort();
    assert_eq!(
        changed, expected_changed,
        "close changes only the tree, the closed markers and the fee payer"
    );
    for transition in &trace.accounts {
        if markers.contains(&transition.address) {
            let before = transition.before.as_ref().expect("marker before close");
            let after_balance_and_size = transition
                .after
                .as_ref()
                .map(|after| (after.lamports, after.data_len))
                .unwrap_or((0, 0));
            assert_eq!(
                ((before.lamports, before.data_len), after_balance_and_size),
                ((rent, NULLIFIER_MARKER_SIZE), (0, 0)),
                "marker {} holds exactly its rent before close and is empty after",
                transition.address
            );
        } else if transition.address == payer {
            let before = transition.before.as_ref().expect("payer before close");
            let after = transition.after.as_ref().expect("payer after close");
            assert_eq!(
                before.lamports,
                after.lamports + LAMPORTS_PER_SIGNATURE,
                "fee payer pays exactly the transaction fee"
            );
        }
    }
}

#[test]
fn transact_rejects_a_pending_nullifier() {
    let mut env = Pool::initialized();
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);
    let pending = *nullifiers.first().expect("first nullifier");
    queue_marker(&mut env, &pending, 0);

    let ix = transact_instruction(&env, data);
    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierAlreadyQueued),
    );
    assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), &pending, 0).expect("pending marker");
    assert_nullifier_markers_absent(
        &env.rpc,
        &env.tree.pubkey(),
        nullifiers.get(1..).expect("second nullifier"),
    )
    .expect("no marker for the rejected input");
}

#[test]
fn transact_rejects_the_same_nullifier_twice_in_one_instruction() {
    let mut env = Pool::initialized();
    let mut data = transfer_ix_data(2, 3);
    let first = data.inputs.first().expect("first input").nullifier_hash;
    data.inputs.get_mut(1).expect("second input").nullifier_hash = first;

    let ix = transact_instruction(&env, data);
    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierAlreadyQueued),
    );
    assert_nullifier_markers_absent(&env.rpc, &env.tree.pubkey(), &[first])
        .expect("duplicate marker rolled back");
}

#[test]
fn transact_rejects_swapped_nullifier_markers() {
    let mut env = Pool::initialized();
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);
    let mut ix = transact_instruction(&env, data);
    ix.accounts
        .swap(TRANSACT_MARKER_OFFSET, TRANSACT_MARKER_OFFSET + 1);

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierMarker),
    );
    assert_nullifier_markers_absent(&env.rpc, &env.tree.pubkey(), &nullifiers)
        .expect("no marker created");
}

#[test]
fn transact_rejects_a_foreign_account_in_a_marker_slot() {
    let mut env = Pool::initialized();
    let impostor = funded_system_account(&mut env);
    let mut ix = transact_instruction(&env, transfer_ix_data(2, 3));
    ix.accounts
        .get_mut(TRANSACT_MARKER_OFFSET)
        .expect("first marker meta")
        .pubkey = impostor;

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierMarker),
    );
}

#[test]
fn transact_rejects_a_read_only_nullifier_marker() {
    let mut env = Pool::initialized();
    let mut ix = transact_instruction(&env, transfer_ix_data(2, 3));
    ix.accounts
        .get_mut(TRANSACT_MARKER_OFFSET + 1)
        .expect("second marker meta")
        .is_writable = false;

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn transact_rejects_missing_nullifier_marker_accounts() {
    let mut env = Pool::initialized();
    let mut ix = transact_instruction(&env, transfer_ix_data(2, 3));
    ix.accounts.truncate(TRANSACT_MARKER_OFFSET);

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn transact_rejects_a_tree_short_of_marker_rent() {
    let mut env = Pool::initialized();
    let tree_rent = tree_rent(&env);
    let marker_rent = marker_rent(&env);
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);

    for tree_lamports in [tree_rent, tree_rent + 2 * marker_rent - 1] {
        set_tree_lamports(&mut env, tree_lamports);
        let ix = transact_instruction(&env, data.clone());
        expect_transact_rejection(
            &mut env,
            ix,
            Rejection::pool(ShieldedPoolError::InsufficientNullifierMarkerRent),
        );
        assert_nullifier_markers_absent(&env.rpc, &env.tree.pubkey(), &nullifiers)
            .expect("no marker survives an underfunded tree");
    }
}

#[test]
fn close_rejects_marker_before_batch_is_reclaimable() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree.pubkey()).expect("close_before_index"),
        0,
        "fresh tree has no reclaimable batches"
    );

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierMarkerNotClosable),
    );
    assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), &nullifier, 0).expect("marker kept");
}

#[test]
fn close_honours_the_watermark_boundary() {
    let mut env = Pool::initialized();
    let at_watermark = fe(1);
    let below_watermark = fe(2);
    queue_marker(&mut env, &at_watermark, 5);
    queue_marker(&mut env, &below_watermark, 4);
    set_close_before_index(&mut env, 5);

    let ix = close_instruction(&env, vec![at_watermark]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierMarkerNotClosable),
    );
    assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), &at_watermark, 5)
        .expect("marker at the watermark kept");

    let tree_before = tree_account(&env);
    env.rpc
        .create_and_send_default_payer_transaction(
            &[close_instruction(&env, vec![below_watermark])],
            &[],
        )
        .expect("close a marker below the watermark");
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("close trace")
        .clone();
    assert_close_markers(&env, &trace, &tree_before, &[below_watermark]);
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree.pubkey()).expect("close_before_index"),
        5,
        "close does not move the watermark"
    );
}

#[test]
fn close_returns_marker_rent_to_the_tree() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2), fe(3)];
    queue_markers(&mut env, &nullifiers, 0);
    set_close_before_index(&mut env, 3);
    let tree_before = tree_account(&env);

    env.rpc
        .create_and_send_default_payer_transaction(
            &[close_instruction(&env, nullifiers.to_vec())],
            &[],
        )
        .expect("close markers below the reclaim watermark");
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("close trace")
        .clone();
    assert_close_markers(&env, &trace, &tree_before, &nullifiers);
}

#[test]
fn closed_marker_does_not_make_an_obsolete_root_spendable_again() {
    let mut env = Pool::initialized();
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);
    queue_markers(&mut env, &nullifiers, 0);
    set_synthetic_watermark_and_zero_root(&mut env, nullifiers.len() as u64, 0);

    env.rpc
        .create_and_send_default_payer_transaction(
            &[close_instruction(&env, nullifiers.clone())],
            &[],
        )
        .expect("close markers below the reclaim watermark");
    assert_nullifier_markers_absent(&env.rpc, &env.tree.pubkey(), &nullifiers)
        .expect("closable markers closed");

    let replay = transact_instruction(&env, data);
    expect_transact_rejection(
        &mut env,
        replay,
        Rejection::pool(ShieldedPoolError::StaleNullifierRoot),
    );
    assert_nullifier_markers_absent(&env.rpc, &env.tree.pubkey(), &nullifiers)
        .expect("failed replay rolls marker creation back");
}

#[test]
fn close_is_atomic_across_markers() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2), fe(3)];
    queue_markers(&mut env, &nullifiers, 0);
    set_close_before_index(&mut env, 2);

    let ix = close_instruction(&env, nullifiers.to_vec());
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierMarkerNotClosable),
    );
    for (nullifier, queue_index) in nullifiers.iter().zip(0..) {
        assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), nullifier, queue_index)
            .expect("no marker closed by a rejected batch");
    }
}

#[test]
fn close_rejects_a_mismatched_nullifier_marker_pair() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2)];
    queue_markers(&mut env, &nullifiers, 0);
    set_close_before_index(&mut env, 2);
    let mut ix = close_instruction(&env, nullifiers.to_vec());
    ix.accounts.swap(1, 2);

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierMarker),
    );
}

#[test]
fn close_rejects_a_marker_with_a_wrong_bump() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    let (_, bump) = pda::nullifier_marker(&env.tree.pubkey(), &nullifier);
    let rent = marker_rent(&env);
    write_marker_account(
        &mut env,
        &nullifier,
        NullifierMarker {
            queue_index: 0,
            bump: bump.wrapping_sub(1),
        },
        rent,
    );
    set_close_before_index(&mut env, 1);

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierMarker),
    );
}

#[test]
fn close_rejects_a_non_marker_account() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    set_close_before_index(&mut env, 1);
    let system_owned = funded_system_account(&mut env);
    let tree = env.tree.pubkey();

    for impostor in [system_owned, tree] {
        let mut ix = close_instruction(&env, vec![nullifier]);
        ix.accounts.get_mut(1).expect("marker meta").pubkey = impostor;
        expect_close_rejection(
            &mut env,
            ix,
            Rejection::pool(ShieldedPoolError::InvalidNullifierMarker),
        );
    }
}

#[test]
fn close_rejects_a_read_only_marker_meta() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    set_close_before_index(&mut env, 1);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts.get_mut(1).expect("marker meta").is_writable = false;

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn close_rejects_the_same_marker_twice_in_one_instruction() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    set_close_before_index(&mut env, 1);

    let ix = close_instruction(&env, vec![nullifier, nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierMarker),
    );
    assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), &nullifier, 0).expect("marker kept");
}

#[test]
fn close_rejects_an_empty_nullifier_list() {
    let mut env = Pool::initialized();

    let ix = close_instruction(&env, Vec::new());
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidInstructionData),
    );
}

#[test]
fn close_rejects_a_trailing_account() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    set_close_before_index(&mut env, 1);
    let extra = funded_system_account(&mut env);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts.push(AccountMeta::new(extra, false));

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidInstructionData),
    );
    assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), &nullifier, 0).expect("marker kept");
}

#[test]
fn close_rejects_a_paused_tree() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    set_close_before_index(&mut env, 1);
    let authority = env.authority.insecure_clone();
    env.rpc
        .pause_tree(&authority, &env.tree, true)
        .expect("pause tree");

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(&mut env, ix, Rejection::pool(ShieldedPoolError::TreePaused));
    assert_nullifier_marker(&env.rpc, &env.tree.pubkey(), &nullifier, 0).expect("marker kept");
}

#[test]
fn close_rejects_a_read_only_tree_meta() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    set_close_before_index(&mut env, 1);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts.first_mut().expect("tree meta").is_writable = false;

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn close_rejects_a_non_tree_account() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_marker(&mut env, &nullifier, 0);
    let impostor = funded_system_account(&mut env);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts.first_mut().expect("tree meta").pubkey = impostor;

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidTreeAccounts),
    );
}
