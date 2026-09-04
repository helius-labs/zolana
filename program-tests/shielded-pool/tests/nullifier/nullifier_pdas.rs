use shielded_pool_tests::support::{fixtures::Pool, transact::set_synthetic_nullifier_sequence};

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
        CloseNullifierPdas, Transact,
    },
    pda,
    state::{
        tree_account_size, TreeFeeSchedule, NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
        NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    },
    NullifierPda, NULLIFIER_PDA_SIZE, N_PUBLIC_SLOTS,
};
use zolana_program_test::{ProgramTestError, Rejection, Rpc, TransactionTrace, ZolanaProgramTest};
use zolana_test_utils::{
    nullifier_pda::{
        assert_nullifier_pda, assert_nullifier_pdas, assert_nullifier_pdas_absent,
        nullifier_pda_addresses, nullifier_pda_rent, tree_close_before_index, tree_fees,
        tree_fees_from,
    },
    transact::{eddsa_input_utxo, fe, inline_output},
};
use zolana_tree::{TreeAccount, TreeAccountLayout, UTXO_TREE_HEIGHT};

const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
const CLOSE_TRANSACTION_FEE: u64 = 2 * LAMPORTS_PER_SIGNATURE;
const TRANSACT_NULLIFIER_PDA_OFFSET: usize = 5;
const CLOSE_TREE_OFFSET: usize = 2;
const CLOSE_NULLIFIER_PDA_OFFSET: usize = 4;
const NULLIFIER_ZKP_BATCHES: usize =
    (NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE / NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE) as usize;
const SYNTHETIC_CLOSE_BEFORE_INDEX: u64 = NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE + 1;
type Layout = TreeAccountLayout<UTXO_TREE_HEIGHT, NULLIFIER_ZKP_BATCHES>;

fn transfer_ix_data(n_in: u64, n_out: u64) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        interface_transfers: Vec::new(),
        outputs: (11..11 + n_out)
            .map(|n| inline_output(fe(n), fe(n)))
            .collect(),
        messages: Vec::new(),
        proof: TransactProof::zeroed(),
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(n_in as u8, n_out as u8, N_PUBLIC_SLOTS as u8),
        inputs: (1..=n_in).map(|n| eddsa_input_utxo(fe(n), 0)).collect(),
        data_hash: None,
        ring_data_hash: None,
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
        input_tree: env.tree,
        output_tree: env.tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
    .expect("valid transact builder input")
}

fn close_instruction(env: &Pool, nullifiers: Vec<[u8; 32]>) -> Instruction {
    close_instruction_for(env, env.rpc.payer.pubkey(), nullifiers)
}

fn close_instruction_for(
    env: &Pool,
    reimbursement_recipient: Pubkey,
    nullifiers: Vec<[u8; 32]>,
) -> Instruction {
    CloseNullifierPdas {
        authority: env.authority.pubkey(),
        tree: env.tree,
        reimbursement_recipient,
        nullifiers,
    }
    .instruction()
}

fn send_close(env: &mut Pool, ix: Instruction) -> Result<(), ProgramTestError> {
    let payer = env.rpc.payer.insecure_clone();
    let authority = env.authority.insecure_clone();
    ZolanaProgramTest::create_and_send_transaction(
        &mut env.rpc,
        &[ix],
        &payer.pubkey(),
        &[&payer, &authority],
    )
    .map(|_| ())
}

fn fund_fee_balance(env: &mut Pool, lamports: u64) {
    let tree = env.tree;
    let mut account = tree_account(env);
    {
        let layout: &mut Layout =
            wincode::deserialize_mut(&mut account.data).expect("load tree layout");
        layout.fee_balance += lamports;
    }
    account.lamports += lamports;
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write fee balance fixture");
}

fn pool_nullifier_pda_rent(env: &Pool) -> u64 {
    nullifier_pda_rent(&env.rpc).expect("nullifier PDA rent")
}

fn tree_rent(env: &Pool) -> u64 {
    env.rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size())
        .expect("tree rent")
}

fn tree_account(env: &Pool) -> Account {
    env.rpc.svm.get_account(&env.tree).expect("tree account")
}

fn funded_system_account(env: &mut Pool) -> Pubkey {
    let account = Pubkey::new_unique();
    env.rpc
        .airdrop(&account, 1_000_000)
        .expect("fund system account");
    account
}

fn write_nullifier_pda_account(
    env: &mut Pool,
    nullifier: &[u8; 32],
    nullifier_pda: NullifierPda,
    lamports: u64,
) -> Pubkey {
    let (address, _) = pda::nullifier_pda(&env.tree, nullifier);
    env.rpc
        .svm
        .set_account(
            address,
            Account {
                lamports,
                data: borsh::to_vec(&nullifier_pda).expect("serialize nullifier PDA"),
                owner: pda::shielded_pool_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write nullifier PDA fixture");
    address
}

fn queue_nullifier_pda(env: &mut Pool, nullifier: &[u8; 32], queue_index: u64) -> Pubkey {
    let rent = pool_nullifier_pda_rent(env);
    write_nullifier_pda_account(
        env,
        nullifier,
        NullifierPda {
            queue_index,
            tree_id: 0,
        },
        rent,
    )
}

fn queue_nullifier_pdas(
    env: &mut Pool,
    nullifiers: &[[u8; 32]],
    first_queue_index: u64,
) -> Vec<Pubkey> {
    nullifiers
        .iter()
        .zip(first_queue_index..)
        .map(|(nullifier, queue_index)| queue_nullifier_pda(env, nullifier, queue_index))
        .collect()
}

fn set_reclaimable_watermark(env: &mut Pool) {
    let tree = env.tree;
    let mut account = tree_account(env);
    {
        let mut on_chain =
            TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
        set_synthetic_nullifier_sequence(&mut on_chain, 2 * NULLIFIER_ZKP_BATCHES as u64);
    }
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write tree watermark fixture");
    assert_eq!(
        tree_close_before_index(&env.rpc, &tree).expect("close_before_index"),
        SYNTHETIC_CLOSE_BEFORE_INDEX,
        "watermark fixture"
    );
}

fn set_synthetic_watermark_and_zero_root(env: &mut Pool, root_index: usize) {
    let tree = env.tree;
    let mut account = tree_account(env);
    {
        let mut on_chain =
            TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
        set_synthetic_nullifier_sequence(&mut on_chain, 2 * NULLIFIER_ZKP_BATCHES as u64);
        *on_chain
            .nullifier_tree()
            .root_history
            .roots
            .get_mut(root_index)
            .expect("fixture root index") = [0u8; 32];
    }
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write reclaimable root fixture");
}

fn set_tree_lamports(env: &mut Pool, lamports: u64) {
    let tree = env.tree;
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
    let error = send_close(env, ix).expect_err("close must be rejected");
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
fn assert_close_nullifier_pdas(
    env: &Pool,
    trace: &TransactionTrace,
    tree_before: &Account,
    nullifiers: &[[u8; 32]],
) {
    let tree = env.tree;
    let payer = env.rpc.payer.pubkey();
    let rent = pool_nullifier_pda_rent(env);
    let nullifier_pdas = nullifier_pda_addresses(&tree, nullifiers);
    let (fees, fee_balance_before) = tree_fees_from(tree_before, &tree).expect("tree fees");
    let paid = (fees.close_reimbursement * nullifiers.len() as u64).min(fee_balance_before);

    let mut expected_tree = tree_before.clone();
    expected_tree.lamports += rent * nullifiers.len() as u64;
    expected_tree.lamports -= paid;
    {
        let layout: &mut Layout =
            wincode::deserialize_mut(&mut expected_tree.data).expect("expected tree layout");
        layout.fee_balance -= paid;
    }
    assert_eq!(
        tree_account(env),
        expected_tree,
        "close moves the nullifier PDA rent into the tree, pays the close reimbursement from the fee balance, and touches no other tree byte"
    );
    assert_nullifier_pdas_absent(&env.rpc, &tree, nullifiers).expect("nullifier PDAs closed");

    let mut changed: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .collect();
    changed.sort();
    let mut expected_changed: Vec<Pubkey> = nullifier_pdas
        .iter()
        .copied()
        .chain([tree, payer])
        .collect();
    expected_changed.sort();
    assert_eq!(
        changed, expected_changed,
        "close changes only the tree, the closed nullifier PDAs and the fee payer"
    );
    for transition in &trace.accounts {
        if nullifier_pdas.contains(&transition.address) {
            let before = transition
                .before
                .as_ref()
                .expect("nullifier PDA before close");
            let after_balance_and_size = transition
                .after
                .as_ref()
                .map(|after| (after.lamports, after.data_len))
                .unwrap_or((0, 0));
            assert_eq!(
                ((before.lamports, before.data_len), after_balance_and_size),
                ((rent, NULLIFIER_PDA_SIZE), (0, 0)),
                "nullifier PDA {} holds exactly its rent before close and is empty after",
                transition.address
            );
        } else if transition.address == payer {
            let before = transition.before.as_ref().expect("payer before close");
            let after = transition.after.as_ref().expect("payer after close");
            assert_eq!(
                before.lamports + paid,
                after.lamports + CLOSE_TRANSACTION_FEE,
                "fee payer pays exactly the two-signature transaction fee and receives the close reimbursement"
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
    queue_nullifier_pda(&mut env, &pending, 1);

    let ix = transact_instruction(&env, data);
    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierAlreadyQueued),
    );
    assert_nullifier_pda(&env.rpc, &env.tree, &pending, 1).expect("pending nullifier PDA");
    assert_nullifier_pdas_absent(
        &env.rpc,
        &env.tree,
        nullifiers.get(1..).expect("second nullifier"),
    )
    .expect("no nullifier PDA for the rejected input");
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
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &[first])
        .expect("duplicate nullifier PDA rolled back");
}

#[test]
fn transact_rejects_swapped_nullifier_pdas() {
    let mut env = Pool::initialized();
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);
    let mut ix = transact_instruction(&env, data);
    ix.accounts.swap(
        TRANSACT_NULLIFIER_PDA_OFFSET,
        TRANSACT_NULLIFIER_PDA_OFFSET + 1,
    );

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierPda),
    );
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
        .expect("no nullifier PDA created");
}

#[test]
fn transact_rejects_a_foreign_account_in_a_nullifier_pda_slot() {
    let mut env = Pool::initialized();
    let impostor = funded_system_account(&mut env);
    let mut ix = transact_instruction(&env, transfer_ix_data(2, 3));
    ix.accounts
        .get_mut(TRANSACT_NULLIFIER_PDA_OFFSET)
        .expect("first nullifier PDA meta")
        .pubkey = impostor;

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierPda),
    );
}

#[test]
fn transact_rejects_a_read_only_nullifier_pda() {
    let mut env = Pool::initialized();
    let mut ix = transact_instruction(&env, transfer_ix_data(2, 3));
    ix.accounts
        .get_mut(TRANSACT_NULLIFIER_PDA_OFFSET + 1)
        .expect("second nullifier PDA meta")
        .is_writable = false;

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn transact_rejects_missing_nullifier_pda_accounts() {
    let mut env = Pool::initialized();
    let mut ix = transact_instruction(&env, transfer_ix_data(2, 3));
    ix.accounts.truncate(TRANSACT_NULLIFIER_PDA_OFFSET);

    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn transact_rejects_a_tree_short_of_nullifier_pda_rent() {
    let mut env = Pool::initialized();
    let tree_rent = tree_rent(&env);
    let nullifier_pda_rent = pool_nullifier_pda_rent(&env);
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);
    // The forester fee lands in the tree before the PDA rent check but is
    // reserved for the fee balance, so it never funds working capital: the
    // largest still-rejecting balance sits one lamport below the two PDA rents.

    for tree_lamports in [tree_rent, tree_rent + 2 * nullifier_pda_rent - 1] {
        set_tree_lamports(&mut env, tree_lamports);
        let ix = transact_instruction(&env, data.clone());
        expect_transact_rejection(
            &mut env,
            ix,
            Rejection::pool(ShieldedPoolError::InsufficientNullifierPdaRent),
        );
        assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
            .expect("no nullifier PDA survives an underfunded tree");
    }
}

#[test]
fn transact_rejects_when_working_capital_would_borrow_from_the_fee_pool() {
    let mut env = Pool::initialized();
    let tree_rent = tree_rent(&env);
    let nullifier_pda_rent = pool_nullifier_pda_rent(&env);
    let fee_balance = 1_000_000;
    fund_fee_balance(&mut env, fee_balance);
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);

    set_tree_lamports(
        &mut env,
        tree_rent + fee_balance + 2 * nullifier_pda_rent - 1,
    );
    let ix = transact_instruction(&env, data);
    expect_transact_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InsufficientNullifierPdaRent),
    );
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
        .expect("no nullifier PDA is funded from the fee balance");
}

#[test]
fn close_rejects_a_non_forester_authority() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);
    let intruder = env.funded_signer(1_000_000_000);
    let tree_before = tree_account(&env);

    let ix = CloseNullifierPdas {
        authority: intruder.pubkey(),
        tree: env.tree,
        reimbursement_recipient: intruder.pubkey(),
        nullifiers: vec![nullifier],
    }
    .instruction();
    let error = ZolanaProgramTest::create_and_send_transaction(
        &mut env.rpc,
        &[ix],
        &intruder.pubkey(),
        &[&intruder],
    )
    .expect_err("a signer that is not the forester authority must be rejected");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("rejected close trace")
        .assert_rolled_back_except(&[intruder.pubkey()]);
    assert_eq!(
        tree_account(&env),
        tree_before,
        "rejected close must leave the tree untouched"
    );
    assert_nullifier_pda(&env.rpc, &env.tree, &nullifier, 1).expect("nullifier PDA kept");
}

#[test]
fn close_rejects_an_unsigned_authority() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);

    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts.first_mut().expect("authority meta").is_signer = false;
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an unsigned forester authority must be rejected");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(error);
    assert_nullifier_pda(&env.rpc, &env.tree, &nullifier, 1).expect("nullifier PDA kept");
}

#[test]
fn close_rejects_nullifier_pda_before_batch_is_reclaimable() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree).expect("close_before_index"),
        0,
        "fresh tree has no reclaimable batches"
    );

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierPdaNotClosable),
    );
    assert_nullifier_pda(&env.rpc, &env.tree, &nullifier, 1).expect("nullifier PDA kept");
}

#[test]
fn close_honours_the_watermark_boundary() {
    let mut env = Pool::initialized();
    let at_watermark = fe(1);
    let below_watermark = fe(2);
    queue_nullifier_pda(&mut env, &at_watermark, SYNTHETIC_CLOSE_BEFORE_INDEX);
    queue_nullifier_pda(&mut env, &below_watermark, SYNTHETIC_CLOSE_BEFORE_INDEX - 1);
    set_reclaimable_watermark(&mut env);

    let ix = close_instruction(&env, vec![at_watermark]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierPdaNotClosable),
    );
    assert_nullifier_pda(
        &env.rpc,
        &env.tree,
        &at_watermark,
        SYNTHETIC_CLOSE_BEFORE_INDEX,
    )
    .expect("nullifier PDA at the watermark kept");

    let tree_before = tree_account(&env);
    let ix = close_instruction(&env, vec![below_watermark]);
    send_close(&mut env, ix).expect("close a nullifier PDA below the watermark");
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("close trace")
        .clone();
    assert_close_nullifier_pdas(&env, &trace, &tree_before, &[below_watermark]);
    assert_eq!(
        tree_close_before_index(&env.rpc, &env.tree).expect("close_before_index"),
        SYNTHETIC_CLOSE_BEFORE_INDEX,
        "close does not move the watermark"
    );
}

#[test]
fn close_returns_nullifier_pda_rent_to_the_tree() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2), fe(3)];
    queue_nullifier_pdas(&mut env, &nullifiers, 1);
    set_reclaimable_watermark(&mut env);
    let tree_before = tree_account(&env);

    let ix = close_instruction(&env, nullifiers.to_vec());
    send_close(&mut env, ix).expect("close nullifier PDAs below the reclaim watermark");
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("close trace")
        .clone();
    assert_close_nullifier_pdas(&env, &trace, &tree_before, &nullifiers);
}

fn close_funded(env: &mut Pool, fee_balance: u64, nullifiers: &[[u8; 32]]) -> u64 {
    queue_nullifier_pdas(env, nullifiers, 1);
    set_reclaimable_watermark(env);
    fund_fee_balance(env, fee_balance);
    let tree_before = tree_account(env);
    let payer_before = env
        .rpc
        .svm
        .get_account(&env.rpc.payer.pubkey())
        .expect("payer")
        .lamports;

    let ix = close_instruction(env, nullifiers.to_vec());
    send_close(env, ix).expect("close nullifier PDAs below the reclaim watermark");
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("close trace")
        .clone();
    assert_close_nullifier_pdas(env, &trace, &tree_before, nullifiers);
    let payer_after = env
        .rpc
        .svm
        .get_account(&env.rpc.payer.pubkey())
        .expect("payer")
        .lamports;
    payer_after + CLOSE_TRANSACTION_FEE - payer_before
}

#[test]
fn close_pays_the_closer_from_the_fee_balance() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2), fe(3)];
    let (fees, _) = tree_fees(&env.rpc, &env.tree).expect("tree fees");
    let owed = fees.close_reimbursement * nullifiers.len() as u64;
    assert_eq!(owed, 510);

    let paid = close_funded(&mut env, 1_000_000, &nullifiers);

    assert_eq!(
        paid, owed,
        "the closer receives the full close reimbursement"
    );
    assert_eq!(
        tree_fees(&env.rpc, &env.tree).expect("tree fees"),
        (fees, 1_000_000 - owed)
    );
}

#[test]
fn close_pays_only_what_the_fee_balance_holds() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2), fe(3)];

    let paid = close_funded(&mut env, 100, &nullifiers);

    assert_eq!(paid, 100, "a short fee balance pays out in full and stops");
    assert_eq!(
        tree_fees(&env.rpc, &env.tree).expect("tree fees").1,
        0,
        "the fee balance is drained, never negative"
    );
}

#[test]
fn close_with_a_zero_schedule_pays_nothing_and_still_closes() {
    let mut env = Pool::initialized();
    let authority = env.authority.insecure_clone();
    env.rpc
        .set_tree_fees(&authority, &env.tree, TreeFeeSchedule::default())
        .expect("zero the fee schedule");
    let nullifiers = [fe(1), fe(2)];

    let paid = close_funded(&mut env, 1_000, &nullifiers);

    assert_eq!(paid, 0);
    assert_eq!(
        tree_fees(&env.rpc, &env.tree).expect("tree fees"),
        (TreeFeeSchedule::default(), 1_000)
    );
}

#[test]
fn close_rejects_a_program_owned_reimbursement_recipient() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2)];
    queue_nullifier_pdas(&mut env, &nullifiers, 1);
    set_reclaimable_watermark(&mut env);
    fund_fee_balance(&mut env, 1_000_000);
    let open_nullifier_pda = pda::nullifier_pda(&env.tree, &fe(2)).0;

    for recipient in [env.tree, open_nullifier_pda, pda::protocol_config()] {
        let ix = close_instruction_for(&env, recipient, vec![fe(1)]);
        expect_close_rejection(
            &mut env,
            ix,
            Rejection::pool(ShieldedPoolError::InvalidReimbursementRecipient),
        );
        assert_nullifier_pdas(&env.rpc, &env.tree, &nullifiers)
            .expect("no nullifier PDA closed by a rejected close");
    }
}

#[test]
fn close_pays_a_recipient_other_than_the_payer() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2)];
    queue_nullifier_pdas(&mut env, &nullifiers, 1);
    set_reclaimable_watermark(&mut env);
    fund_fee_balance(&mut env, 1_000_000);
    let recipient = funded_system_account(&mut env);
    let recipient_before = env.rpc.svm.get_account(&recipient).expect("recipient");
    let (fees, fee_balance_before) = tree_fees(&env.rpc, &env.tree).expect("tree fees");

    let ix = close_instruction_for(&env, recipient, nullifiers.to_vec());
    send_close(&mut env, ix).expect("close with a separate recipient");

    let owed = fees.close_reimbursement * nullifiers.len() as u64;
    let mut expected_recipient = recipient_before;
    expected_recipient.lamports += owed;
    assert_eq!(
        env.rpc.svm.get_account(&recipient).expect("recipient"),
        expected_recipient,
        "the recipient receives exactly the close reimbursement"
    );
    assert_eq!(
        tree_fees(&env.rpc, &env.tree).expect("tree fees"),
        (fees, fee_balance_before - owed)
    );
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers).expect("nullifier PDAs closed");
}

#[test]
fn closed_nullifier_pda_does_not_make_an_obsolete_root_spendable_again() {
    let mut env = Pool::initialized();
    let data = transfer_ix_data(2, 3);
    let nullifiers = nullifiers_of(&data);
    queue_nullifier_pdas(&mut env, &nullifiers, 1);
    set_synthetic_watermark_and_zero_root(&mut env, 0);

    let ix = close_instruction(&env, nullifiers.clone());
    send_close(&mut env, ix).expect("close nullifier PDAs below the reclaim watermark");
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
        .expect("closable nullifier PDAs closed");

    let replay = transact_instruction(&env, data);
    expect_transact_rejection(
        &mut env,
        replay,
        Rejection::pool(ShieldedPoolError::StaleNullifierRoot),
    );
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
        .expect("failed replay rolls nullifier PDA creation back");
}

#[test]
fn close_is_atomic_across_nullifier_pdas() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2), fe(3)];
    queue_nullifier_pdas(&mut env, &nullifiers, SYNTHETIC_CLOSE_BEFORE_INDEX - 2);
    set_reclaimable_watermark(&mut env);

    let ix = close_instruction(&env, nullifiers.to_vec());
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierPdaNotClosable),
    );
    for (nullifier, queue_index) in nullifiers.iter().zip(SYNTHETIC_CLOSE_BEFORE_INDEX - 2..) {
        assert_nullifier_pda(&env.rpc, &env.tree, nullifier, queue_index)
            .expect("no nullifier PDA closed by a rejected batch");
    }
}

#[test]
fn close_accepts_nullifier_pdas_in_any_order() {
    let mut env = Pool::initialized();
    let nullifiers = [fe(1), fe(2)];
    queue_nullifier_pdas(&mut env, &nullifiers, 1);
    set_reclaimable_watermark(&mut env);
    let mut ix = close_instruction(&env, nullifiers.to_vec());
    ix.accounts
        .swap(CLOSE_NULLIFIER_PDA_OFFSET, CLOSE_NULLIFIER_PDA_OFFSET + 1);

    send_close(&mut env, ix).expect("close in swapped account order");
    assert_nullifier_pdas_absent(&env.rpc, &env.tree, &nullifiers)
        .expect("both nullifier PDAs closed");
}

#[test]
fn close_rejects_a_nullifier_pda_of_another_tree() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    let rent = pool_nullifier_pda_rent(&env);
    write_nullifier_pda_account(
        &mut env,
        &nullifier,
        NullifierPda {
            queue_index: 1,
            tree_id: 1,
        },
        rent,
    );
    set_reclaimable_watermark(&mut env);

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::NullifierPdaTreeMismatch),
    );
}

#[test]
fn close_rejects_a_non_nullifier_pda_account() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    set_reclaimable_watermark(&mut env);
    let system_owned = funded_system_account(&mut env);
    let tree = env.tree;

    for impostor in [system_owned, tree] {
        let mut ix = close_instruction(&env, vec![nullifier]);
        ix.accounts
            .get_mut(CLOSE_NULLIFIER_PDA_OFFSET)
            .expect("nullifier PDA meta")
            .pubkey = impostor;
        expect_close_rejection(
            &mut env,
            ix,
            Rejection::pool(ShieldedPoolError::InvalidNullifierPda),
        );
    }
}

/// A program-owned ten-byte account the program never wrote decodes as an
/// all-zero record. Queue indices start at 1, so a zero `queue_index` is
/// rejected even though `tree_id` matches and the watermark is above it.
#[test]
fn close_rejects_a_zero_queue_index_record() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    let rent = pool_nullifier_pda_rent(&env);
    write_nullifier_pda_account(
        &mut env,
        &nullifier,
        NullifierPda {
            queue_index: 0,
            tree_id: 0,
        },
        rent,
    );
    set_reclaimable_watermark(&mut env);

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierPda),
    );
}

#[test]
fn close_rejects_a_read_only_nullifier_pda_meta() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts
        .get_mut(CLOSE_NULLIFIER_PDA_OFFSET)
        .expect("nullifier PDA meta")
        .is_writable = false;

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn close_rejects_the_same_nullifier_pda_twice_in_one_instruction() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);

    let ix = close_instruction(&env, vec![nullifier, nullifier]);
    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierPda),
    );
    assert_nullifier_pda(&env.rpc, &env.tree, &nullifier, 1).expect("nullifier PDA kept");
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
fn close_rejects_a_trailing_non_nullifier_account() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);
    let extra = funded_system_account(&mut env);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts.push(AccountMeta::new(extra, false));

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidNullifierPda),
    );
    assert_nullifier_pda(&env.rpc, &env.tree, &nullifier, 1).expect("nullifier PDA kept");
}

#[test]
fn close_rejects_a_paused_tree() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);
    let authority = env.authority.insecure_clone();
    env.rpc
        .pause_tree(&authority, &env.tree, true)
        .expect("pause tree");

    let ix = close_instruction(&env, vec![nullifier]);
    expect_close_rejection(&mut env, ix, Rejection::pool(ShieldedPoolError::TreePaused));
    assert_nullifier_pda(&env.rpc, &env.tree, &nullifier, 1).expect("nullifier PDA kept");
}

#[test]
fn close_rejects_a_read_only_tree_meta() {
    let mut env = Pool::initialized();
    let nullifier = fe(1);
    queue_nullifier_pda(&mut env, &nullifier, 1);
    set_reclaimable_watermark(&mut env);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts
        .get_mut(CLOSE_TREE_OFFSET)
        .expect("tree meta")
        .is_writable = false;

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
    queue_nullifier_pda(&mut env, &nullifier, 1);
    let impostor = funded_system_account(&mut env);
    let mut ix = close_instruction(&env, vec![nullifier]);
    ix.accounts
        .get_mut(CLOSE_TREE_OFFSET)
        .expect("tree meta")
        .pubkey = impostor;

    expect_close_rejection(
        &mut env,
        ix,
        Rejection::pool(ShieldedPoolError::InvalidTreeAccounts),
    );
}
