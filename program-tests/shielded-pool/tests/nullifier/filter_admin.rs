use solana_account::Account;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::builders::{direct_spend::enable_pending_nullifiers, historical_nullifiers::*},
    pda,
    state::TREE_ALLOCATION_STEP,
    PROGRAM_ID_PUBKEY,
};
use zolana_program_test::{ProgramTestError, Rejection};
use zolana_test_utils::backend::LiteSvmPoolBackend as Pool;
use zolana_tree::{
    nullifier_filter::{NullifierFilter, DEFAULT_BIT_BYTES},
    pending_nullifiers::PendingNullifiers,
    NullifierFilterMode, TreeAccount,
};

fn preallocate(pool: &mut Pool, address: Pubkey, size: usize) {
    pool.rpc
        .svm
        .set_account(
            address,
            Account {
                lamports: solana_rent::Rent::default().minimum_balance(size),
                data: vec![0; size],
                owner: PROGRAM_ID_PUBKEY,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
}

fn compact_pool() -> Pool {
    let mut pool = Pool::initialized();
    let mut data = pool.rpc.account_data(&pool.tree).unwrap();
    let batch = TreeAccount::from_bytes(&mut data, pool.tree.to_bytes())
        .unwrap()
        .nullifier_tree()
        .batch_size;
    let pending = pda::pending_nullifiers(&pool.tree).0;
    preallocate(
        &mut pool,
        pending,
        PendingNullifiers::account_size(batch).unwrap(),
    );
    let instruction =
        enable_pending_nullifiers(pool.rpc.payer.pubkey(), pool.authority.pubkey(), pool.tree);
    send(&mut pool, &instruction).unwrap();
    pool
}

fn enable(pool: &Pool) -> Instruction {
    enable_nullifier_filter(pool.rpc.payer.pubkey(), pool.authority.pubkey(), pool.tree)
}

fn send(pool: &mut Pool, instruction: &Instruction) -> Result<(), ProgramTestError> {
    pool.rpc
        .create_and_send_default_payer_transaction(&[instruction.clone()], &[&pool.authority])
        .map(|_| ())
}

fn mode(pool: &Pool) -> NullifierFilterMode {
    TreeAccount::read_nullifier_filter_mode(&pool.rpc.account_data(&pool.tree).unwrap()).unwrap()
}

fn ready_filter(pool: &mut Pool) -> Pubkey {
    let address = pda::nullifier_filter(&pool.tree).0;
    // Equivalent to completed allocation: initialization still executes through SPP.
    preallocate(
        pool,
        address,
        NullifierFilter::account_size(DEFAULT_BIT_BYTES).unwrap(),
    );
    address
}

fn assert_rollback(pool: &Pool) {
    pool.rpc
        .last_transaction_trace()
        .unwrap()
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

#[test]
fn allocation_keeps_fast_admission_off_until_complete() {
    let mut pool = compact_pool();
    let instruction = enable(&pool);
    send(&mut pool, &instruction).unwrap();
    assert_eq!(mode(&pool), NullifierFilterMode::Off);
    let filter = pool
        .rpc
        .account_data(&pda::nullifier_filter(&pool.tree).0)
        .unwrap();
    assert_eq!(filter.len(), TREE_ALLOCATION_STEP);
    assert!(filter.iter().all(|byte| *byte == 0));
}

#[test]
fn enabling_checks_authority_pda_and_compact_guard() {
    let mut pool = Pool::initialized();
    let instruction = enable(&pool);
    let error = send(&mut pool, &instruction).unwrap_err();
    Rejection::pool(ShieldedPoolError::InvalidNullifierFilter).assert_litesvm(error);
    assert_rollback(&pool);

    let outsider = pool.funded_signer(1_000_000);
    let unauthorized =
        enable_nullifier_filter(pool.rpc.payer.pubkey(), outsider.pubkey(), pool.tree);
    let error = pool
        .rpc
        .create_and_send_default_payer_transaction(&[unauthorized], &[&outsider])
        .unwrap_err();
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert_rollback(&pool);

    let mut wrong = instruction;
    wrong.accounts[4].pubkey = Pubkey::new_unique();
    let error = send(&mut pool, &wrong).unwrap_err();
    Rejection::pool(ShieldedPoolError::InvalidPda).assert_litesvm(error);
    assert_rollback(&pool);
}

#[test]
fn initialization_and_retirement_are_single_use() {
    let mut pool = compact_pool();
    let filter = ready_filter(&mut pool);
    let instruction = enable(&pool);
    send(&mut pool, &instruction).unwrap();
    assert_eq!(mode(&pool), NullifierFilterMode::Active);
    let mut bytes = pool.rpc.account_data(&filter).unwrap();
    assert_eq!(
        NullifierFilter::from_bytes(&mut bytes, &pool.tree.to_bytes())
            .unwrap()
            .next_sequence(),
        1
    );
    let error = send(&mut pool, &instruction).unwrap_err();
    Rejection::pool(ShieldedPoolError::InvalidNullifierFilter).assert_litesvm(error);
    assert_rollback(&pool);

    let outsider = pool.funded_signer(1_000_000);
    let unauthorized = retire_nullifier_filter(outsider.pubkey(), pool.tree);
    let error = pool
        .rpc
        .create_and_send_default_payer_transaction(&[unauthorized], &[&outsider])
        .unwrap_err();
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert_rollback(&pool);
    let retire = retire_nullifier_filter(pool.authority.pubkey(), pool.tree);
    send(&mut pool, &retire).unwrap();
    assert_eq!(mode(&pool), NullifierFilterMode::Retired);
    assert_eq!(pool.rpc.account_data(&filter).unwrap(), bytes);
    assert!(send(&mut pool, &retire).is_err());
    assert_rollback(&pool);
    let error = send(&mut pool, &instruction).unwrap_err();
    Rejection::pool(ShieldedPoolError::InvalidNullifierFilter).assert_litesvm(error);
    assert_rollback(&pool);
}

#[test]
fn historical_or_queued_spends_block_empty_filter_initialization() {
    let mut pool = compact_pool();
    let filter = ready_filter(&mut pool);
    let original = pool.rpc.svm.get_account(&pool.tree).unwrap();
    for (inserted, queued) in [(1, 2), (2, 2), (2, 3)] {
        let mut account = original.clone();
        let mut tree = TreeAccount::from_bytes(&mut account.data, pool.tree.to_bytes()).unwrap();
        tree.nullifier_tree().next_index = inserted;
        tree.nullifier_tree().queue_next_index = queued;
        drop(tree);
        pool.rpc.svm.set_account(pool.tree, account).unwrap();
        let instruction = enable(&pool);
        let error = send(&mut pool, &instruction).unwrap_err();
        Rejection::pool(ShieldedPoolError::InvalidNullifierFilter).assert_litesvm(error);
        assert_eq!(mode(&pool), NullifierFilterMode::Off);
        assert!(pool
            .rpc
            .account_data(&filter)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0));
        assert_rollback(&pool);
    }
}

#[test]
fn failed_transaction_rolls_back_filter_initialization_and_mode() {
    let mut pool = compact_pool();
    let filter = ready_filter(&mut pool);
    let instruction = enable(&pool);
    let invalid = Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: Vec::new(),
        data: vec![255],
    };
    assert!(pool
        .rpc
        .create_and_send_default_payer_transaction(
            &[instruction.clone(), invalid],
            &[&pool.authority]
        )
        .is_err());
    assert_eq!(mode(&pool), NullifierFilterMode::Off);
    assert!(pool
        .rpc
        .account_data(&filter)
        .unwrap()
        .iter()
        .all(|byte| *byte == 0));
    assert_rollback(&pool);
    send(&mut pool, &instruction).unwrap();
    assert_eq!(mode(&pool), NullifierFilterMode::Active);
}
