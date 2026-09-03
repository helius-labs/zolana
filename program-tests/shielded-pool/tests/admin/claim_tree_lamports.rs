use mollusk_svm::result::Check;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{ClaimTreeLamports, UpdateProtocolConfigData},
    pda,
    state::tree_working_capital_lamports,
    NULLIFIER_PDA_SIZE,
};
use zolana_program_test::Rejection;
use zolana_test_utils::mollusk::{
    expect_err_exact, mollusk_pubkey, sweep_account_matrix, AccountMutation, Expected,
};
use zolana_tree::{TreeAccountLayout, PAUSED, UTXO_TREE_HEIGHT};

type Layout = TreeAccountLayout<
    UTXO_TREE_HEIGHT,
    { zolana_tree::nullifier_tree::constants::NULLIFIER_TREE_ZKP_BATCHES },
>;

use shielded_pool_tests::support::{
    fixtures::Pool,
    mollusk::{
        account_named, claim_tree_lamports_fixture, system_account,
        CLAIM_TREE_LAMPORTS_FIXTURE_SURPLUS,
    },
};

const RECIPIENT_FUNDING: u64 = 1_000_000_000;

/// The lamports a tree must keep: its rent, its fee balance, and the working
/// capital for `NUM_BATCHES + 1` batches of nullifier PDAs, at `rent`.
fn reserve(rent: &Rent, tree: &Account) -> u64 {
    let mut data = tree.data.clone();
    let layout: &mut Layout = wincode::deserialize_mut(&mut data).expect("tree layout");
    let working_capital = tree_working_capital_lamports(
        layout.nullifier.batch_size,
        rent.minimum_balance(NULLIFIER_PDA_SIZE),
    )
    .expect("working capital fits in u64");
    rent.minimum_balance(tree.data.len()) + layout.fee_balance + working_capital
}

fn claim_ix(
    pool: &Pool,
    authority: &Keypair,
    recipient: Pubkey,
) -> solana_instruction::Instruction {
    ClaimTreeLamports {
        authority: authority.pubkey(),
        tree: pool.tree,
        recipient,
    }
    .instruction()
}

fn lamports(pool: &Pool, key: &Pubkey) -> u64 {
    pool.rpc.svm.get_balance(key).expect("account exists")
}

#[test]
fn claim_tree_lamports_pays_exactly_the_surplus() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    let tree = pool.tree;
    let recipient = pool.funded_signer(RECIPIENT_FUNDING).pubkey();
    let surplus = 123_456_789;
    pool.rpc.airdrop(&tree, surplus).expect("fund tree surplus");
    let tree_before = pool.rpc.svm.get_account(&tree).expect("tree");
    let rent: Rent = pool.rpc.svm.get_sysvar();
    assert_eq!(tree_before.lamports, reserve(&rent, &tree_before) + surplus);

    pool.rpc
        .claim_tree_lamports(&authority, &tree, &recipient)
        .expect("claim the surplus");

    let tree_after = pool.rpc.svm.get_account(&tree).expect("tree");
    assert_eq!(tree_after.lamports, reserve(&rent, &tree_after));
    assert_eq!(
        tree_after.data, tree_before.data,
        "claim must not touch tree data"
    );
    assert_eq!(lamports(&pool, &recipient), RECIPIENT_FUNDING + surplus);
}

#[test]
fn claim_tree_lamports_rejects_a_tree_without_surplus() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    let recipient = pool.funded_signer(RECIPIENT_FUNDING).pubkey();
    let tree_before = pool.rpc.svm.get_account(&pool.tree).expect("tree");
    let rent: Rent = pool.rpc.svm.get_sysvar();
    assert_eq!(tree_before.lamports, reserve(&rent, &tree_before));

    let error = pool
        .rpc
        .claim_tree_lamports(&authority, &pool.tree, &recipient)
        .expect_err("a tree at its reserve has nothing to claim");
    Rejection::pool(ShieldedPoolError::NoClaimableTreeLamports).assert_litesvm(error);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
    assert_eq!(lamports(&pool, &recipient), RECIPIENT_FUNDING);
}

#[test]
fn claim_tree_lamports_keeps_the_fee_balance_and_works_on_a_paused_tree() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    let tree = pool.tree;
    let recipient = pool.funded_signer(RECIPIENT_FUNDING).pubkey();
    let fee_balance = 777;
    let surplus = 5_000;
    let mut account = pool.rpc.svm.get_account(&tree).expect("tree");
    {
        let layout: &mut Layout = wincode::deserialize_mut(&mut account.data).expect("tree layout");
        layout.fee_balance = fee_balance;
    }
    account.lamports += fee_balance + surplus;
    pool.rpc
        .svm
        .set_account(tree, account)
        .expect("write fee balance");
    pool.rpc
        .pause_tree(&authority, &tree, true)
        .expect("pause tree");
    let mut tree_before = pool.rpc.svm.get_account(&tree).expect("tree");
    {
        let layout: &mut Layout =
            wincode::deserialize_mut(&mut tree_before.data).expect("tree layout");
        assert_eq!((layout.state, layout.fee_balance), (PAUSED, fee_balance));
    }

    pool.rpc
        .claim_tree_lamports(&authority, &tree, &recipient)
        .expect("claim on a paused tree");

    let tree_after = pool.rpc.svm.get_account(&tree).expect("tree");
    let rent: Rent = pool.rpc.svm.get_sysvar();
    assert_eq!(tree_after.lamports, reserve(&rent, &tree_after));
    assert_eq!(
        tree_after.data, tree_before.data,
        "the pause state and the fee balance survive a claim"
    );
    assert_eq!(lamports(&pool, &recipient), RECIPIENT_FUNDING + surplus);
}

#[test]
fn claim_tree_lamports_is_gated_by_the_fee_authority_alone() {
    let mut pool = Pool::initialized();
    let protocol_authority = pool.authority.insecure_clone();
    let fee_authority = pool.funded_signer(RECIPIENT_FUNDING);
    let recipient = pool.funded_signer(RECIPIENT_FUNDING).pubkey();
    let surplus = 1_000_000;
    pool.rpc
        .airdrop(&pool.tree, surplus)
        .expect("fund tree surplus");
    pool.rpc
        .send_protocol_config_update(
            &protocol_authority,
            UpdateProtocolConfigData::FeeAuthority(fee_authority.pubkey()),
        )
        .expect("rotate fee authority");
    let tree_lamports_before = lamports(&pool, &pool.tree);

    let error = pool
        .rpc
        .create_and_send_default_payer_transaction(
            &[claim_ix(&pool, &protocol_authority, recipient)],
            &[&protocol_authority],
        )
        .expect_err("the protocol authority is no longer the fee authority");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
    assert_eq!(lamports(&pool, &pool.tree), tree_lamports_before);

    pool.rpc
        .claim_tree_lamports(&fee_authority, &pool.tree, &recipient)
        .expect("the fee authority claims");
    assert_eq!(lamports(&pool, &pool.tree), tree_lamports_before - surplus);
    assert_eq!(lamports(&pool, &recipient), RECIPIENT_FUNDING + surplus);
}

#[test]
fn claim_tree_lamports_rejects_a_program_owned_recipient() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    pool.rpc
        .airdrop(&pool.tree, 1_000_000)
        .expect("fund tree surplus");
    let tree_lamports_before = lamports(&pool, &pool.tree);

    let error = pool
        .rpc
        .claim_tree_lamports(&authority, &pool.tree, &pda::protocol_config())
        .expect_err("a program-owned recipient is rejected");
    Rejection::pool(ShieldedPoolError::InvalidReimbursementRecipient).assert_litesvm(error);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
    assert_eq!(lamports(&pool, &pool.tree), tree_lamports_before);
}

#[test]
fn claim_tree_lamports_recovers_a_rent_reduction() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    let tree = pool.tree;
    let recipient = pool.funded_signer(RECIPIENT_FUNDING).pubkey();
    let old_rent: Rent = pool.rpc.svm.get_sysvar();
    let tree_before = pool.rpc.svm.get_account(&tree).expect("tree");
    assert_eq!(tree_before.lamports, reserve(&old_rent, &tree_before));

    let new_rent = Rent {
        lamports_per_byte: old_rent.lamports_per_byte / 2,
        ..old_rent
    };
    pool.rpc.svm.set_sysvar(&new_rent);
    let released = reserve(&old_rent, &tree_before) - reserve(&new_rent, &tree_before);
    assert!(released > 0);

    pool.rpc
        .claim_tree_lamports(&authority, &tree, &recipient)
        .expect("claim the rent reduction");

    let tree_after = pool.rpc.svm.get_account(&tree).expect("tree");
    assert_eq!(tree_after.lamports, reserve(&new_rent, &tree_after));
    assert_eq!(tree_after.data, tree_before.data);
    assert_eq!(lamports(&pool, &recipient), RECIPIENT_FUNDING + released);
}

#[test]
fn mollusk_claim_tree_lamports_moves_only_lamports() {
    let (mollusk, instruction, accounts) = claim_tree_lamports_fixture();
    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let authority = instruction.accounts.first().expect("authority meta").pubkey;
    let config = instruction.accounts.get(1).expect("config meta").pubkey;
    let tree = instruction.accounts.get(2).expect("tree meta").pubkey;
    let recipient = instruction.accounts.get(3).expect("recipient meta").pubkey;

    for key in [authority, config] {
        assert_eq!(
            account_named(&result.resulting_accounts, &key),
            account_named(&accounts, &key),
            "claim_tree_lamports must not change account {key}"
        );
    }

    let tree_before = account_named(&accounts, &tree);
    let tree_after = account_named(&result.resulting_accounts, &tree);
    let mut expected_tree = tree_before.clone();
    expected_tree.lamports -= CLAIM_TREE_LAMPORTS_FIXTURE_SURPLUS;
    assert_eq!(
        tree_after, &expected_tree,
        "claim must move only the surplus"
    );
    assert_eq!(tree_after.lamports, reserve(&Rent::default(), tree_after));

    let mut expected_recipient = account_named(&accounts, &recipient).clone();
    expected_recipient.lamports += CLAIM_TREE_LAMPORTS_FIXTURE_SURPLUS;
    assert_eq!(
        account_named(&result.resulting_accounts, &recipient),
        &expected_recipient
    );
}

#[test]
fn mollusk_claim_tree_lamports_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = claim_tree_lamports_fixture();
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 0 } => {
            Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
        }
        AccountMutation::Readonly { index: 2 | 3 } => Expected::Err(ProgramError::Custom(
            u32::from(AccountError::AccountNotMutable),
        )),
        _ => Expected::Rejected,
    });
}

#[test]
fn claim_tree_lamports_rejects_wrong_authority_exactly() {
    let (mollusk, valid, accounts) = claim_tree_lamports_fixture();
    let wrong_authority = Pubkey::new_unique();
    let mut wrong_authority_ix = valid;
    wrong_authority_ix
        .accounts
        .first_mut()
        .expect("authority meta")
        .pubkey = mollusk_pubkey(&wrong_authority);
    let mut wrong_authority_accounts = accounts;
    *wrong_authority_accounts
        .first_mut()
        .expect("authority account") = (
        mollusk_pubkey(&wrong_authority),
        system_account(1_000_000_000),
    );

    expect_err_exact(
        &mollusk,
        &wrong_authority_ix,
        &wrong_authority_accounts,
        ProgramError::Custom(ShieldedPoolError::UnauthorizedCaller as u32),
    );
}

#[test]
fn claim_tree_lamports_rejects_a_non_empty_payload() {
    let (mollusk, valid, accounts) = claim_tree_lamports_fixture();
    assert_eq!(valid.data.len(), 1);

    let mut long_payload = valid;
    long_payload.data.push(0);
    expect_err_exact(
        &mollusk,
        &long_payload,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );
}

#[test]
fn claim_tree_lamports_rejects_a_non_tree_account() {
    let (mollusk, valid, accounts) = claim_tree_lamports_fixture();
    let impostor = Pubkey::new_unique();
    let mut impostor_ix = valid;
    impostor_ix.accounts.get_mut(2).expect("tree meta").pubkey = mollusk_pubkey(&impostor);
    let mut impostor_accounts = accounts;
    *impostor_accounts.get_mut(2).expect("tree account") =
        (mollusk_pubkey(&impostor), system_account(1_000_000));

    expect_err_exact(
        &mollusk,
        &impostor_ix,
        &impostor_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidTreeAccounts as u32),
    );
}
