use mollusk_svm::result::ProgramResult;
use solana_account::Account;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_interface::{
    instruction::builders::{
        direct_spend::use_pending_nullifiers, historical_nullifiers::use_nullifier_filter,
    },
    pda,
};
use zolana_ring_policy::ListId;
use zolana_tree::{NullifierFilterMode, TreeAccount};

use crate::common::{
    authority, entries_tree, initialized_entries_tree_account, initialized_policy_config_account,
    setup_mollusk, EntryFixture,
};

fn mutation(
    compact: bool,
    mode: NullifierFilterMode,
    update: bool,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let entry = EntryFixture::new(ListId::Allow, authority());
    let fixture = if update {
        entry.update(initialized_policy_config_account(), 0)
    } else {
        entry.create(initialized_policy_config_account())
    };
    let mut tree_account = initialized_entries_tree_account();
    let mut tree = TreeAccount::from_bytes(&mut tree_account.data, entries_tree().to_bytes())
        .expect("entries tree");
    if compact {
        tree.enable_compact_nullifiers().unwrap();
    }
    if mode != NullifierFilterMode::Off {
        tree.enable_nullifier_filter().unwrap();
    }
    if mode == NullifierFilterMode::Retired {
        tree.retire_nullifier_filter().unwrap();
    }
    drop(tree);
    let mut accounts = fixture.accounts().to_vec();
    for (key, account) in &mut accounts {
        if *key == entries_tree() {
            *account = tree_account.clone();
        }
    }
    let nullifier = [9; 32];
    let mut instruction = fixture.instruction().clone();
    instruction.accounts[7].pubkey = pda::nullifier_pda(&entries_tree(), &nullifier).0;
    accounts.push((instruction.accounts[7].pubkey, Account::default()));
    if compact {
        use_pending_nullifiers(&mut instruction, &entries_tree(), &[nullifier]).unwrap();
        accounts.push((
            pda::pending_nullifiers(&entries_tree()).0,
            Account::default(),
        ));
    }
    if mode == NullifierFilterMode::Active {
        use_nullifier_filter(&mut instruction, &entries_tree()).unwrap();
        accounts.push((pda::nullifier_filter(&entries_tree()).0, Account::default()));
    }
    (instruction, accounts)
}

#[test]
fn mutation_layouts_reach_the_spp_cpi() {
    let (mollusk, _) = setup_mollusk();
    for (compact, mode) in [
        (false, NullifierFilterMode::Off),
        (true, NullifierFilterMode::Off),
        (true, NullifierFilterMode::Active),
        (true, NullifierFilterMode::Retired),
    ] {
        for update in [false, true] {
            let (instruction, accounts) = mutation(compact, mode, update);
            assert_eq!(
                mollusk
                    .process_instruction(&instruction, &accounts)
                    .program_result,
                ProgramResult::UnknownError(InstructionError::UnsupportedProgramId),
                "compact={compact}, mode={mode:?}, update={update}"
            );
        }
    }
}

#[test]
fn active_mutations_require_a_writable_filter_before_the_namespace() {
    let (mollusk, _) = setup_mollusk();
    for missing in [false, true] {
        let (mut instruction, accounts) = mutation(true, NullifierFilterMode::Active, false);
        if missing {
            instruction.accounts.remove(8);
        } else {
            instruction.accounts[8].is_writable = false;
        }
        zolana_test_utils::mollusk::expect_err_exact(
            &mollusk,
            &instruction,
            &accounts,
            ProgramError::from(AccountError::AccountNotMutable),
        );
    }
}

#[test]
fn inactive_mutations_reject_an_extra_filter() {
    let (mollusk, _) = setup_mollusk();
    for mode in [NullifierFilterMode::Off, NullifierFilterMode::Retired] {
        let (mut instruction, mut accounts) = mutation(true, mode, false);
        let filter = pda::nullifier_filter(&entries_tree()).0;
        instruction
            .accounts
            .insert(8, AccountMeta::new(filter, false));
        accounts.push((filter, Account::default()));
        zolana_test_utils::mollusk::expect_err_exact(
            &mollusk,
            &instruction,
            &accounts,
            ProgramError::InvalidArgument,
        );
    }
}
