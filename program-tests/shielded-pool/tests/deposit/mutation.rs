//! Mollusk mutation coverage for the deposit fixture.
//!
//! Every mutation class is pinned against its exact rejection error via
//! `expect_err_exact`, so a regression that changes *how* a malformed
//! instruction fails is caught, not just that it fails. Two classes are not
//! rejections and are pinned as such:
//!
//! - A non-executable program account is a no-op mutation: mollusk executes
//!   the program from its own loader cache keyed by program id, so the passed
//!   program account's `executable` flag is never consulted on this path.
//! - Byte flips inside the instruction payload (amount/owner/blinding are
//!   self-consistent deposit fields) and inside tree bytes the deposit path
//!   never reads can stay valid deposits, so those keep a determinism-only
//!   proptest at the bottom of the file.
use proptest::prelude::*;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{error::ShieldedPoolError, instruction::tag};
use zolana_test_utils::mollusk::expect_err_exact;

use shielded_pool_tests::support::mollusk::{deposit_fixture, setup_mollusk};

fn pool_error(error: ShieldedPoolError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn account_error(error: AccountError) -> ProgramError {
    ProgramError::Custom(u32::from(error))
}

/// Every truncation of the instruction data is rejected. Empty data fails the
/// tag read with the builtin `InvalidInstructionData`; a present tag with a
/// truncated payload fails deserialization with the program's own
/// `ShieldedPoolError::InvalidInstructionData`.
#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, valid, accounts) = deposit_fixture();
    for end in 0..valid.data.len() {
        let mut truncated = valid.clone();
        truncated.data.truncate(end);
        let expected = if end == 0 {
            ProgramError::InvalidInstructionData
        } else {
            pool_error(ShieldedPoolError::InvalidInstructionData)
        };
        expect_err_exact(&mollusk, &truncated, &accounts, expected);
    }
}

/// Removing any single account (from both the metas and the account set) is
/// rejected with a stable per-index error: the tree or depositor slot loses
/// its expected shape so the signer gate fires, a missing program account
/// surfaces as invalid settlement accounts, and a missing system program or
/// SOL vault is the account-iterator shortfall.
#[test]
fn removing_any_account_is_rejected_exactly() {
    let (mollusk, valid, accounts) = deposit_fixture();
    for index in 0..valid.accounts.len() {
        let mut instruction = valid.clone();
        let mut shrunk = accounts.clone();
        instruction.accounts.remove(index);
        shrunk.remove(index);
        let expected = match index {
            0 | 1 => account_error(AccountError::InvalidSigner),
            2 => pool_error(ShieldedPoolError::InvalidSettlementAccounts),
            _ => account_error(AccountError::NotEnoughAccountKeys),
        };
        expect_err_exact(&mollusk, &instruction, &shrunk, expected);
    }
}

#[test]
fn unsigned_depositor_is_rejected_exactly() {
    let (mollusk, mut instruction, accounts) = deposit_fixture();
    instruction
        .accounts
        .get_mut(1)
        .expect("depositor meta")
        .is_signer = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        account_error(AccountError::InvalidSigner),
    );
}

#[test]
fn readonly_tree_is_rejected_exactly() {
    let (mollusk, mut instruction, accounts) = deposit_fixture();
    instruction
        .accounts
        .first_mut()
        .expect("tree meta")
        .is_writable = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        account_error(AccountError::AccountNotMutable),
    );
}

/// With the tree and depositor metas swapped, the depositor slot holds the
/// (unsigned) tree key, so the signer check is the branch that fires.
#[test]
fn swapped_tree_and_depositor_are_rejected_exactly() {
    let (mollusk, mut instruction, accounts) = deposit_fixture();
    instruction.accounts.swap(0, 1);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        account_error(AccountError::InvalidSigner),
    );
}

#[test]
fn wrong_tree_owner_is_rejected_exactly() {
    let (mollusk, instruction, mut accounts) = deposit_fixture();
    accounts.first_mut().expect("tree account").1.owner =
        solana_pubkey::Pubkey::new_from_array([7u8; 32]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        pool_error(ShieldedPoolError::InvalidTreeAccounts),
    );
}

/// Truncating the tree account's data is rejected with the same tree-account
/// error regardless of the surviving length.
#[test]
fn truncated_tree_data_is_rejected_exactly() {
    let (mollusk, instruction, accounts) = deposit_fixture();
    for end in [8usize, 64, 1024] {
        let mut truncated = accounts.clone();
        truncated
            .first_mut()
            .expect("tree account")
            .1
            .data
            .truncate(end);
        expect_err_exact(
            &mollusk,
            &instruction,
            &truncated,
            pool_error(ShieldedPoolError::InvalidTreeAccounts),
        );
    }
}

/// An unfunded depositor cannot settle the transfer; the system program's
/// negative-lamports error propagates.
#[test]
fn unfunded_depositor_is_rejected_exactly() {
    let (mollusk, instruction, mut accounts) = deposit_fixture();
    accounts.get_mut(1).expect("depositor account").1.lamports = 0;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SystemError::ResultWithNegativeLamports as u32),
    );
}

/// Positive case: mollusk executes the program from its own loader cache
/// keyed by program id, so the `executable` flag on the passed program
/// account is never consulted and this mutation is a no-op.
#[test]
fn non_executable_program_account_still_executes() {
    let (mollusk, instruction, mut accounts) = deposit_fixture();
    accounts.last_mut().expect("program account").1.executable = false;
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert!(
        result.raw_result.is_ok(),
        "flag-only program account mutation must stay valid: {:?}",
        result.raw_result
    );
}

/// Positive case: the `EMIT_EVENT` tag is a no-validation no-op self-CPI
/// target by design (see `zolana_interface::instruction::tag::EMIT_EVENT`), so arbitrary
/// payload bytes with no accounts succeed. This is why the garbage-instruction
/// proptest below excludes that tag.
#[test]
fn emit_event_tag_accepts_arbitrary_account_free_bytes() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = Instruction {
        program_id,
        accounts: Vec::new(),
        data: vec![tag::EMIT_EVENT, 1, 2, 3],
    };
    let result = mollusk.process_instruction(&instruction, &[]);
    assert!(
        result.raw_result.is_ok(),
        "EMIT_EVENT is a no-op by design: {:?}",
        result.raw_result
    );
}

// Failure persistence is left at the proptest default, so any failing case is
// recorded under `proptest-regressions/` (commit those files) and replays on
// every later run.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    })]

    /// Arbitrary account-free instruction bytes are rejected, and the
    /// rejection is deterministic. The one exception is the `EMIT_EVENT` tag,
    /// which is a no-validation no-op self-CPI target by design (see
    /// `zolana_interface::instruction::tag::EMIT_EVENT`), so cases carrying it are excluded
    /// here and pinned as a positive case below.
    #[test]
    fn arbitrary_account_free_instruction_bytes_are_rejected_deterministically(
        cases in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 1..32)
    ) {
        let (mollusk, program_id) = setup_mollusk();
        for data in cases {
            // Only this byte string is skipped (not the whole generated case):
            // EMIT_EVENT is a no-validation no-op by design, pinned positively below.
            if data.first() == Some(&tag::EMIT_EVENT) {
                continue;
            }
            let instruction = Instruction {
                program_id,
                accounts: Vec::new(),
                data,
            };
            let first = mollusk.process_instruction(&instruction, &[]);
            let second = mollusk.process_instruction(&instruction, &[]);
            prop_assert!(first.raw_result.is_err());
            prop_assert_eq!(first.raw_result, second.raw_result);
            prop_assert_eq!(first.resulting_accounts, second.resulting_accounts);
        }
    }

    /// Determinism-only harness for the two mutation classes that can stay
    /// valid: payload byte flips (amount/owner/blinding remain a
    /// self-consistent deposit) and tree byte flips outside the bytes the
    /// deposit path reads. Rejection is not asserted here -- the exact-error
    /// tests above cover the classes that must fail.
    #[test]
    fn instruction_payload_and_tree_byte_flips_are_deterministic(
        flips in prop::collection::vec((any::<bool>(), any::<usize>(), any::<u8>()), 1..24)
    ) {
        let (mollusk, valid, original_accounts) = deposit_fixture();
        for (target_tree, index, value) in flips {
            let mut instruction = valid.clone();
            let mut accounts = original_accounts.clone();
            if target_tree {
                let tree_data = &mut accounts.first_mut().expect("tree account").1.data;
                let data_index = index % tree_data.len();
                *tree_data.get_mut(data_index).expect("tree data byte") ^= value | 1;
            } else {
                let data_index = index % instruction.data.len();
                *instruction
                    .data
                    .get_mut(data_index)
                    .expect("instruction byte") ^= value | 1;
            }

            let first = mollusk.process_instruction(&instruction, &accounts);
            let second = mollusk.process_instruction(&instruction, &accounts);
            prop_assert_eq!(&first.raw_result, &second.raw_result);
            prop_assert_eq!(&first.program_result, &second.program_result);
            prop_assert_eq!(&first.return_data, &second.return_data);
            prop_assert_eq!(&first.resulting_accounts, &second.resulting_accounts);
            prop_assert_eq!(first.compute_units_consumed, second.compute_units_consumed);
        }
    }
}
