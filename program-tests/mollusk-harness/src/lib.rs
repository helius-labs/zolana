//! Harness-generic Mollusk support shared by SBF instruction-level tests.
//!
//! Mollusk 0.3 pins solana 2.2 wire types while the workspace is on the 3.x
//! line, so fixtures built from workspace types must be converted before
//! Mollusk can execute them. The `mollusk_*` conversion helpers below exist
//! only to bridge that version split. Delete them (and the renamed 2.2
//! dependencies in this crate's manifest) as soon as a mollusk-svm release
//! ships against solana-instruction 3.x; nothing else in this crate depends
//! on the split.

use std::sync::Once;

use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_instruction::{
    AccountMeta as MolluskAccountMeta, Instruction as MolluskInstruction,
};
use mollusk_solana_program_error::ProgramError;
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

static SETUP: Once = Once::new();

pub fn mollusk_pubkey(key: &Pubkey) -> MolluskPubkey {
    MolluskPubkey::new_from_array(key.to_bytes())
}

pub fn mollusk_account(account: &Account) -> MolluskAccount {
    MolluskAccount {
        lamports: account.lamports,
        data: account.data.clone(),
        owner: MolluskPubkey::new_from_array(account.owner.to_bytes()),
        executable: account.executable,
        rent_epoch: account.rent_epoch,
    }
}

pub fn mollusk_instruction(ix: &Instruction) -> MolluskInstruction {
    MolluskInstruction {
        program_id: mollusk_pubkey(&ix.program_id),
        accounts: ix
            .accounts
            .iter()
            .map(|meta| MolluskAccountMeta {
                pubkey: mollusk_pubkey(&meta.pubkey),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

/// Build a Mollusk instance with one SBF program loaded from `sbf_out_dir`.
///
/// The first call in a process fixes `SBF_OUT_DIR` (and quiets `RUST_LOG`
/// unless the caller set it); all workspace test crates resolve to the same
/// `target/deploy`, so later callers agree with whichever ran first.
pub fn mollusk_with_program(
    sbf_out_dir: &str,
    program_id: [u8; 32],
    program_name: &str,
) -> (Mollusk, MolluskPubkey) {
    let dir = sbf_out_dir.to_string();
    SETUP.call_once(move || {
        std::env::set_var("SBF_OUT_DIR", dir);
        if std::env::var_os("RUST_LOG").is_none() {
            std::env::set_var("RUST_LOG", "error");
        }
    });
    let program_id = MolluskPubkey::new_from_array(program_id);
    let mut mollusk = Mollusk::default();
    mollusk.add_program(&program_id, program_name, &LOADER_V3);
    (mollusk, program_id)
}

/// Stand-in for an account a fixture references but its source environment
/// never created (for example a PDA the instruction initializes). It models
/// the canonical on-chain reality of a nonexistent account: zero lamports,
/// empty data, system-owned. Fixtures must only rely on this fallback for
/// accounts the instruction creates or never reads; a typo'd pubkey in a
/// fixture would otherwise be masked as one of these.
pub fn empty_placeholder_account() -> MolluskAccount {
    MolluskAccount {
        lamports: 0,
        data: Vec::new(),
        owner: MolluskPubkey::new_from_array([0u8; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

/// Snapshot the accounts an instruction references into Mollusk form.
///
/// `target_program` is the key the instruction data refers to the program
/// under test by; it is materialized as a loader-v3 program account. The
/// default (all-zero) pubkey is materialized as the system program. Every
/// other key is resolved through `fetch`; keys `fetch` cannot resolve fall
/// back to [`empty_placeholder_account`].
pub fn snapshot_instruction_accounts(
    ix: &Instruction,
    target_program: (&Pubkey, MolluskPubkey),
    fetch: impl Fn(&Pubkey) -> Option<Account>,
) -> Vec<(MolluskPubkey, MolluskAccount)> {
    ix.accounts
        .iter()
        .map(|meta| {
            if &meta.pubkey == target_program.0 {
                (
                    target_program.1,
                    mollusk_svm::program::create_program_account_loader_v3(&target_program.1),
                )
            } else if meta.pubkey == Pubkey::default() {
                mollusk_svm::program::keyed_account_for_system_program()
            } else {
                let account = fetch(&meta.pubkey)
                    .map_or_else(empty_placeholder_account, |account| {
                        mollusk_account(&account)
                    });
                (mollusk_pubkey(&meta.pubkey), account)
            }
        })
        .collect()
}

/// Assert the instruction fails with exactly `expected` and rolls back all
/// account state byte-for-byte.
#[track_caller]
pub fn expect_err_atomic(
    mollusk: &Mollusk,
    instruction: &MolluskInstruction,
    accounts: &[(MolluskPubkey, MolluskAccount)],
    expected: ProgramError,
) {
    check_exact(mollusk, instruction, accounts, expected, "");
}

#[track_caller]
fn check_exact(
    mollusk: &Mollusk,
    instruction: &MolluskInstruction,
    accounts: &[(MolluskPubkey, MolluskAccount)],
    expected: ProgramError,
    context: &str,
) {
    let result =
        mollusk.process_and_validate_instruction(instruction, accounts, &[Check::err(expected)]);
    assert_eq!(
        result.resulting_accounts, accounts,
        "rejected instruction changed account state{context}"
    );
}

/// Assert the instruction is rejected, that the rejection is deterministic
/// (same error and account result on re-execution), and that it left all
/// account state untouched.
#[track_caller]
pub fn assert_rejected_atomically(
    mollusk: &Mollusk,
    instruction: &MolluskInstruction,
    accounts: &[(MolluskPubkey, MolluskAccount)],
) {
    check_rejected(mollusk, instruction, accounts, "");
}

#[track_caller]
fn check_rejected(
    mollusk: &Mollusk,
    instruction: &MolluskInstruction,
    accounts: &[(MolluskPubkey, MolluskAccount)],
    context: &str,
) {
    let first = mollusk.process_instruction(instruction, accounts);
    let second = mollusk.process_instruction(instruction, accounts);
    assert!(
        first.raw_result.is_err(),
        "mutated fixture unexpectedly succeeded{context}"
    );
    assert_eq!(
        first.raw_result, second.raw_result,
        "non-deterministic error{context}"
    );
    assert_eq!(
        first.resulting_accounts, second.resulting_accounts,
        "non-deterministic account result{context}"
    );
    assert_eq!(
        first.resulting_accounts, accounts,
        "rejected instruction changed account state{context}"
    );
}

/// One privilege downgrade applied to a green fixture by
/// [`sweep_account_matrix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountMutation {
    /// Clear `is_signer` on the meta at `index`.
    Unsign { index: usize },
    /// Clear `is_writable` on the meta at `index`.
    Readonly { index: usize },
    /// Remove the meta at `index`, shifting every later account forward.
    Remove { index: usize },
}

/// The caller's verdict for one [`AccountMutation`] cell.
pub enum Expected {
    /// The program must fail with exactly this error.
    Err(ProgramError),
    /// The program must fail deterministically and atomically; the exact
    /// error depends on how the account shape shifts, so it is not pinned.
    Rejected,
    /// The downgrade removes a privilege the program never uses, so the
    /// instruction must still succeed. Pinning this keeps an over-declared
    /// account meta from silently becoming load-bearing.
    Success,
    /// The cell does not apply to this fixture.
    Skip,
}

/// Exercise the full account-privilege matrix of a green fixture: for every
/// account meta, unsign it (if a signer), make it readonly (if writable), and
/// remove it. The caller maps each cell to an [`Expected`] verdict, so "every
/// privilege downgrade is rejected" becomes a constructed property instead of
/// a hand-enumerated sample.
#[track_caller]
pub fn sweep_account_matrix(
    mollusk: &Mollusk,
    instruction: &MolluskInstruction,
    accounts: &[(MolluskPubkey, MolluskAccount)],
    expected: impl Fn(AccountMutation) -> Expected,
) {
    let mut mutations = Vec::new();
    for (index, meta) in instruction.accounts.iter().enumerate() {
        if meta.is_signer {
            mutations.push(AccountMutation::Unsign { index });
        }
        if meta.is_writable {
            mutations.push(AccountMutation::Readonly { index });
        }
        mutations.push(AccountMutation::Remove { index });
    }

    for mutation in mutations {
        let mut mutated = instruction.clone();
        match mutation {
            AccountMutation::Unsign { index } => {
                mutated
                    .accounts
                    .get_mut(index)
                    .expect("sweep index in bounds")
                    .is_signer = false;
            }
            AccountMutation::Readonly { index } => {
                mutated
                    .accounts
                    .get_mut(index)
                    .expect("sweep index in bounds")
                    .is_writable = false;
            }
            AccountMutation::Remove { index } => {
                mutated.accounts.remove(index);
            }
        }
        let context = format!(" (mutation {mutation:?})");
        match expected(mutation) {
            Expected::Skip => {}
            Expected::Err(error) => check_exact(mollusk, &mutated, accounts, error, &context),
            Expected::Rejected => check_rejected(mollusk, &mutated, accounts, &context),
            Expected::Success => {
                let result = mollusk.process_instruction(&mutated, accounts);
                assert!(
                    result.raw_result.is_ok(),
                    "downgrade of an unused privilege failed{context}: {:?}",
                    result.raw_result
                );
            }
        }
    }
}
