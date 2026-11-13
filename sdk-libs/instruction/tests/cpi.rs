#![cfg(feature = "cpi")]

use pinocchio::{error::ProgramError, AccountView, Address};
use spr_account_checks::account_info::test_account_info::get_account_view;
use spr_instruction::cpi::{SppTransactAccounts, TransactAccountsError};
use spr_interface::{instruction::tag::TRANSACT, SHIELDED_POOL_PROGRAM_ID};

const PDA: [u8; 32] = [4u8; 32];

fn view(address: [u8; 32], owner: [u8; 32]) -> AccountView {
    get_account_view(address, owner, false, true, false, Vec::new())
}

/// payer, output tree, the shielded pool, the system program and a PDA, with
/// the shielded pool replaceable.
fn transact_accounts(spp_program: [u8; 32]) -> Vec<AccountView> {
    vec![
        view([1u8; 32], [0u8; 32]),
        view([21u8; 32], SHIELDED_POOL_PROGRAM_ID),
        view(spp_program, [2u8; 32]),
        view([0u8; 32], [3u8; 32]),
        view(PDA, [0u8; 32]),
    ]
}

#[test]
fn new_accepts_the_transact_layout_and_rejects_anything_else() {
    let pda = Address::new_from_array(PDA);
    let absent = Address::new_from_array([8u8; 32]);
    let signer_pdas = [&pda];
    let absent_second = [&pda, &absent];
    let accounts = transact_accounts(SHIELDED_POOL_PROGRAM_ID);
    let short = accounts.get(..2).unwrap();
    let wrong_spp_program = transact_accounts([9u8; 32]);

    let results = [
        SppTransactAccounts::new(short, &signer_pdas).map(|_| ()),
        SppTransactAccounts::new(&wrong_spp_program, &signer_pdas).map(|_| ()),
        SppTransactAccounts::new(&accounts, &absent_second).map(|_| ()),
        SppTransactAccounts::new(&accounts, &signer_pdas).map(|_| ()),
    ];

    assert_eq!(
        results,
        [
            Err(TransactAccountsError::NotEnoughAccounts),
            Err(TransactAccountsError::InvalidSppProgram),
            Err(TransactAccountsError::MissingPdaSigner { index: 1 }),
            Ok(()),
        ]
    );
}

#[test]
fn signs_for_only_the_signer_pdas() {
    let pda = Address::new_from_array(PDA);
    let signer_pdas = [&pda];
    let accounts = transact_accounts(SHIELDED_POOL_PROGRAM_ID);
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();

    assert_eq!(
        (
            spp.signs_for(&pda),
            spp.signs_for(&Address::new_from_array([1u8; 32]))
        ),
        (true, false)
    );
}

#[test]
fn instruction_accounts_keep_flags_and_sign_only_for_the_pdas() {
    let pda = Address::new_from_array(PDA);
    let signer_pdas = [&pda];
    let mut accounts = transact_accounts(SHIELDED_POOL_PROGRAM_ID);
    // A read-only owner that signed the outer transaction keeps its signature.
    accounts.push(get_account_view(
        [30u8; 32],
        [0u8; 32],
        true,
        false,
        false,
        Vec::new(),
    ));
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();

    let metas = spp.instruction_accounts::<8>().unwrap();
    let flags: Vec<([u8; 32], bool, bool)> = metas
        .iter()
        .take(accounts.len())
        .map(|meta| (meta.address.to_bytes(), meta.is_writable, meta.is_signer))
        .collect();

    assert_eq!(
        flags,
        vec![
            ([1u8; 32], true, false),
            ([21u8; 32], true, false),
            (SHIELDED_POOL_PROGRAM_ID, true, false),
            ([0u8; 32], true, false),
            (PDA, true, true),
            ([30u8; 32], false, true),
        ]
    );
}

#[test]
fn instruction_accounts_reject_more_accounts_than_the_bound() {
    let pda = Address::new_from_array(PDA);
    let signer_pdas = [&pda];
    let accounts = transact_accounts(SHIELDED_POOL_PROGRAM_ID);
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();

    assert_eq!(
        (
            spp.instruction_accounts::<4>().map(|_| ()),
            spp.instruction_accounts::<5>().map(|_| ()),
        ),
        (Err(TransactAccountsError::TooManyAccounts), Ok(()))
    );
}

#[test]
fn invoke_tagged_rejects_data_without_the_transact_tag() {
    let pda = Address::new_from_array(PDA);
    let signer_pdas = [&pda];
    let accounts = transact_accounts(SHIELDED_POOL_PROGRAM_ID);
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();
    let expected = Err(ProgramError::from(
        TransactAccountsError::MissingTransactTag,
    ));

    assert_eq!(
        (
            spp.invoke_tagged::<8>(&[], &[]),
            spp.invoke_tagged::<8>(&[TRANSACT.wrapping_add(1), 0], &[]),
        ),
        (expected.clone(), expected)
    );
}

#[test]
fn error_codes_are_stable() {
    use TransactAccountsError::*;

    for (error, code) in [
        (NotEnoughAccounts, 14100),
        (InvalidSppProgram, 14101),
        (MissingPdaSigner { index: 3 }, 14102),
        (TooManyAccounts, 14103),
        (MissingTransactTag, 14104),
    ] {
        assert_eq!(ProgramError::from(error), ProgramError::Custom(code));
    }
}
