#![cfg(feature = "cpi")]

use pinocchio::{error::ProgramError, AccountView, Address};
use spr_account_checks::account_info::test_account_info::get_account_view;
use spr_instruction::cpi::{PdaSigner, SppTransactAccounts, TransactAccountsError};
use spr_interface::SHIELDED_POOL_PROGRAM_ID;

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
fn error_codes_are_stable() {
    use TransactAccountsError::*;

    for (error, code) in [
        (NotEnoughAccounts, 14100),
        (InvalidSppProgram, 14101),
        (MissingPdaSigner { index: 3 }, 14102),
    ] {
        assert_eq!(ProgramError::from(error), ProgramError::Custom(code));
    }
}

#[test]
fn pda_signer_derives_the_canonical_bump_and_appends_it_to_the_seeds() {
    let program_id = Address::new_from_array([5u8; 32]);
    let creator = [6u8; 32];
    let seeds: [&[u8]; 2] = [b"authority", &creator];
    let (address, bump) = Address::find_program_address(&seeds, &program_id);

    let signer = PdaSigner::find(seeds, &program_id);
    let signer_seeds: Vec<Vec<u8>> = signer
        .signer_seeds()
        .iter()
        .map(|seed| seed.to_vec())
        .collect();

    assert_eq!(
        (*signer.address(), signer.bump(), signer_seeds),
        (
            address,
            bump,
            vec![b"authority".to_vec(), creator.to_vec(), vec![bump]]
        )
    );
}

#[test]
fn pda_signer_invokes_transact_only_when_its_pda_is_in_the_accounts() {
    let program_id = Address::new_from_array([5u8; 32]);
    let signer = PdaSigner::find([b"authority".as_slice()], &program_id);
    let mut accounts = transact_accounts(SHIELDED_POOL_PROGRAM_ID);
    let without_pda = signer.invoke_transact::<8>(&accounts, &[]);
    accounts.push(view(signer.address().to_bytes(), [0u8; 32]));

    assert_eq!(
        (without_pda, signer.invoke_transact::<8>(&accounts, &[])),
        (
            Err(TransactAccountsError::MissingPdaSigner { index: 0 }.into()),
            Ok(())
        )
    );
}
