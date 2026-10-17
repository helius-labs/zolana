use custom_ring_interface::{CustomRingError, RingAccount};
use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_slice, Seed, Signer, MAX_CPI_ACCOUNTS},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use wincode::{config::DefaultConfig, SchemaRead};
use zolana_interface::{RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};

use crate::{instructions::loader::load_mut, state::Init};

/// Instruction data of `T`, trailing bytes refused.
#[inline(never)]
pub(crate) fn parse<'a, T: SchemaRead<'a, DefaultConfig, Dst = T>>(
    data: &'a [u8],
) -> Result<T, CustomRingError> {
    wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)
}

pub(crate) fn check_system_program(account: &AccountView) -> Result<(), CustomRingError> {
    if !pinocchio_system::check_id(account.address()) {
        return Err(CustomRingError::InvalidSystemProgram);
    }
    Ok(())
}

/// The canonical bump of `seeds`, `mismatch` for another address.
pub(crate) fn verify_pda<const N: usize>(
    program_id: &Address,
    address: &Address,
    seeds: &[&[u8]; N],
    mismatch: CustomRingError,
) -> Result<u8, CustomRingError> {
    match Address::derive_program_address(seeds, program_id) {
        Some((derived, bump)) if address_eq(address, &derived) => Ok(bump),
        _ => Err(mismatch),
    }
}

/// Creates `T`'s account at its canonical address, refusing an occupied one.
pub(crate) fn create_pda<T: RingAccount, const N: usize>(
    program_id: &Address,
    payer: &AccountView,
    account: &mut AccountView,
    seeds: &[&[u8]; N],
) -> Result<u8, ProgramError> {
    let bump = verify_pda(program_id, account.address(), seeds, T::ADDRESS)?;
    if account.data_len() != 0 {
        return Err(T::EXISTS.into());
    }
    create_account(program_id, payer, account, seeds, bump, T::SIZE)?;
    Ok(bump)
}

#[inline(never)]
fn create_account(
    program_id: &Address,
    payer: &AccountView,
    account: &mut AccountView,
    seeds: &[&[u8]],
    bump: u8,
    space: usize,
) -> ProgramResult {
    let bump = [bump];
    let signer: Vec<Seed> = seeds
        .iter()
        .map(|seed| Seed::from(*seed))
        .chain([Seed::from(&bump)])
        .collect();
    pinocchio_system::create_account_with_minimum_balance_signed(
        account,
        space,
        program_id,
        payer,
        None,
        &[Signer::from(signer.as_slice())],
    )
}

/// Replaces `T` in place when its stored bump derives the account from `seeds`,
/// otherwise creates it at the canonical address.
pub(crate) fn upsert<T: RingAccount, const N: usize>(
    program_id: &Address,
    payer: &AccountView,
    account: &mut AccountView,
    seeds: &[&[u8]; N],
    value: impl FnOnce(u8) -> T,
) -> ProgramResult {
    if account.data_len() == 0 {
        let bump = create_pda::<T, N>(program_id, payer, account, seeds)?;
        return Init(&value(bump)).init(account);
    }
    let address = *account.address();
    let mut existing = load_mut::<T>(program_id, account)?;
    let bump = existing.bump();
    if !address_eq(
        &address,
        &Address::derive_address(seeds, Some(bump), program_id),
    ) {
        return Err(T::ADDRESS.into());
    }
    *existing = value(bump);
    Ok(())
}

/// Refunds the rent and closes, `mismatch` when the recipient is the account.
pub(crate) fn close_into(
    account: &mut AccountView,
    rent_recipient: &mut AccountView,
    mismatch: CustomRingError,
) -> ProgramResult {
    if account.address() == rent_recipient.address() {
        return Err(mismatch.into());
    }
    let refund = rent_recipient
        .lamports()
        .checked_add(account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    account.set_lamports(0);
    account.close()
}

/// Forwards `data`, tag byte included, over `accounts` in SPP's order with the
/// ring authority PDA raised to a signer. Routes that debit a caller account
/// must call `check_funding_signer` before forwarding.
#[inline(never)]
pub(crate) fn cpi_spp<A: AsRef<AccountView>>(
    program_id: &Address,
    accounts: &[A],
    data: &[u8],
) -> ProgramResult {
    let (ring_auth, ring_auth_bump) =
        Address::derive_program_address(&[RING_AUTH_PDA_SEED], program_id)
            .ok_or(CustomRingError::MissingRingAuth)?;
    if !accounts
        .iter()
        .any(|account| account.as_ref().address() == &ring_auth)
    {
        return Err(CustomRingError::MissingRingAuth.into());
    }
    if accounts.len() > MAX_CPI_ACCOUNTS {
        return Err(CustomRingError::TooManyAccounts.into());
    }
    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|account| {
            let account = account.as_ref();
            let is_signer = account.is_signer() || address_eq(account.address(), &ring_auth);
            InstructionAccount::new(account.address(), account.is_writable(), is_signer)
        })
        .collect();
    let ring_auth_bump = [ring_auth_bump];
    let ring_auth_seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(&ring_auth_bump)];
    let instruction = InstructionView {
        program_id: &Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: &metas,
        data,
    };
    invoke_signed_with_slice(
        &instruction,
        accounts,
        &[Signer::from(ring_auth_seeds.as_slice())],
    )
}

/// Require the SPP funding account to have signed before the ring raises its PDA.
/// Otherwise a caller could name `ring_auth` as payer and gain its CPI signature.
pub(crate) fn check_funding_signer(accounts: &[AccountView], index: usize) -> ProgramResult {
    let funder = accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !funder.is_signer() {
        return Err(CustomRingError::MissingFundingSigner.into());
    }
    Ok(())
}
