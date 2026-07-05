//! Zone-auth CPI signer and SPP cross-program invocations.
//!
//! The Squads zone drives the shielded-pool program (SPP) by CPI, signing with
//! the `[b"zone_auth"]` PDA. `spp_transact` and `spp_merge_transact` perform a
//! real `invoke_signed` into SPP's `zone_transact` / `merge_zone`
//! (`spp_transact`'s withdrawal leg is rejected by callers before reaching
//! this, per `SquadsZoneError::ZoneSettlementNotImplemented`).

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_squads_interface::{error::SquadsZoneError, ZONE_AUTH_PDA_SEED};

/// Build the `[b"zone_auth", bump]` seeds for the zone-auth CPI signer. The
/// caller owns the returned array and wraps it in a `Signer` inline, e.g.:
///
/// ```ignore
/// let bump = [zone_auth_bump];
/// let seeds = zone_auth_seeds(&bump);
/// let signer = Signer::from(&seeds);
/// // ... invoke_signed(&instruction, accounts, &[signer]) ...
/// ```
///
/// Keeping the seed array on the caller's stack mirrors the SPP `settle_sol`
/// signer pattern and avoids returning a borrow of a local.
#[inline(always)]
pub fn zone_auth_seeds<'a>(bump: &'a [u8; 1]) -> [Seed<'a>; 2] {
    [Seed::from(ZONE_AUTH_PDA_SEED), Seed::from(bump.as_slice())]
}

/// Maximum CPI accounts the transfer / merge settlement forwards. SPP reads
/// three (`zone_transact` `[payer, tree, zone_config]`, `merge_zone` `[tree,
/// zone_config, payer]`) plus a trailing SPP program account: SPP settles then
/// emits its `GeneralEvent` via a self-CPI (`invoke(crate::ID, [])`), which can
/// only resolve if SPP's own program account is present in the context the zone
/// forwarded. So every settlement CPI forwards it, as the proofless deposit and
/// the policy-zone reference both do. Hence `3 + 1`.
const SPP_CPI_MAX_ACCOUNTS: usize = 4;

/// Maximum CPI accounts the proofless deposit forwards to SPP's `zone_deposit`.
/// SPP's deposit loader reads the trailing program account directly (and it is
/// also needed for the event self-CPI). The widest shape is SPL: `[tree,
/// depositor, zone_config, user_token, vault, registry, token_program,
/// program]`.
const SPP_DEPOSIT_CPI_MAX_ACCOUNTS: usize = 8;

/// Maximum CPI accounts a withdrawal forwards to SPP's `zone_transact`: the
/// transfer's `[payer, tree, zone_config]`, the settlement tail, and the
/// trailing SPP program account (for the event self-CPI). The widest shape is
/// SPL: `[cpi_authority, vault, recipient, user_token_account, token_program]`
/// (5), so `3 + 5 + 1`.
const SPP_WITHDRAWAL_CPI_MAX_ACCOUNTS: usize = 9;

/// SPP `zone_transact` CPI: settle a synchronous transfer through the
/// shielded pool, signed by the zone-auth PDA. `accounts` must be exactly
/// `[payer, tree, zone_auth, spp_program]` (the transfer leg only -- the
/// withdrawal leg has a settlement tail and uses [`spp_zone_withdraw`]). The
/// trailing SPP program account is required for SPP's event self-CPI.
#[inline(never)]
pub fn spp_transact(
    spp_program: &AccountView,
    accounts: &[&AccountView],
    instruction_data: &[u8],
    zone_auth_bump: u8,
) -> ProgramResult {
    validate_spp_program(spp_program)?;
    invoke_zone_signed::<SPP_CPI_MAX_ACCOUNTS>(accounts, instruction_data, zone_auth_bump)
}

/// SPP `merge_zone` CPI: settle a merge proof through the shielded pool,
/// signed by the zone-auth PDA. `accounts` must be exactly `[tree, zone_auth,
/// merge_authority, spp_program]` -- SPP's `merge_zone` reads `zone_auth` (its
/// `zone_config`) as one signer and a second, independent signer it calls
/// `payer` (the zone forwards its own `merge_authority`, already a real
/// transaction-level signer, straight through for that role); the trailing SPP
/// program account is required for SPP's event self-CPI.
#[inline(never)]
pub fn spp_merge_transact(
    spp_program: &AccountView,
    accounts: &[&AccountView],
    instruction_data: &[u8],
    zone_auth_bump: u8,
) -> ProgramResult {
    validate_spp_program(spp_program)?;
    invoke_zone_signed::<SPP_CPI_MAX_ACCOUNTS>(accounts, instruction_data, zone_auth_bump)
}

/// SPP `zone_transact` CPI for a withdrawal: like [`spp_transact`] but forwards
/// the settlement account tail after `zone_auth`. `accounts` must be `[payer,
/// tree, zone_auth, <settlement>, spp_program]` where settlement is SOL
/// `[sol_interface, recipient, system_program]` or SPL `[cpi_authority, vault,
/// recipient, user_token_account, token_program]`. The trailing SPP program
/// account is required for SPP's event self-CPI.
#[inline(never)]
pub fn spp_zone_withdraw(
    spp_program: &AccountView,
    accounts: &[&AccountView],
    instruction_data: &[u8],
    zone_auth_bump: u8,
) -> ProgramResult {
    validate_spp_program(spp_program)?;
    invoke_zone_signed::<SPP_WITHDRAWAL_CPI_MAX_ACCOUNTS>(
        accounts,
        instruction_data,
        zone_auth_bump,
    )
}

/// SPP `zone_deposit` CPI: settle a proofless deposit through the shielded
/// pool, signed by the zone-auth PDA. Unlike `zone_transact`/`merge_zone`, SPP's
/// deposit loader reads a trailing program account, so `accounts` must end with
/// the SPP program account: `[tree, depositor, zone_auth, <settlement>,
/// spp_program]`. The depositor is already a real signer; the zone-auth PDA is
/// flipped to signer by `invoke_zone_signed`.
#[inline(never)]
pub fn spp_zone_deposit(
    spp_program: &AccountView,
    accounts: &[&AccountView],
    instruction_data: &[u8],
    zone_auth_bump: u8,
) -> ProgramResult {
    validate_spp_program(spp_program)?;
    invoke_zone_signed::<SPP_DEPOSIT_CPI_MAX_ACCOUNTS>(accounts, instruction_data, zone_auth_bump)
}

/// Shared CPI plumbing: build `InstructionAccount` metas from `accounts` (in
/// order, forwarded verbatim -- callers must already include every account
/// SPP's own loader expects, in its exact order), flip the signer bit for
/// whichever address equals this program's `zone_auth` PDA, then
/// `invoke_signed`.
#[inline(always)]
pub(crate) fn invoke_zone_signed<const MAX_ACCOUNTS: usize>(
    accounts: &[&AccountView],
    instruction_data: &[u8],
    zone_auth_bump: u8,
) -> ProgramResult {
    let bump = [zone_auth_bump];
    let zone_auth_address = derive_zone_auth_address(&bump)?;

    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|account| {
            let is_signer =
                account.is_signer() || address_eq(account.address(), &zone_auth_address);
            InstructionAccount::new(account.address(), account.is_writable(), is_signer)
        })
        .collect();

    let spp_program_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let instruction = InstructionView {
        program_id: &spp_program_id,
        accounts: &metas,
        data: instruction_data,
    };
    let seeds = zone_auth_seeds(&bump);
    let signer = Signer::from(&seeds);

    invoke_signed_with_bounds::<MAX_ACCOUNTS, _>(
        &instruction,
        accounts,
        core::slice::from_ref(&signer),
    )
    .map_err(|_| SquadsZoneError::SppCpiFailed)?;
    Ok(())
}

/// Confirm the supplied account is executable AND is the canonical SPP
/// program id. Every CPI into SPP must run this before invoking.
#[inline(always)]
pub(crate) fn validate_spp_program(spp_program: &AccountView) -> Result<(), ProgramError> {
    if !spp_program.executable()
        || !address_eq(
            spp_program.address(),
            &Address::from(SHIELDED_POOL_PROGRAM_ID),
        )
    {
        return Err(SquadsZoneError::InvalidSppProgram.into());
    }
    Ok(())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_zone_auth_address(bump: &[u8; 1]) -> Result<Address, ProgramError> {
    Address::create_program_address(&[ZONE_AUTH_PDA_SEED, bump.as_slice()], &crate::ID)
        .map_err(|_| SquadsZoneError::InvalidZoneAuth.into())
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_zone_auth_address(_bump: &[u8; 1]) -> Result<Address, ProgramError> {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}
