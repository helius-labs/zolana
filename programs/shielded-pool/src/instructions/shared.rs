use bytemuck::{from_bytes, from_bytes_mut, Pod};
use pinocchio::{
    account::{Ref, RefMut},
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;
use zolana_interface::error::ShieldedPoolError;
use zolana_tree::{nullifier_tree::error::NullifierTreeError, TreeError};

pub(crate) fn bool_field(value: bool) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[31] = u8::from(value);
    field
}

pub fn tree_error(error: TreeError) -> ProgramError {
    match error {
        TreeError::Paused => ShieldedPoolError::TreePaused.into(),
        TreeError::InvalidRootIndex => ShieldedPoolError::StaleNullifierRoot.into(),
        TreeError::TreeIsFull => ShieldedPoolError::StateAppendFailed.into(),
        TreeError::FeeOverflow => ShieldedPoolError::InvalidForesterFee.into(),
        _ => ShieldedPoolError::InvalidTreeAccounts.into(),
    }
}

pub fn nullifier_tree_error(error: NullifierTreeError) -> ProgramError {
    match error {
        NullifierTreeError::NonCanonicalFieldElement => ShieldedPoolError::NonCanonicalRoot.into(),
        _ => ShieldedPoolError::NullifierTreeUpdateFailed.into(),
    }
}

pub(crate) fn caused_by<E>(error: impl Into<ProgramError>) -> impl FnOnce(E) -> ProgramError {
    move |_| error.into()
}

pub(crate) fn check_field_element(
    value: &[u8; 32],
    _field: &str,
    _index: Option<usize>,
    error: ShieldedPoolError,
) -> ProgramResult {
    if is_canonical_bn254_scalar_be(value) {
        return Ok(());
    }
    Err(error.into())
}

#[inline(always)]
fn validate_config<T: Pod>(
    data: &[u8],
    invalid_error: ShieldedPoolError,
    has_valid_discriminator: impl FnOnce(&T) -> bool,
) -> ProgramResult {
    let config = bytemuck::try_from_bytes::<T>(data).map_err(caused_by(invalid_error))?;
    has_valid_discriminator(config)
        .then_some(())
        .ok_or_else(|| invalid_error.into())
}

#[inline(always)]
pub(crate) fn load_config<T: Pod>(
    account: &AccountView,
    invalid_error: ShieldedPoolError,
    has_valid_discriminator: impl FnOnce(&T) -> bool,
) -> Result<Ref<'_, T>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(invalid_error.into());
    }
    let data = account.try_borrow().map_err(caused_by(invalid_error))?;
    validate_config(&data, invalid_error, has_valid_discriminator)?;
    Ok(Ref::map(data, |data| from_bytes::<T>(data)))
}

#[inline(always)]
pub(crate) fn load_config_mut<T: Pod>(
    account: &mut AccountView,
    invalid_error: ShieldedPoolError,
    has_valid_discriminator: impl FnOnce(&T) -> bool,
) -> Result<RefMut<'_, T>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(invalid_error.into());
    }
    let data = account.try_borrow_mut().map_err(caused_by(invalid_error))?;
    validate_config(&data, invalid_error, has_valid_discriminator)?;
    Ok(RefMut::map(data, |data| from_bytes_mut::<T>(data)))
}

/// Collect one tree's forester fee with one System Program CPI. The amount was
/// computed and credited to the tree's fee balance inside the tree data borrow.
///
/// Every current insertion instruction has one tree. If an instruction gains
/// multiple trees, aggregate their amounts into the first tree and redistribute
/// from that program-owned tree, following Light's multi-transfer pattern.
#[inline(never)]
pub fn collect_forester_fee(payer: &AccountView, tree: &AccountView, amount: u64) -> ProgramResult {
    if !tree.is_writable() || !tree.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    if amount == 0 {
        return Ok(());
    }

    Transfer {
        from: payer,
        to: tree,
        lamports: amount,
    }
    .invoke()
}

pub fn check_reimbursement_recipient(recipient: &AccountView) -> ProgramResult {
    if recipient.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidReimbursementRecipient.into());
    }
    Ok(())
}

pub fn pay_reimbursement(
    tree: &mut AccountView,
    recipient: &mut AccountView,
    paid: u64,
) -> ProgramResult {
    if paid == 0 {
        return Ok(());
    }
    let rent_minimum = Rent::get()?.try_minimum_balance(tree.data_len())?;
    pay_reimbursement_with_rent_minimum(tree, recipient, paid, rent_minimum)
}

pub fn pay_reimbursement_with_rent_minimum(
    tree: &mut AccountView,
    recipient: &mut AccountView,
    paid: u64,
    rent_minimum: u64,
) -> ProgramResult {
    let remaining = tree
        .lamports()
        .checked_sub(paid)
        .filter(|remaining| *remaining >= rent_minimum)
        .ok_or(ShieldedPoolError::InsufficientForesterFeeBalance)?;
    let recipient_balance = recipient
        .lamports()
        .checked_add(paid)
        .ok_or(ShieldedPoolError::InvalidForesterFee)?;
    tree.set_lamports(remaining);
    recipient.set_lamports(recipient_balance);
    Ok(())
}

/// Reject a transaction whose `expiry_unix_ts` has passed (or a negative clock).
/// Shared by every instruction that carries an `expiry_unix_ts`.
#[inline(always)]
pub fn check_not_expired(expiry_unix_ts: u64, clock: &Clock) -> ProgramResult {
    if clock.unix_timestamp < 0 || (clock.unix_timestamp as u64) > expiry_unix_ts {
        return Err(ShieldedPoolError::ExpiredTransaction.into());
    }
    Ok(())
}

/// Create a program-derived account. Handles both the hot path (the account has
/// no lamports) and the cold path (an attacker pre-funded the address) via the
/// pinocchio system helper; a raw `CreateAccount` would fail on a donated
/// balance and let an attacker DoS the creation.
///
/// `signer_seeds` must NOT include the bump; it is appended automatically.
pub struct CreatePdaAccount<'a, const N: usize> {
    pub fee_payer: &'a AccountView,
    pub new_account: &'a mut AccountView,
    pub space: usize,
    pub owner: &'a Address,
    pub signer_seeds: [&'a [u8]; N],
    pub bump: u8,
}

impl<const N: usize> CreatePdaAccount<'_, N> {
    #[inline(always)]
    pub fn execute(self) -> ProgramResult {
        let bump_seed = [self.bump];
        let s = self.signer_seeds;
        match N {
            1 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let seeds = [Seed::from(*s0), Seed::from(bump_seed.as_ref())];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            2 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let s1 = s.get(1).ok_or(ProgramError::InvalidArgument)?;
                let seeds = [
                    Seed::from(*s0),
                    Seed::from(*s1),
                    Seed::from(bump_seed.as_ref()),
                ];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            _ => Err(ProgramError::InvalidArgument),
        }
    }
}

/// Derive the canonical PDA from `seeds` and `program_id`, then verify it
/// matches `account_key`. Returns the canonical bump on success.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn verify_pda(
    account_key: &Address,
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<u8, ProgramError> {
    use pinocchio::address::address_eq;
    use zolana_interface::error::ShieldedPoolError;

    let (derived, bump) = Address::find_program_address(seeds, program_id);
    if !address_eq(account_key, &derived) {
        return Err(ShieldedPoolError::InvalidPda.into());
    }
    Ok(bump)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn verify_pda(
    _account_key: &Address,
    _seeds: &[&[u8]],
    _program_id: &Address,
) -> Result<u8, ProgramError> {
    unimplemented!("verify_pda requires Solana runtime syscalls")
}
