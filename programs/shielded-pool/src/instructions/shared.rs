use bytemuck::{from_bytes, from_bytes_mut, Pod};
use pinocchio::{
    account::{Ref, RefMut},
    address::address_eq,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    state::{forester_fee_per_queue_element, FORESTER_REIMBURSEMENT_LAMPORTS},
};
use zolana_tree::TreeError;

pub(crate) fn bool_field(value: bool) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[31] = u8::from(value);
    field
}

/// Consume the trailing self-CPI program account, then the optional VK
/// registry that follows it.
///
/// The registry is always last, so the program account MUST be consumed first.
/// Testing for a leftover account without it accepts the program account as a
/// registry and fails the address compare on every well-formed instruction.
pub(crate) fn take_program_and_registry<'a>(
    iter: &mut AccountIterator<'a>,
) -> Result<Option<&'a AccountView>, ProgramError> {
    let program = iter.next_account("shielded_pool_program")?;
    if !address_eq(program.address(), &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    #[cfg(feature = "vk-registry")]
    if !iter.iterator_is_empty() {
        return Ok(Some(&*iter.next_non_mut("vk_registry")?));
    }
    Ok(None)
}

pub fn tree_error(error: TreeError) -> ProgramError {
    match error {
        TreeError::Paused => ShieldedPoolError::TreePaused.into(),
        TreeError::InvalidRootIndex => ShieldedPoolError::StaleNullifierRoot.into(),
        TreeError::TreeIsFull => ShieldedPoolError::StateAppendFailed.into(),
        _ => ShieldedPoolError::InvalidTreeAccounts.into(),
    }
}

#[inline(always)]
fn validate_config<T: Pod>(
    data: &[u8],
    invalid_error: ShieldedPoolError,
    has_valid_discriminator: impl FnOnce(&T) -> bool,
) -> ProgramResult {
    let config = bytemuck::try_from_bytes::<T>(data).map_err(|_| invalid_error)?;
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
    let data = account.try_borrow().map_err(|_| invalid_error)?;
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
    let data = account.try_borrow_mut().map_err(|_| invalid_error)?;
    validate_config(&data, invalid_error, has_valid_discriminator)?;
    Ok(RefMut::map(data, |data| from_bytes_mut::<T>(data)))
}

/// Collect one tree's per-element forester fee with one System Program CPI.
///
/// Every current insertion instruction has one tree. If an instruction gains
/// multiple trees, aggregate their amounts into the first tree and redistribute
/// from that program-owned tree, following Light's multi-transfer pattern.
#[inline(never)]
pub fn collect_forester_fee(
    payer: &AccountView,
    tree: &AccountView,
    inserted_elements: u64,
    zkp_batch_size: u64,
) -> ProgramResult {
    if !tree.is_writable() || !tree.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    let amount = forester_fee_amount(inserted_elements, zkp_batch_size)?;
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

pub fn forester_fee_amount(
    inserted_elements: u64,
    zkp_batch_size: u64,
) -> Result<u64, ProgramError> {
    forester_fee_per_queue_element(zkp_batch_size)
        .and_then(|fee| fee.checked_mul(inserted_elements))
        .ok_or_else(|| ShieldedPoolError::InvalidForesterFee.into())
}

/// Reimburse the caller that paid for successfully applied forester batches.
/// The tree is program-owned, so this transfer requires no CPI.
pub fn reimburse_forester(
    tree: &mut AccountView,
    recipient: &mut AccountView,
    applied_batches: u32,
) -> ProgramResult {
    if applied_batches == 0 {
        return Ok(());
    }
    if tree.address() == recipient.address() {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    let amount = u64::from(applied_batches)
        .checked_mul(FORESTER_REIMBURSEMENT_LAMPORTS)
        .ok_or(ShieldedPoolError::InvalidForesterFee)?;
    let rent_minimum = Rent::get()?.try_minimum_balance(tree.data_len())?;
    reimburse_forester_with_rent_minimum(tree, recipient, amount, rent_minimum)
}

pub fn reimburse_forester_with_rent_minimum(
    tree: &mut AccountView,
    recipient: &mut AccountView,
    amount: u64,
    rent_minimum: u64,
) -> ProgramResult {
    let remaining = tree
        .lamports()
        .checked_sub(amount)
        .filter(|remaining| *remaining >= rent_minimum)
        .ok_or(ShieldedPoolError::InsufficientForesterFeeBalance)?;
    let recipient_balance = recipient
        .lamports()
        .checked_add(amount)
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
/// pinocchio system helper. A raw `CreateAccount` would fail on a donated
/// balance and let an attacker DoS the creation.
///
/// `signer_seeds` must NOT include the bump. It is appended automatically.
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

#[cfg(test)]
mod tests {
    use zolana_account_checks::account_info::test_account_info::get_account_view;

    use super::*;

    fn account(address: [u8; 32]) -> AccountView {
        get_account_view(address, [0u8; 32], false, false, false, Vec::new())
    }

    /// Every builder ends the account list with the program account for the
    /// event self-CPI. A registry can only follow it, so a well-formed
    /// instruction that passes no registry must resolve to `None`.
    #[test]
    fn the_trailing_program_account_is_not_a_registry() {
        let mut accounts = [account(crate::ID.to_bytes())];
        let mut iter = AccountIterator::new(&mut accounts);
        assert!(take_program_and_registry(&mut iter)
            .expect("parse")
            .is_none());
    }

    #[cfg(feature = "vk-registry")]
    #[test]
    fn the_registry_follows_the_program_account() {
        let registry = [7u8; 32];
        let mut accounts = [account(crate::ID.to_bytes()), account(registry)];
        let mut iter = AccountIterator::new(&mut accounts);
        let parsed = take_program_and_registry(&mut iter).expect("parse");
        assert_eq!(parsed.map(|a| a.address().to_bytes()), Some(registry));
    }

    #[test]
    fn another_program_in_the_self_cpi_slot_is_rejected() {
        let mut accounts = [account([9u8; 32])];
        let mut iter = AccountIterator::new(&mut accounts);
        assert_eq!(
            take_program_and_registry(&mut iter),
            Err(ProgramError::IncorrectProgramId)
        );
    }
}
