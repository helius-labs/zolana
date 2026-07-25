use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use zolana_interface::{
    error::ShieldedPoolError,
    state::{forester_fee_per_queue_element, FORESTER_REIMBURSEMENT_LAMPORTS},
};

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

fn forester_fee_amount(inserted_elements: u64, zkp_batch_size: u64) -> Result<u64, ProgramError> {
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

fn reimburse_forester_with_rent_minimum(
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

#[cfg(test)]
mod tests {
    use zolana_account_checks::account_info::test_account_info::get_account_view;

    use super::*;

    #[test]
    fn per_tree_fee_scales_with_inserted_elements() {
        assert_eq!(forester_fee_amount(3, 250).unwrap(), 60);
    }

    #[test]
    fn reimbursement_moves_funded_lamports_and_preserves_rent() {
        let mut tree = get_account_view(
            [1; 32],
            crate::ID.to_bytes(),
            false,
            true,
            false,
            vec![0; 10],
        );
        let mut recipient = get_account_view([2; 32], [0; 32], false, true, false, vec![]);
        tree.set_lamports(6_500);
        recipient.set_lamports(1_000);

        reimburse_forester_with_rent_minimum(&mut tree, &mut recipient, 5_000, 1_500).unwrap();

        assert_eq!(tree.lamports(), 1_500);
        assert_eq!(recipient.lamports(), 6_000);
    }

    #[test]
    fn reimbursement_cannot_spend_tree_rent() {
        let mut tree = get_account_view(
            [1; 32],
            crate::ID.to_bytes(),
            false,
            true,
            false,
            vec![0; 10],
        );
        let mut recipient = get_account_view([2; 32], [0; 32], false, true, false, vec![]);
        tree.set_lamports(6_499);

        let error = reimburse_forester_with_rent_minimum(&mut tree, &mut recipient, 5_000, 1_500)
            .unwrap_err();

        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InsufficientForesterFeeBalance as u32)
        );
        assert_eq!(tree.lamports(), 6_499);
        assert_eq!(recipient.lamports(), 1_000);
    }
}
