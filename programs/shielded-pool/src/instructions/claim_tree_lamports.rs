use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    state::{discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_working_capital_lamports},
    NULLIFIER_PDA_SIZE,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    protocol_config::loader::load_and_validate_fee_authority,
    shared::{check_reimbursement_recipient, pay_reimbursement_with_rent_minimum, tree_error},
};

/// Move every lamport above the tree's reserve to `recipient`. The reserve is
/// the tree's rent exemption, the forester fee balance, and the full nullifier
/// PDA working capital, all at the current rent, so a claim never starves
/// nullifier PDA creation and never touches forester money.
#[inline(never)]
pub fn process_claim_tree_lamports(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let recipient = iter.next_mut("recipient")?;

    load_and_validate_fee_authority(protocol_config, authority)?;
    check_reimbursement_recipient(recipient)?;

    let rent = Rent::get()?;
    let tree_rent_minimum = rent.try_minimum_balance(tree.data_len())?;
    let nullifier_pda_rent_minimum = rent.try_minimum_balance(NULLIFIER_PDA_SIZE)?;
    let reserve = {
        let mut tree_account = TreeAccount::from_account_view_mut_allow_paused(
            tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let working_capital = tree_working_capital_lamports(
            tree_account.nullifier_tree().batch_size,
            nullifier_pda_rent_minimum,
        )
        .ok_or(ProgramError::ArithmeticOverflow)?;
        tree_rent_minimum
            .checked_add(tree_account.fee_balance())
            .and_then(|reserve| reserve.checked_add(working_capital))
            .ok_or(ProgramError::ArithmeticOverflow)?
    };

    let claimable = tree.lamports().saturating_sub(reserve);
    if claimable == 0 {
        return Err(ShieldedPoolError::NoClaimableTreeLamports.into());
    }
    pay_reimbursement_with_rent_minimum(tree, recipient, claimable, reserve)
}
