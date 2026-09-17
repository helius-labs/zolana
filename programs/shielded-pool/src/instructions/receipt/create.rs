use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateReceiptData,
    state::{
        discriminator::{RECEIPT, TREE_ACCOUNT_DISCRIMINATOR},
        receipt::{is_supported_capacity, receipt_account_size, ReceiptHeader, RECEIPT_SEED},
    },
};
use zolana_tree::TreeAccount;

use super::loader::{header_mut, load_receipt};
use crate::instructions::shared::{caused_by, tree_error, verify_pda, CreatePdaAccount};

/// Accounts: rent payer (signer, becomes the sponsor), receipt (writable),
/// tree (read-only, bound into the receipt), system program. Idempotent: a
/// repeated create with the same configuration is a no-op, a different one is
/// rejected. The PDA derives from the sponsor, so nobody can squat it.
pub fn process_create_receipt(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = CreateReceiptData::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer("rent_payer")?;
    let receipt = iter.next_mut("receipt")?;
    // Writable only because the tree loader has no read-only form; nothing is
    // written.
    let tree = iter.next_mut("tree")?;
    let system = iter.next_account("system_program")?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    if !pinocchio_system::check_id(system.address()) {
        return Err(ShieldedPoolError::InvalidSystemProgram.into());
    }
    if !is_supported_capacity(ix.capacity) {
        return Err(ShieldedPoolError::UnsupportedReceiptCapacity.into());
    }
    // A live tree of this program; the receipt is only meaningful for it.
    let tree_address =
        TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(tree_error)?
            .pubkey();
    let rent_sponsor = payer.address().to_bytes();
    let nonce_le = ix.nonce.to_le_bytes();
    let bump = verify_pda(
        receipt.address(),
        &[RECEIPT_SEED, &rent_sponsor, &nonce_le],
        &crate::ID,
    )?;
    if receipt.owned_by(&crate::ID) {
        let data = load_receipt(receipt)?;
        let current = super::loader::header(&data);
        if current.capacity() != ix.capacity
            || current.tree != tree_address
            || current.rent_sponsor != rent_sponsor
            || current.nonce() != ix.nonce
            || current.bump != bump
        {
            return Err(ShieldedPoolError::ReceiptConfigMismatch.into());
        }
        return Ok(());
    }
    if !pinocchio_system::check_id(receipt.owner()) || receipt.data_len() != 0 {
        return Err(ShieldedPoolError::InvalidReceipt.into());
    }
    CreatePdaAccount {
        fee_payer: payer,
        new_account: receipt,
        space: receipt_account_size(ix.capacity),
        owner: &crate::ID,
        signer_seeds: [RECEIPT_SEED, &rent_sponsor, &nonce_le],
        bump,
    }
    .execute()?;
    let mut data = receipt
        .try_borrow_mut()
        .map_err(caused_by(ShieldedPoolError::InvalidReceipt))?;
    if data.len() != receipt_account_size(ix.capacity) || data.iter().any(|byte| *byte != 0) {
        return Err(ShieldedPoolError::InvalidReceipt.into());
    }
    *header_mut(&mut data) = ReceiptHeader {
        discriminator: RECEIPT,
        bump,
        verified: 0,
        _padding: 0,
        capacity: ix.capacity.to_le_bytes(),
        count: [0; 2],
        filled: [0; 2],
        _padding2: [0; 6],
        tree: tree_address,
        nullifier_root: [0; 32],
        rent_sponsor,
        nonce: nonce_le,
    };
    Ok(())
}
