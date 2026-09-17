use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{VerifyReceiptData, RECEIPT_DOMAIN},
    state::{discriminator::TREE_ACCOUNT_DISCRIMINATOR, receipt::receipt_nullifiers},
    tree_slot::tree_id_field,
    verifying_keys::nullifier_receipt_8_0,
};
use zolana_tree::TreeAccount;

use super::loader::{header, header_mut, load_receipt_mut};
use crate::instructions::{
    shared::{caused_by, tree_error},
    verifier::{verify_groth16, Groth16Proof},
};

/// Accounts: receipt (writable), tree (writable, unmodified). Permissionless.
/// Requires `count` filled slots and zero padding, verifies the receipt proof
/// against the tree's nullifier root at `nullifier_tree_root_index`, then
/// records that root and freezes the receipt.
pub fn process_verify_receipt(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = VerifyReceiptData::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let receipt = iter.next_mut("receipt")?;
    let tree = iter.next_mut("tree")?;
    if !iter.remaining_unchecked_mut()?.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut bytes = load_receipt_mut(receipt)?;
    let (capacity, tree_address) = {
        let current = header(&bytes);
        if current.verified != 0 {
            return Err(ShieldedPoolError::ReceiptAlreadyVerified.into());
        }
        if ix.count == 0 || ix.count != current.filled() || ix.count > current.capacity() {
            return Err(ShieldedPoolError::ReceiptIncomplete.into());
        }
        (current.capacity(), current.tree)
    };
    if tree.address().to_bytes() != tree_address {
        return Err(ShieldedPoolError::ReceiptTreeMismatch.into());
    }
    let (tree_id, root) = {
        let tree = TreeAccount::from_account_view_mut(tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
            .map_err(tree_error)?;
        (
            tree.tree_id(),
            tree.get_nullifier_tree_root(ix.nullifier_tree_root_index)
                .map_err(tree_error)?,
        )
    };
    let nullifiers = receipt_nullifiers(&bytes);
    // Padding must be zero: the circuit reads zero as an inactive slot.
    if nullifiers[usize::from(ix.count)..]
        .iter()
        .any(|slot| *slot != [0; 32])
    {
        return Err(ShieldedPoolError::ReceiptIncomplete.into());
    }
    let fields = [
        right_align(&RECEIPT_DOMAIN.to_be_bytes()),
        tree_id_field(tree_id),
        root,
        right_align(&ix.count.to_be_bytes()),
        create_hash_chain_4_from_slice(nullifiers)
            .map_err(caused_by(ShieldedPoolError::InvalidReceipt))?,
    ];
    let public_input_hash = create_hash_chain_4_from_slice(&fields)
        .map_err(caused_by(ShieldedPoolError::InvalidReceipt))?;
    verify_groth16(
        Groth16Proof {
            a: &ix.proof.a,
            b: &ix.proof.b,
            c: &ix.proof.c,
            commitment: Some((&ix.commitment, &ix.commitment_pok)),
        },
        public_input_hash,
        verifying_key(capacity)?,
        ShieldedPoolError::InvalidTransactProofEncoding,
        ShieldedPoolError::TransactProofVerificationFailed,
    )?;
    let current = header_mut(&mut bytes);
    current.verified = 1;
    current.count = ix.count.to_le_bytes();
    current.nullifier_root = root;
    Ok(())
}

fn verifying_key(capacity: u16) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
    // One arm per entry of `RECEIPT_CAPACITIES`.
    Ok(match capacity {
        8 => &nullifier_receipt_8_0::VERIFYINGKEY,
        _ => return Err(ShieldedPoolError::UnsupportedReceiptCapacity.into()),
    })
}
