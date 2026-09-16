use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    direct_spend::{certificate_id, Payload, PrepareCertificate, CERTIFICATE_INPUTS},
    verifying_keys::{input_certificate_36_0, nullifier_freshness_36_0},
};

use super::{buffer, check_freshness, load_payload, tree_layout, verify};

pub fn process_prepare(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let request = PrepareCertificate::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let owner = iter.next_signer("owner")?;
    let receipt = iter.next_mut("certificate")?;
    let tree = iter.next_account("input_tree")?;
    let Payload::Certificate { statement, proof } =
        load_payload(receipt, owner.address().as_array())?
    else {
        return Err(ProgramError::InvalidAccountData);
    };
    if !statement.validate(CERTIFICATE_INPUTS) || statement.tree != tree.address().to_bytes() {
        return Err(ProgramError::InvalidArgument);
    }
    let bytes = tree.try_borrow()?;
    let tree = tree_layout(tree, &bytes)?;
    check_freshness(tree, request.freshness)?;
    if buffer::read(&receipt.try_borrow()?)?.status() == 0 {
        if tree.utxo.root_by_index(statement.state_root.index).ok()
            != Some(statement.state_root.value)
        {
            return Err(ProgramError::InvalidArgument);
        }
        verify(
            &proof,
            &statement.fields(
                certificate_id(receipt.address().as_array())?,
                owner.address().as_array(),
                tree.tree_id,
                CERTIFICATE_INPUTS,
            )?,
            &input_certificate_36_0::VERIFYINGKEY,
        )?;
    }
    verify(
        &request.proof,
        &statement.freshness_fields(request.freshness, tree.tree_id, CERTIFICATE_INPUTS)?,
        &nullifier_freshness_36_0::VERIFYINGKEY,
    )?;
    buffer::mark_prepared(&mut receipt.try_borrow_mut()?, request.freshness);
    Ok(())
}
