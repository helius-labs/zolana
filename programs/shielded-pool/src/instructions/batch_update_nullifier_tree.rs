use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{BatchUpdateNullifierTreeData, BatchUpdateNullifierTreeFoldedData},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    event::emit_batch_address_append_event, protocol_config::loader::load_protocol_config,
    shared::reimburse_forester,
};

pub fn process_batch_update_nullifier_tree(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let instruction = BatchUpdateNullifierTreeData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let reimbursement_recipient = iter.next_mut("reimbursement_recipient")?;
    #[cfg(feature = "vk-registry")]
    let vk_registry = if iter.iterator_is_empty() {
        None
    } else {
        Some(&*iter.next_non_mut("vk_registry")?)
    };

    let config = load_protocol_config(protocol_config)?;
    config
        .check_forester_authority(authority.address())
        .map_err(ShieldedPoolError::from)?;
    drop(config);

    let event = {
        let mut tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        #[cfg(feature = "vk-registry")]
        match vk_registry {
            Some(registry) => {
                // Spec selection mirrors the verify-side batch-size match; the
                // batch size comes from tree state, not instruction data.
                let batch_size = tree_account.nullifer_tree().queue_batches.zkp_batch_size;
                let spec = match batch_size {
                    10 => &zolana_interface::verifying_keys::registry::BATCH_ADDRESS_APPEND_40_10_REGISTRY,
                    250 => &zolana_interface::verifying_keys::registry::BATCH_ADDRESS_APPEND_40_250_REGISTRY,
                    _ => return Err(ShieldedPoolError::NullifierTreeUpdateFailed.into()),
                };
                let data =
                    crate::instructions::vk_registry::load_finalized_vk_registry(registry, spec)?;
                let refs = crate::instructions::vk_registry::prepared_vk_refs(&data, spec)?;
                tree_account
                    .nullifer_tree()
                    .update_tree_from_address_queue_registered(instruction, &refs)
                    .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?
            }
            None => tree_account
                .nullifer_tree()
                .update_tree_from_address_queue(instruction)
                .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?,
        }
        #[cfg(not(feature = "vk-registry"))]
        tree_account
            .nullifer_tree()
            .update_tree_from_address_queue(instruction)
            .map_err(ShieldedPoolError::from)?
    };

    // The emit self-CPI passes no accounts, so the tree borrow does not conflict.
    // INVARIANT: the event emit must remain the LAST fallible operation in this
    // processor. Photon's parser records batch updates from the emitted event in
    // successful transactions only (its `tx.error` guard); an emit-then-fail
    // shape would either drop a genuine update or wedge the indexer on a forged
    // one. Keep every fallible step (including `reimburse_forester`) above it.
    if let Some(event) = event {
        reimburse_forester(tree, reimbursement_recipient, event.num_update)?;
        emit_batch_address_append_event(&event)?;
    }
    Ok(())
}

/// Settle a run of consecutive appends against one folded proof.
///
/// The run advances the tree by `run` zkp batches but appends one root, because
/// the intermediate roots are private to the fold. See
/// `update_tree_from_address_queue_folded` for why that is sound and what it
/// changes for readers of root history.
pub fn process_batch_update_nullifier_tree_folded(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (run, instruction) = <(u32, BatchUpdateNullifierTreeFoldedData)>::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let reimbursement_recipient = iter.next_mut("reimbursement_recipient")?;

    let config = load_protocol_config(protocol_config)?;
    config
        .check_forester_authority(authority.address())
        .map_err(ShieldedPoolError::from)?;
    drop(config);

    let event = {
        let mut tree_account =
            TreeAccount::from_account_view_mut(&mut *tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(ShieldedPoolError::from)?;
        tree_account
            .nullifer_tree()
            .update_tree_from_address_queue_folded(&instruction, run)
            .map_err(ShieldedPoolError::from)?
    };

    // INVARIANT: the event emit must remain the LAST fallible operation, for the
    // reason given on `process_batch_update_nullifier_tree`.
    reimburse_forester(tree, reimbursement_recipient, event.num_update)?;
    emit_batch_address_append_event(&event)?;
    Ok(())
}
