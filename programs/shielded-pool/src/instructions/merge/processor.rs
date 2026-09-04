use crate::instructions::shared::caused_by;
use arrayvec::ArrayVec;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_event::MergeEvent;
use zolana_hasher::hash_chain::HashChain;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_transact::{
            MergeExternalDataHash, MergeTransactIxDataRef, MAX_MERGE_INPUTS,
        },
        tag::MERGE_TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use super::{
    account::{load_user_record, MergeTransactAccounts},
    verify::{MergeOwnerBinding, MergeProof, MergeProofInputs},
};
use crate::instructions::{
    event::emit_merge_event,
    nullifier_pda::{create_nullifier_pdas, InputTreeResult},
    shared::{
        bool_field, check_field_element, check_not_expired, collect_forester_fee, tree_error,
    },
};

pub(crate) struct MergeCoreAccounts<'a> {
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    pub nullifier_pdas: &'a mut [AccountView],
}

pub(crate) fn validate_field_elements(ix: &MergeTransactIxDataRef<'_>) -> ProgramResult {
    for (index, nullifier) in ix.nullifiers.try_iter().enumerate() {
        check_field_element(
            nullifier.map_err(|_| ProgramError::InvalidInstructionData)?,
            "input nullifier",
            Some(index),
            ShieldedPoolError::NonCanonicalInputNullifier,
        )?;
    }
    check_field_element(
        ix.output_utxo_hash,
        "output utxo hash",
        None,
        ShieldedPoolError::NonCanonicalOutputUtxoHash,
    )?;
    check_field_element(
        ix.private_tx_hash,
        "private tx hash",
        None,
        ShieldedPoolError::NonCanonicalPrivateTxHash,
    )
}

#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeTransactIxDataRef::from_bytes(data)
        .map_err(caused_by(ShieldedPoolError::InvalidMergeShape))?;
    validate_field_elements(&ix)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeTransactAccounts::validate_and_parse(accounts, ix.nullifiers.len())?;

    let pk_fields = load_user_record(merge_accounts.user_record, ix.eddsa_owner)?;

    // Per-user merge opt-in: the owner must have enabled merging. Any caller may
    // then run the merge.
    if !pk_fields.merging_enabled {
        return Err(ShieldedPoolError::MergeDisabled.into());
    }

    let signing_pk_field = pk_fields.signing_pk_field;
    // Owner-indexing view tag for the merged output: the owner signing pubkey (the
    // confidential default-ring tag, like every other confidential output). The
    // proof binds `signing_pk_field` to the same registered key, so a relayer cannot
    // alter it.
    let output_view_tag = pk_fields.signing_view_tag;

    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: MERGE_TRANSACT,
        expiry_unix_ts: ix.expiry_unix_ts,
        output_utxo_hash: ix.output_utxo_hash,
    }
    .hash()
    .map_err(caused_by(
        ShieldedPoolError::TransactProofVerificationFailed,
    ))?;

    process_merge_core(
        MergeCoreAccounts {
            input_tree: merge_accounts.input_tree,
            output_tree: merge_accounts.output_tree,
            payer: merge_accounts.payer,
            nullifier_pdas: merge_accounts.nullifier_pdas,
        },
        &ix,
        external_data_hash,
        MergeOwnerBinding::Registry { signing_pk_field },
        output_view_tag,
    )
}

/// Shared execution path for `merge_transact` and `merge_ring`: read roots,
/// nullify the inputs, append the output, verify the proof, and emit the event. The
/// tree-derived dummy-input policy is
/// captured before any queue insertion or state append.
#[inline(never)]
pub(crate) fn process_merge_core(
    accounts: MergeCoreAccounts<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    external_data_hash: [u8; 32],
    owner_binding: MergeOwnerBinding,
    output_view_tag: [u8; 32],
) -> ProgramResult {
    let mut nullifiers: ArrayVec<&[u8; 32], MAX_MERGE_INPUTS> = ArrayVec::new();
    for nullifier in ix.nullifiers.try_iter() {
        nullifiers
            .try_push(nullifier.map_err(|_| ProgramError::InvalidInstructionData)?)
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
    }
    let (input_tree_result, derived) = {
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *accounts.input_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let allow_dummy_inputs = tree.allow_dummy_inputs().map_err(tree_error)?;
        let mut derived = MergeProofInputs {
            utxo_root_chain: [0u8; 32],
            nullifier_tree_root_chain: [0u8; 32],
            input_count: 0,
            external_data_hash,
            allow_dummy_inputs: bool_field(allow_dummy_inputs),
            owner_binding,
        };
        let first_input_queue_seq = apply_input_tree(&mut tree, ix, &mut derived)?;
        let forester_fee = tree
            .credit_insertion_fee(ix.nullifiers.len() as u64)
            .map_err(tree_error)?;
        (
            InputTreeResult {
                first_input_queue_seq,
                forester_fee,
                fee_balance: tree.fee_balance(),
                tree_id: tree.tree_id(),
            },
            derived,
        )
    };
    // The fee transfer CPI includes the tree, so it must run before
    // create_nullifier_pdas moves tree lamports directly: a CPI boundary syncs
    // only its own accounts into the transaction context, and a pending tree
    // debit without the matching nullifier PDA credits trips the runtime's
    // UnbalancedInstruction check.
    collect_forester_fee(
        accounts.payer,
        accounts.input_tree,
        input_tree_result.forester_fee,
    )?;
    create_nullifier_pdas(
        accounts.input_tree,
        accounts.nullifier_pdas.iter_mut(),
        nullifiers.iter().copied(),
        &input_tree_result,
    )?;
    let output_leaf_index = {
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *accounts.output_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_output_tree(&mut tree, ix)?
    };

    MergeProof::new(ix, &derived).verify()?;
    // Only the execution-assigned positions, plus the output view tag, which
    // `merge_transact` reads from the `user_record` account rather than from
    // instruction data and so an indexer cannot recover.
    emit_merge_event(&MergeEvent {
        first_input_queue_seq: input_tree_result.first_input_queue_seq,
        first_output_leaf_index: output_leaf_index,
        output_view_tag,
    })
}

#[inline(never)]
fn apply_input_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    derived: &mut MergeProofInputs,
) -> Result<u64, ProgramError> {
    let input_count = ix.nullifiers.len();
    let mut first_input_queue_seq: Option<u64> = None;
    // Folded in place, so neither buffer scales with the merge input count.
    let mut utxo_root_chain = HashChain::new();
    let mut nullifier_tree_root_chain = HashChain::new();
    let inputs = ix
        .nullifiers
        .try_iter()
        .zip(ix.utxo_tree_root_index.try_iter())
        .zip(ix.nullifier_tree_root_index.try_iter());
    for ((nullifier, utxo_root_index), nullifier_root_index) in inputs {
        let nullifier = nullifier.map_err(|_| ProgramError::InvalidInstructionData)?;
        let utxo_root_index = utxo_root_index.map_err(|_| ProgramError::InvalidInstructionData)?;
        let nullifier_root_index =
            nullifier_root_index.map_err(|_| ProgramError::InvalidInstructionData)?;

        utxo_root_chain.push(
            &tree
                .get_utxo_tree_root(utxo_root_index)
                .map_err(tree_error)?,
        )?;
        nullifier_tree_root_chain.push(
            &tree
                .get_nullifier_tree_root(nullifier_root_index)
                .map_err(tree_error)?,
        )?;
        let queue_index = tree
            .nullifier_tree()
            .insert_nullifier_into_queue(nullifier)
            .map_err(caused_by(ShieldedPoolError::NullifierTreeUpdateFailed))?;
        // Only the first index is kept: the queue counter is monotone and this
        // loop walks one tree in instruction order.
        if first_input_queue_seq.is_none() {
            first_input_queue_seq = Some(queue_index);
        }
    }

    derived.utxo_root_chain = utxo_root_chain.finish();
    derived.nullifier_tree_root_chain = nullifier_tree_root_chain.finish();
    derived.input_count =
        u8::try_from(input_count).map_err(|_| ShieldedPoolError::InvalidMergeShape)?;

    Ok(first_input_queue_seq.unwrap_or_default())
}

fn apply_output_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
) -> Result<u64, ProgramError> {
    let output_leaf_index = tree.utxo_tree().next_index();
    tree.utxo_tree()
        .append(*ix.output_utxo_hash)
        .map_err(tree_error)?;
    Ok(output_leaf_index)
}
