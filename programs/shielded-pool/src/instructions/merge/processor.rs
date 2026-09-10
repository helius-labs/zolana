use crate::instructions::shared::caused_by;
use arrayvec::ArrayVec;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{EventKind, InputTreeSequence},
    instruction::{
        instruction_data::merge_transact::{
            MergeExternalDataHash, MergeTransactIxDataRef, MAX_MERGE_INPUTS,
        },
        tag::MERGE_TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    tree_slot::TreeSlot,
};
use zolana_tree::TreeAccount;

use super::{
    account::{load_user_record, MergeTransactAccounts},
    event::{build_merge_event, MergeTreeWrite},
    verify::{MergeOwnerBinding, MergeProof, MergeProofInputs},
};
use crate::instructions::{
    event::emit_event,
    nullifier_pda::{create_nullifier_pdas, InputTreeResult},
    shared::{
        bool_field, check_field_element, check_field_elements, check_not_expired, tree_error,
    },
    transact::tree::queue_nullifiers,
};

pub(crate) struct MergeCoreAccounts<'a> {
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub payer: &'a AccountView,
    pub nullifier_pdas: ArrayVec<&'a mut AccountView, MAX_MERGE_INPUTS>,
}

pub(crate) fn validate_field_elements(ix: &MergeTransactIxDataRef<'_>) -> ProgramResult {
    check_field_elements(
        ix.nullifiers.iter(),
        "input nullifier",
        ShieldedPoolError::NonCanonicalInputNullifier,
    )?;
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
        clock.slot,
    )
}

/// Shared tail for `merge_transact` and `merge_ring`: resolve the input tree's
/// roots, nullify the inputs, append the output, verify the proof, and emit the
/// event. The tree-derived dummy-input policy is captured before any queue
/// insertion or state append.
#[inline(never)]
pub(crate) fn process_merge_core(
    mut accounts: MergeCoreAccounts<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    external_data_hash: [u8; 32],
    owner_binding: MergeOwnerBinding,
    output_view_tag: [u8; 32],
    slot: u64,
) -> ProgramResult {
    let (input_tree_result, mut derived) = {
        let input_tree = accounts.input_tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *accounts.input_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let allow_dummy_inputs = tree.allow_dummy_inputs().map_err(tree_error)?;
        let mut derived = MergeProofInputs {
            tree_slot: TreeSlot::ZERO,
            output_tree_id: [0u8; 32],
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
                input_tree: InputTreeSequence {
                    tree: input_tree,
                    first_input_queue_seq,
                },
                forester_fee,
                fee_balance: tree.fee_balance(),
                tree_id: tree.tree_id(),
            },
            derived,
        )
    };
    create_nullifier_pdas(
        accounts.payer,
        accounts.input_tree,
        &mut accounts.nullifier_pdas,
        ix.nullifiers.iter(),
        &input_tree_result,
    )?;
    let tree_write = {
        let output_tree = accounts.output_tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *accounts.output_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        derived.output_tree_id = tree.tree_id_array();
        apply_output_tree(
            &mut tree,
            ix,
            output_tree,
            input_tree_result.input_tree,
            slot,
        )?
    };

    let event = build_merge_event(tree_write, output_view_tag);
    MergeProof::new(ix, derived).verify()?;
    emit_event(EventKind::Merge, &event)
}

/// Resolve `input_tree`'s roots into the proof's tree slot and insert every
/// nullifier into its queue, returning the first input's queue sequence
/// number. `from_bytes` already enforced a supported merge shape. The circuit
/// publishes `INPUT_TREES` slots, but SPP spends from one `input_tree`, so every
/// input must reference the same pair of root indexes
/// (`InputTreeRootIndexMismatch` otherwise): the roots they resolve to fill
/// slot 0 and the remaining slots stay zero.
#[inline(never)]
fn apply_input_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    derived: &mut MergeProofInputs,
) -> Result<u64, ProgramError> {
    let shape = ShieldedPoolError::InvalidMergeShape;
    let utxo_tree_root_index = *ix.utxo_tree_root_index.first().ok_or(shape)?;
    let nullifier_tree_root_index = *ix.nullifier_tree_root_index.first().ok_or(shape)?;
    if ix
        .utxo_tree_root_index
        .iter()
        .any(|index| *index != utxo_tree_root_index)
        || ix
            .nullifier_tree_root_index
            .iter()
            .any(|index| *index != nullifier_tree_root_index)
    {
        return Err(ShieldedPoolError::InputTreeRootIndexMismatch.into());
    }
    derived.tree_slot = TreeSlot {
        id: tree.tree_id_array(),
        utxo_root: tree
            .get_utxo_tree_root(utxo_tree_root_index)
            .map_err(tree_error)?,
        nullifier_root: tree
            .get_nullifier_tree_root(nullifier_tree_root_index)
            .map_err(tree_error)?,
    };

    queue_nullifiers(tree, ix.nullifiers.iter())
}

fn apply_output_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    output_tree: [u8; 32],
    input_tree: InputTreeSequence,
    slot: u64,
) -> Result<MergeTreeWrite, ProgramError> {
    let output_leaf_index = tree.utxo_tree().next_index();
    tree.utxo_tree()
        .append(*ix.output_utxo_hash, slot)
        .map_err(tree_error)?;
    Ok(MergeTreeWrite {
        input_tree,
        output_leaf_index,
        output_tree,
    })
}
