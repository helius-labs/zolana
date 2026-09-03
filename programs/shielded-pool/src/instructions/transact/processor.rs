use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    error::ShieldedPoolError,
    event::TransactEvent,
    instruction::{
        instruction_data::transact::{external_data_hash, CircuitId, OwnerTag, TransactIxDataRef},
        tag::InstructionTag,
    },
    N_PUBLIC_SLOTS,
};

use super::{
    account::{RingTransactAccounts, TransactAccounts},
    event::resolve_outputs,
    interface_transfer::settle_interface_transfers,
    tree::{apply_input_tree, apply_output_tree},
};
use crate::instructions::{
    event::emit_transact_event,
    nullifier_pda::create_nullifier_pdas,
    settlement::Settlement,
    shared::{check_field_element, check_field_elements, check_not_expired, collect_forester_fee},
    transact::verify::{OwnerHashCache, TransactProof, TransactProofInputs},
};

// 1. Deserialize instruction data.
// 2. Validate declared circuit type.
// 3. Check proof is not expired.
// 4. Resolve output tags from accounts.
#[inline(never)]
#[profile]
pub fn process_transact_ix(
    accounts: &mut [AccountView],
    data: &[u8],
    instruction: InstructionTag,
) -> ProgramResult {
    // 1. Deserialize instruction data.
    let (ix, bound_bytes) = TransactIxDataRef::parse_bound(data)
        .map_err(caused_by(ProgramError::InvalidInstructionData))?;
    // 2. Validate declared circuit type.
    validate_circuit_type(&ix, instruction)?;

    // 3. Check proof is not expired.
    let clock = Clock::get()?;
    check_not_expired(ix.bound.expiry_unix_ts, &clock)?;

    // 4. Resolve output tags from accounts.
    let resolved_outputs = resolve_outputs(accounts, &ix)?;
    // Neither is heap-allocated any more: both are now sized by fixed protocol
    // constants rather than by the input or output count.
    let mut proof_inputs = TransactProofInputs::new(ix.tail.circuit);
    let mut owner_hashes = OwnerHashCache::new();
    // 5. Derive the circuit-specific fixed-width output-owner commitment.
    proof_inputs.fill_output_owner_chain(
        ix.tail.circuit.output_owner_mode(),
        &resolved_outputs,
        &mut owner_hashes,
    )?;
    // 6. Check accounts.
    let transact_accounts = match ix.tail.circuit {
        CircuitId::ConfidentialEddsa(..) => TransactAccounts::validate_and_parse(accounts, &ix)?,
        CircuitId::RingEddsa(..) | CircuitId::RingAuthority(..) | CircuitId::RingP256(..) => {
            let (transact_accounts, ring_program_id) = RingTransactAccounts::validate_and_parse(
                accounts,
                &ix,
                ix.tail.circuit.is_authority(),
            )?;
            proof_inputs.assign_ring_program_id(hash_bytes(&ring_program_id)?);
            transact_accounts
        }
    };
    // 6. Add owner signer hashes to proof inputs.
    proof_inputs.fill_owner_signer_hashes(
        transact_accounts.payer,
        transact_accounts.owner_signers,
        &mut owner_hashes,
    )?;

    // 7. Process sol and spl transfers.
    proof_inputs.assign_public_amounts_and_assets(
        &ix.bound.interface_transfers,
        &transact_accounts.settlements,
        usize::from(ix.tail.circuit.num_public_asset_slots()),
    )?;
    // 8. Insert nullifiers into queue.
    let input_tree_result = apply_input_tree(transact_accounts.input_tree, &ix, &mut proof_inputs)?;
    // The fee transfer CPI includes the tree, so it must run before
    // create_nullifier_pdas moves tree lamports directly: a CPI boundary syncs
    // only its own accounts into the transaction context, and a pending tree
    // debit without the matching nullifier PDA credits trips the runtime's
    // UnbalancedInstruction check.
    collect_forester_fee(
        transact_accounts.payer,
        transact_accounts.input_tree,
        input_tree_result.forester_fee,
    )?;
    create_nullifier_pdas(
        transact_accounts.payer,
        transact_accounts.input_tree,
        transact_accounts.nullifier_pdas.iter_mut(),
        ix.tail.inputs.iter().map(|input| &input.nullifier_hash),
        &input_tree_result,
    )?;
    // 9. Append new utxo hashes.
    let tree_write = apply_output_tree(transact_accounts.output_tree, &ix)?;

    // Hashed straight out of the instruction buffer: the bound region is a
    // contiguous prefix, and the only values not already in it are the account
    // addresses the proof must commit to.
    let external_data_hash = external_data_hash(
        instruction as u8,
        bound_bytes,
        transact_accounts
            .settlements
            .iter()
            .flat_map(Settlement::bound_addresses)
            .chain(
                resolved_outputs
                    .iter()
                    .zip(&ix.bound.outputs)
                    .filter(|(_, wire)| matches!(wire.owner_tag, OwnerTag::Account(_)))
                    .map(|(resolved, _)| &resolved.owner_tag),
            ),
    )
    .map_err(caused_by(
        ShieldedPoolError::TransactProofVerificationFailed,
    ))?;
    proof_inputs.assign_external_data_hash(external_data_hash);
    proof_inputs.ensure_complete()?;

    TransactProof::new(&ix, &proof_inputs).verify()?;

    settle_interface_transfers(
        &ix.bound.interface_transfers,
        &transact_accounts.settlements,
    )?;

    // Only the execution-assigned positions: an indexer rebuilds nullifiers,
    // outputs, messages and trees from this instruction and its account list.
    emit_transact_event(&TransactEvent {
        first_input_queue_seq: input_tree_result.first_input_queue_seq,
        first_output_leaf_index: tree_write.first_output_leaf_index,
    })
}

/// Checks:
/// 1. Circuit is allowed for the instruction type
/// 2. Circuit parameters (in, out) match instruction data
/// 3. Circuit variant exists with in out public params is supported.
/// 4. Nullifiers, output utxo hashes, and the private tx hash are canonical
///    field elements.
pub fn validate_circuit_type(
    ix: &TransactIxDataRef<'_>,
    instruction_tag: InstructionTag,
) -> ProgramResult {
    // 1. Circuit is allowed for the instruction type.
    let circuit_matches = match instruction_tag {
        InstructionTag::Transact => matches!(ix.tail.circuit, CircuitId::ConfidentialEddsa(..)),
        InstructionTag::RingTransact => {
            matches!(
                ix.tail.circuit,
                CircuitId::RingEddsa(..) | CircuitId::RingP256(..)
            )
        }
        InstructionTag::RingAuthorityTransact => ix.tail.circuit.is_authority(),
        _ => false,
    };
    if !circuit_matches {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    if usize::from(ix.tail.circuit.num_inputs()) != ix.tail.inputs.len() // 2.
        || usize::from(ix.tail.circuit.num_outputs()) != ix.bound.outputs.len() //2.
        || usize::from(ix.tail.circuit.num_public_asset_slots()) > N_PUBLIC_SLOTS
        || !ix.tail.circuit.is_supported()
    // 3.
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    check_field_elements(
        ix.tail.inputs.iter().map(|input| &input.nullifier_hash),
        "input nullifier",
        ShieldedPoolError::NonCanonicalInputNullifier,
    )?;
    check_field_elements(
        ix.bound.outputs.iter().map(|output| output.utxo_hash),
        "output utxo hash",
        ShieldedPoolError::NonCanonicalOutputUtxoHash,
    )?;
    check_field_element(
        ix.tail.private_tx_hash,
        "private tx hash",
        None,
        ShieldedPoolError::NonCanonicalPrivateTxHash,
    )
}
