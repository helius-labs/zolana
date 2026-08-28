use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    error::ShieldedPoolError,
    event::EventKind,
    instruction::{
        instruction_data::transact::{CircuitId, ExternalDataHash, TransactIxDataRef},
        tag::InstructionTag,
    },
    N_PUBLIC_SLOTS,
};

use super::{
    account::{RingTransactAccounts, TransactAccounts},
    event::{build_transact_event, resolve_outputs},
    interface_transfer::{resolve_interface_transfers, settle_interface_transfers},
    tree::{apply_input_tree, apply_output_tree},
};
use crate::instructions::{
    event::emit_general_event,
    nullifier_marker::{create_nullifier_markers, fund_nullifier_markers},
    shared::{check_not_expired, collect_forester_fee},
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
    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    // 2. Validate declared circuit type.
    validate_circuit_type(&ix, instruction)?;

    // 3. Check proof is not expired.
    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    // 4. Resolve output tags from accounts.
    let resolved_outputs = resolve_outputs(accounts, &ix)?;
    let mut proof_inputs = Box::new(TransactProofInputs::new(ix.circuit));
    let mut owner_hashes = Box::new(OwnerHashCache::new());
    // 5. Derive the circuit-specific fixed-width output-owner commitment.
    proof_inputs.fill_output_owner_pk_hashes(
        ix.circuit.output_owner_mode(),
        &resolved_outputs,
        &mut owner_hashes,
    )?;
    // 6. Check accounts.
    let mut transact_accounts = match ix.circuit {
        CircuitId::ConfidentialEddsa(..) => TransactAccounts::validate_and_parse(accounts, &ix)?,
        CircuitId::RingEddsa(..) | CircuitId::RingAuthority(..) | CircuitId::RingP256(..) => {
            let (transact_accounts, ring_program_id) =
                RingTransactAccounts::validate_and_parse(accounts, &ix, ix.circuit.is_authority())?;
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
        &ix.interface_transfers,
        &transact_accounts.settlements,
        usize::from(ix.circuit.num_public_asset_slots()),
    )?;
    // 8. Insert nullifiers into queue.
    let input_tree_result = apply_input_tree(transact_accounts.input_tree, &ix, &mut proof_inputs)?;
    let marker_rent = create_nullifier_markers(
        transact_accounts.input_tree,
        &mut transact_accounts.nullifier_markers,
        &input_tree_result.inputs,
    )?;
    // 9. Append new utxo hashes.
    let tree_write =
        apply_output_tree(transact_accounts.output_tree, &ix, input_tree_result.inputs)?;

    let resolved_interface_transfers =
        resolve_interface_transfers(&ix, &transact_accounts.settlements);

    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: instruction as u8,
        expiry_unix_ts: ix.expiry_unix_ts,
        interface_transfers: &resolved_interface_transfers,
        data_hash: ix.data_hash,
        ring_data_hash: ix.ring_data_hash,
        tx_viewing_pk: ix.tx_viewing_pk,
        salt: ix.salt,
        outputs: &resolved_outputs,
        messages: &ix.messages,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    proof_inputs.assign_external_data_hash(external_data_hash);
    proof_inputs.ensure_complete()?;

    TransactProof::new(&ix, &proof_inputs).verify()?;

    settle_interface_transfers(&ix.interface_transfers, &transact_accounts.settlements)?;

    collect_forester_fee(
        transact_accounts.payer,
        transact_accounts.input_tree,
        ix.inputs.len() as u64,
        input_tree_result.zkp_batch_size,
    )?;
    fund_nullifier_markers(
        transact_accounts.input_tree,
        &mut transact_accounts.nullifier_markers,
        &marker_rent,
    )?;

    let event = build_transact_event(
        &ix,
        &transact_accounts.settlements,
        tree_write,
        &resolved_outputs,
    );
    emit_general_event(EventKind::Transact, event)
}

/// Checks:
/// 1. Circuit is allowed for the instruction type
/// 2. Circuit parameters (in, out) match instruction data
/// 3. Circuit variant exists with in out public params is supported.
pub fn validate_circuit_type(
    ix: &TransactIxDataRef<'_>,
    instruction_tag: InstructionTag,
) -> ProgramResult {
    // 1. Circuit is allowed for the instruction type.
    let circuit_matches = match instruction_tag {
        InstructionTag::Transact => matches!(ix.circuit, CircuitId::ConfidentialEddsa(..)),
        InstructionTag::RingTransact => {
            matches!(
                ix.circuit,
                CircuitId::RingEddsa(..) | CircuitId::RingP256(..)
            )
        }
        InstructionTag::RingAuthorityTransact => ix.circuit.is_authority(),
        _ => false,
    };
    if !circuit_matches {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    if usize::from(ix.circuit.num_inputs()) != ix.inputs.len() // 2.
        || usize::from(ix.circuit.num_outputs()) != ix.outputs.len() //2.
        || usize::from(ix.circuit.num_public_asset_slots()) > N_PUBLIC_SLOTS
        || !ix.circuit.is_supported()
    // 3.
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    Ok(())
}
