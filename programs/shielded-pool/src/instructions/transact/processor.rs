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
    event::EventKind,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataPreimage, ResolvedOutput, TransactIxDataRef,
        },
        tag::InstructionTag,
        validate_input_tree_contexts,
    },
    N_PUBLIC_SLOTS,
};

use super::{
    account::{RingTransactAccounts, TransactAccounts},
    event::{build_transact_event, resolve_outputs},
    interface_transfer::settle_interface_transfers,
    tree::{apply_input_trees, apply_output_tree},
};
use crate::instructions::{
    event::emit_event,
    settlement::Settlement,
    shared::{check_field_element, check_field_elements, check_not_expired},
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
    let (ix, external_data_prefix) = TransactIxDataRef::parse_with_external_data_prefix(data)
        .map_err(caused_by(ProgramError::InvalidInstructionData))?;
    // 2. Validate declared circuit type and the declared input trees.
    validate_circuit_type(&ix, instruction)?;
    validate_input_tree_contexts(&ix.inputs, &ix.tree_contexts)?;

    // 3. Check proof is not expired.
    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    // 4. Resolve output tags from accounts.
    let resolved_outputs = resolve_outputs(accounts, &ix)?;
    let mut proof_inputs = Box::new(TransactProofInputs::new(ix.circuit));
    let mut owner_hashes = Box::new(OwnerHashCache::new());
    // 5. Check accounts.
    let mut transact_accounts = match ix.circuit {
        CircuitId::ConfidentialEddsa(..) => TransactAccounts::validate_and_parse(accounts, &ix)?,
        CircuitId::RingEddsa(..) | CircuitId::RingAuthority(..) | CircuitId::RingP256(..) => {
            let (transact_accounts, ring_program_id) =
                RingTransactAccounts::validate_and_parse(accounts, &ix, ix.circuit.is_authority())?;
            proof_inputs.assign_ring_program_id(hash_bytes(&ring_program_id)?);
            transact_accounts
        }
    };
    // 6. Hash all signers before output owners: cache hits deduplicate signers.
    proof_inputs.fill_owner_signer_hashes(
        transact_accounts.payer,
        transact_accounts.owner_signers,
        &mut owner_hashes,
    )?;
    // 7. Derive the circuit-specific fixed-width output-owner commitment.
    proof_inputs.fill_output_owner_pk_hashes(
        ix.circuit.output_owner_mode(),
        &resolved_outputs,
        &mut owner_hashes,
    )?;

    // 8. Process sol and spl transfers.
    proof_inputs.assign_public_amounts_and_assets(
        &ix.interface_transfers,
        &transact_accounts.settlements,
        usize::from(ix.circuit.num_public_asset_slots()),
    )?;
    // 9. Resolve each input tree's roots, queue its nullifiers and create its PDAs.
    let input_tree_sequences = apply_input_trees(&mut transact_accounts, &ix, &mut proof_inputs)?;
    // 10. Append new utxo hashes.
    let tree_write = apply_output_tree(transact_accounts.output_tree, &ix, clock.slot)?;
    proof_inputs.assign_output_tree_id(tree_write.output_tree_id);

    let tag = [instruction as u8];
    let external_data_hash = hash_external_data(
        &tag,
        external_data_prefix,
        &ix,
        &transact_accounts.settlements,
        &resolved_outputs,
    )?;
    proof_inputs.assign_external_data_hash(external_data_hash);
    proof_inputs.ensure_complete()?;

    TransactProof::new(&ix, &proof_inputs).verify()?;

    settle_interface_transfers(&ix.interface_transfers, &transact_accounts.settlements)?;

    let event = build_transact_event(tree_write, &input_tree_sequences);
    emit_event(EventKind::Transact, &event)
}

#[inline(never)]
pub fn hash_external_data<'a>(
    tag: &'a [u8; 1],
    external_data_prefix: &'a [u8],
    ix: &TransactIxDataRef<'_>,
    settlements: &'a [Settlement<'a>],
    resolved_outputs: &'a [ResolvedOutput<'_>],
) -> Result<[u8; 32], ProgramError> {
    let mut preimage = ExternalDataPreimage::new(tag, external_data_prefix);
    for settlement in settlements {
        let [asset, user] = settlement.committed_accounts();
        preimage
            .push_settlement(asset.address().as_array(), user.address().as_array())
            .map_err(caused_by(ShieldedPoolError::TooManyExternalDataHashSlices))?;
    }
    for (output, resolved) in ix.outputs.iter().zip(resolved_outputs) {
        preimage
            .push_owner_tag(&output.owner_tag, &resolved.owner_tag)
            .map_err(caused_by(ShieldedPoolError::TooManyExternalDataHashSlices))?;
    }
    preimage
        .finish()
        .map_err(caused_by(ShieldedPoolError::TooManyExternalDataHashSlices))
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
    check_field_elements(
        ix.inputs.iter().map(|input| &input.nullifier_hash),
        "input nullifier",
        ShieldedPoolError::NonCanonicalInputNullifier,
    )?;
    check_field_elements(
        ix.outputs.iter().map(|output| output.utxo_hash),
        "output utxo hash",
        ShieldedPoolError::NonCanonicalOutputUtxoHash,
    )?;
    check_field_element(
        ix.private_tx_hash,
        "private tx hash",
        None,
        ShieldedPoolError::NonCanonicalPrivateTxHash,
    )
}
