use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    error::ShieldedPoolError,
    event::EventKind,
    instruction::{
        instruction_data::transact::{CircuitId, ExternalDataHash, TransactIxDataRef},
        tag::InstructionTag,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    N_PUBLIC_SLOTS,
};
use zolana_tree::TreeAccount;

use super::{
    account::{TransactAccounts, ZoneTransactAccounts},
    event::{build_transact_event, resolve_outputs},
    interface_transfer::{
        process_interface_transfers, resolve_interface_transfers, settle_interface_transfers,
    },
    tree::{apply_input_tree, apply_output_tree},
};
use crate::instructions::{
    event::emit_general_event,
    hash::solana_pk_hash,
    shared::{check_not_expired, collect_forester_fee, tree_error},
    transact::verify::{TransactProof, TransactProofInputs},
};

#[inline(never)]
#[profile]
#[allow(clippy::field_reassign_with_default)]
pub fn process_transact_ix(
    accounts: &mut [AccountView],
    data: &[u8],
    instruction: InstructionTag,
) -> ProgramResult {
    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    validate_circuit_type(&ix, instruction)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let resolved_outputs = resolve_outputs(accounts, &ix)?;
    let mut proof_inputs = TransactProofInputs::default();
    if ix.circuit.requires_input_signatures() {
        proof_inputs.check_input_signers(accounts, &ix)?;
    }
    if ix.circuit.binds_output_owners() {
        proof_inputs.fill_output_owner_pk_hashes(&resolved_outputs)?;
    }
    let transact_accounts = match ix.circuit {
        CircuitId::ConfidentialEddsa(..) => TransactAccounts::validate_and_parse(accounts, &ix)?,
        CircuitId::ZoneEddsa(..) | CircuitId::ZoneAuthority(..) => {
            let (transact_accounts, zone_program_id) =
                ZoneTransactAccounts::validate_and_parse(accounts, &ix, ix.circuit.is_authority())?;
            proof_inputs.zone_program_id = solana_pk_hash(&zone_program_id)?;
            transact_accounts
        }
    };

    process_interface_transfers(
        &ix.interface_transfers,
        &transact_accounts.settlements,
        &mut proof_inputs,
        usize::from(ix.circuit.num_public_asset_slots()),
    )?;
    let resolved_interface_transfers =
        resolve_interface_transfers(&ix, &transact_accounts.settlements);

    let (inputs, zkp_batch_size) = {
        let input_tree_address = transact_accounts.input_tree.address().to_bytes();
        let mut input_tree = TreeAccount::from_account_view_mut(
            &mut *transact_accounts.input_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let inputs = apply_input_tree(&mut input_tree, &ix, input_tree_address, &mut proof_inputs)?;
        let zkp_batch_size = input_tree.nullifer_tree().queue_batches.zkp_batch_size;
        (inputs, zkp_batch_size)
    };
    let tree_write = {
        let output_tree_address = transact_accounts.output_tree.address().to_bytes();
        let mut output_tree = TreeAccount::from_account_view_mut(
            &mut *transact_accounts.output_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_output_tree(&mut output_tree, &ix, output_tree_address, inputs)?
    };

    proof_inputs.external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: instruction as u8,
        expiry_unix_ts: ix.expiry_unix_ts,
        interface_transfers: &resolved_interface_transfers,
        data_hash: ix.data_hash,
        zone_data_hash: ix.zone_data_hash,
        tx_viewing_pk: ix.tx_viewing_pk,
        salt: ix.salt,
        outputs: &resolved_outputs,
        messages: &ix.messages,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    proof_inputs.payer_pubkey_hash = Sha256BE::hash(transact_accounts.payer.address().as_ref())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    TransactProof::new(&ix, &proof_inputs).verify()?;

    settle_interface_transfers(&ix.interface_transfers, &transact_accounts.settlements)?;

    collect_forester_fee(
        transact_accounts.payer,
        transact_accounts.input_tree,
        ix.inputs.len() as u64,
        zkp_batch_size,
    )?;

    let event = build_transact_event(
        &ix,
        &transact_accounts.settlements,
        tree_write,
        &resolved_outputs,
    );
    emit_general_event(EventKind::Transact, event)
}

/// Validate the untrusted selector before it is allowed to drive account
/// parsing, proof-input layout, settlement limits, or verifying-key selection.
pub fn validate_circuit_type(
    ix: &TransactIxDataRef<'_>,
    instruction: InstructionTag,
) -> ProgramResult {
    let family_matches = match instruction {
        InstructionTag::Transact => matches!(ix.circuit, CircuitId::ConfidentialEddsa(..)),
        InstructionTag::ZoneTransact => matches!(ix.circuit, CircuitId::ZoneEddsa(..)),
        InstructionTag::ZoneAuthorityTransact => ix.circuit.is_authority(),
        _ => false,
    };
    if !family_matches {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    if usize::from(ix.circuit.num_inputs()) != ix.inputs.len()
        || usize::from(ix.circuit.num_outputs()) != ix.outputs.len()
        || usize::from(ix.circuit.num_public_asset_slots()) > N_PUBLIC_SLOTS
        || !ix.circuit.is_supported()
        || ix
            .inputs
            .iter()
            .any(|input| input.eddsa_signer_index == u8::MAX)
    // u8::MAX is a placeholder to mark that the UTXO is signed with by a p256 signature.
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    Ok(())
}
