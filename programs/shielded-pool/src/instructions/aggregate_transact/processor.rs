use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_hasher::{hash_chain::create_hash_chain_from_slice, primitives::hash_bytes};
use zolana_interface::{
    error::ShieldedPoolError,
    event::EventKind,
    instruction::instruction_data::{
        aggregate_transact::{AggregateTransactIxDataRef, EMPTY_LEG_COMMITMENT, EMPTY_LEG_PROOF},
        transact::{CircuitId, ExternalDataHash, TransactIxDataRef},
    },
    verifying_keys::{AggregateCircuitId, MAX_AGGREGATE_BATCH},
};

use crate::instructions::{
    event::emit_general_event,
    shared::{check_not_expired, collect_forester_fee},
    transact::{
        account::{RingTransactAccounts, TransactAccounts},
        event::{build_transact_event, resolve_outputs},
        interface_transfer::{resolve_interface_transfers, settle_interface_transfers},
        tree::{apply_input_tree, apply_output_tree},
        verify::{OwnerHashCache, TransactProof, TransactProofInputs},
    },
    verifier,
};

/// Payer, input tree, output tree, program id, system program. A ring leg adds
/// its ring config, and any leg adds its owner signers and settlement accounts.
const MIN_LEG_ACCOUNTS: usize = 5;

/// Every leg runs the `transact` pipeline except its own pairing. Leg public
/// input hashes chain in batch order and the outer proof is verified once.
#[inline(never)]
#[profile]
pub fn process_aggregate_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = AggregateTransactIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    validate_batch(&ix)?;

    // Checked before any leg settles, so a list that does not split cannot
    // leave earlier legs applied.
    let mut declared = 0usize;
    for count in &ix.leg_account_counts {
        let count = usize::from(*count);
        if count < MIN_LEG_ACCOUNTS {
            return Err(ShieldedPoolError::InvalidAggregateBatch.into());
        }
        declared += count;
    }
    // One trailing account past the declared total is the registry for the
    // outer key. It must satisfy the address commitment or the batch is
    // rejected. One account serves the whole batch because the selector fixes
    // one outer key.
    #[cfg(feature = "vk-registry")]
    let (vk_registry, accounts) = if accounts.len() == declared + 1 {
        let (registry, rest) = accounts
            .split_last_mut()
            .ok_or(ShieldedPoolError::InvalidAggregateBatch)?;
        (Some(&*registry), rest)
    } else {
        (None, accounts)
    };
    if declared != accounts.len() {
        return Err(ShieldedPoolError::InvalidAggregateBatch.into());
    }

    let clock = Clock::get()?;
    let mut leg_hashes = [[0u8; 32]; MAX_AGGREGATE_BATCH as usize];
    let mut rest = accounts;

    for (index, (leg, count)) in ix.legs.iter().zip(&ix.leg_account_counts).enumerate() {
        let (leg_accounts, remaining) = rest.split_at_mut(usize::from(*count));
        rest = remaining;
        leg_hashes[index] = settle_leg(leg_accounts, leg, ix.circuit, &clock)?;
    }

    let aggregate_hash = create_hash_chain_from_slice(&leg_hashes[..ix.legs.len()])?;
    let verifying_key = ix
        .circuit
        .verifying_key()
        .ok_or(ShieldedPoolError::InvalidAggregateBatch)?;
    let statement = verifier::Groth16Statement {
        proof: verifier::CompressedGroth16Proof {
            a: &ix.proof.a,
            b: &ix.proof.b,
            c: &ix.proof.c,
            commitment: Some((
                &ix.bsb22_commitment.commitment,
                &ix.bsb22_commitment.commitment_pok,
            )),
        },
        public_input_hash: aggregate_hash,
        verifying_key,
        encoding_err: ShieldedPoolError::InvalidTransactProofEncoding,
        verify_err: ShieldedPoolError::AggregateProofVerificationFailed,
    };
    #[cfg(feature = "vk-registry")]
    {
        // The selector fixes one outer key, so one spec serves the whole batch.
        let spec =
            zolana_interface::verifying_keys::registry_spec::vk_registry_spec_for(verifying_key)
                .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?;
        statement.verify_registered(vk_registry, spec)
    }
    #[cfg(not(feature = "vk-registry"))]
    statement.verify()
}

/// The selector names the outer verifying key, so a mismatch is rejected before
/// any pairing runs.
fn validate_batch(ix: &AggregateTransactIxDataRef<'_>) -> ProgramResult {
    if !ix.circuit.is_supported() || ix.circuit.verifying_key().is_none() {
        return Err(ShieldedPoolError::InvalidAggregateBatch.into());
    }
    if ix.legs.len() != usize::from(ix.circuit.batch)
        || ix.leg_account_counts.len() != ix.legs.len()
    {
        return Err(ShieldedPoolError::InvalidAggregateBatch.into());
    }
    for leg in &ix.legs {
        if !ix.circuit.accepts_leg(leg.circuit) {
            return Err(ShieldedPoolError::MismatchedCircuitType.into());
        }
        if usize::from(leg.circuit.num_inputs()) != leg.inputs.len()
            || usize::from(leg.circuit.num_outputs()) != leg.outputs.len()
            || !leg.circuit.is_supported()
        {
            return Err(ShieldedPoolError::InvalidTransactShape.into());
        }
        // A leg's proof is not part of the statement, so a non-zero value would
        // be unconstrained instruction data.
        if leg.proof != EMPTY_LEG_PROOF {
            return Err(ShieldedPoolError::AggregateLegCarriesProof.into());
        }
        // The inner commitment lives in the outer witness, so a leg carrying one
        // would be unconstrained too.
        if leg
            .circuit
            .bsb22_commitment()
            .is_some_and(|c| *c != EMPTY_LEG_COMMITMENT)
        {
            return Err(ShieldedPoolError::AggregateLegCarriesProof.into());
        }
    }
    Ok(())
}

/// Returns the public input hash the outer proof must chain.
#[inline(never)]
fn settle_leg(
    accounts: &mut [AccountView],
    leg: &TransactIxDataRef<'_>,
    circuit: AggregateCircuitId,
    clock: &Clock,
) -> Result<[u8; 32], ProgramError> {
    check_not_expired(leg.expiry_unix_ts, clock)?;

    let resolved_outputs = resolve_outputs(accounts, leg)?;
    let mut proof_inputs = Box::new(TransactProofInputs::new(leg.circuit));
    let mut owner_hashes = Box::new(OwnerHashCache::new());
    proof_inputs.fill_output_owner_pk_hashes(
        leg.circuit.output_owner_mode(),
        &resolved_outputs,
        &mut owner_hashes,
    )?;

    let transact_accounts = match leg.circuit {
        CircuitId::ConfidentialEddsa(..) => TransactAccounts::validate_and_parse(accounts, leg)?,
        CircuitId::RingEddsa(..) | CircuitId::RingAuthority(..) | CircuitId::RingP256(..) => {
            let (transact_accounts, ring_program_id) = RingTransactAccounts::validate_and_parse(
                accounts,
                leg,
                leg.circuit.is_authority(),
            )?;
            proof_inputs.assign_ring_program_id(hash_bytes(&ring_program_id)?);
            transact_accounts
        }
    };

    proof_inputs.fill_owner_signer_hashes(
        transact_accounts.payer,
        transact_accounts.owner_signers,
        &mut owner_hashes,
    )?;
    proof_inputs.assign_public_amounts_and_assets(
        &leg.interface_transfers,
        &transact_accounts.settlements,
        usize::from(leg.circuit.num_public_asset_slots()),
    )?;

    let input_tree_result = apply_input_tree(transact_accounts.input_tree, leg, &mut proof_inputs)?;
    let tree_write =
        apply_output_tree(transact_accounts.output_tree, leg, input_tree_result.inputs)?;

    let resolved_interface_transfers =
        resolve_interface_transfers(leg, &transact_accounts.settlements);
    // Solo discriminator, so the same proof verifies alone or batched.
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: circuit.kind.solo_tag(),
        expiry_unix_ts: leg.expiry_unix_ts,
        interface_transfers: &resolved_interface_transfers,
        data_hash: leg.data_hash,
        ring_data_hash: leg.ring_data_hash,
        tx_viewing_pk: leg.tx_viewing_pk,
        salt: leg.salt,
        outputs: &resolved_outputs,
        messages: &leg.messages,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::AggregateProofVerificationFailed)?;
    proof_inputs.assign_external_data_hash(external_data_hash);
    proof_inputs.ensure_complete()?;

    let leg_hash = TransactProof::new(leg, &proof_inputs).public_input_hash()?;

    settle_interface_transfers(&leg.interface_transfers, &transact_accounts.settlements)?;
    collect_forester_fee(
        transact_accounts.payer,
        transact_accounts.input_tree,
        leg.inputs.len() as u64,
        input_tree_result.zkp_batch_size,
    )?;

    let event = build_transact_event(
        leg,
        &transact_accounts.settlements,
        tree_write,
        &resolved_outputs,
    );
    emit_general_event(EventKind::Transact, event)?;

    Ok(leg_hash)
}
