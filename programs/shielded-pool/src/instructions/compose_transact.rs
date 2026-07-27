//! Batch incarnation: foreign policy proof + one pure-shielded transact, one hetero RLC.
//! Accounts: `foreign_vk` (packed), then pure-shielded transact accounts.

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
        instruction_data::transact::{ExternalDataHash, TransactIxDataRef},
        tag::InstructionTag,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    event::emit_general_event,
    shared::{check_not_expired, collect_forester_fee, tree_error},
    transact::{
        account::TransactAccounts,
        event::{build_transact_event, resolve_outputs},
        interface_transfer::{
            process_interface_transfers, resolve_interface_transfers, settle_interface_transfers,
        },
        tree::{apply_input_tree, apply_output_tree},
        validate_circuit_type,
        verify::{TransactProof, TransactProofInputs},
    },
    verifier::{batch_verify_compose, BatchProofItem},
};

/// Foreign prefix: public_input || a || b || c (standard rail only).
const FOREIGN_PREFIX: usize = 32 + 32 + 64 + 32;

#[inline(never)]
#[profile]
pub fn process_compose_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if data.len() <= FOREIGN_PREFIX {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (foreign_pi, rest) = data.split_at(32);
    let (fa, rest) = rest.split_at(32);
    let (fb, rest) = rest.split_at(64);
    let (fc, transact_body) = rest.split_at(32);

    let mut foreign_public_input = [0u8; 32];
    foreign_public_input.copy_from_slice(foreign_pi);
    let mut proof_a = [0u8; 32];
    proof_a.copy_from_slice(fa);
    let mut proof_b = [0u8; 64];
    proof_b.copy_from_slice(fb);
    let mut proof_c = [0u8; 32];
    proof_c.copy_from_slice(fc);

    let (foreign_vk_account, rest) = accounts
        .split_first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let foreign_vk_data = foreign_vk_account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;

    let ix = TransactIxDataRef::from_bytes(transact_body)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    validate_circuit_type(&ix, InstructionTag::Transact)?;
    if !ix.interface_transfers.is_empty() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let resolved_outputs = resolve_outputs(rest, &ix)?;
    let mut proof_inputs = TransactProofInputs::default();
    if ix.circuit.requires_input_signatures() {
        proof_inputs.check_input_signers(rest, &ix)?;
    }
    if ix.circuit.binds_output_owners() {
        proof_inputs.fill_output_owner_pk_hashes(&resolved_outputs)?;
    }
    let ta = TransactAccounts::validate_and_parse(rest, &ix)?;
    process_interface_transfers(
        &ix.interface_transfers,
        &ta.settlements,
        &mut proof_inputs,
        usize::from(ix.circuit.num_public_asset_slots()),
    )?;
    let resolved_itf = resolve_interface_transfers(&ix, &ta.settlements);

    let (inputs, zkp_batch_size) = {
        let addr = ta.input_tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *ta.input_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let inputs = apply_input_tree(&mut tree, &ix, addr, &mut proof_inputs)?;
        let zkp = tree.nullifer_tree().queue_batches.zkp_batch_size;
        (inputs, zkp)
    };
    let tree_write = {
        let addr = ta.output_tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *ta.output_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_output_tree(&mut tree, &ix, addr, inputs)?
    };

    proof_inputs.external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: InstructionTag::Transact as u8,
        expiry_unix_ts: ix.expiry_unix_ts,
        interface_transfers: &resolved_itf,
        data_hash: ix.data_hash,
        zone_data_hash: ix.zone_data_hash,
        tx_viewing_pk: ix.tx_viewing_pk,
        salt: ix.salt,
        outputs: &resolved_outputs,
        messages: &ix.messages,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    proof_inputs.payer_pubkey_hash = Sha256BE::hash(ta.payer.address().as_ref())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let spp_hash = TransactProof::new(&ix, &proof_inputs).public_input_hash_value()?;
    let spp_vk = ix
        .circuit
        .verifying_key()
        .ok_or(ShieldedPoolError::InvalidTransactShape)?;

    batch_verify_compose(
        foreign_vk_data.as_ref(),
        spp_vk,
        &BatchProofItem {
            a: proof_a,
            b: proof_b,
            c: proof_c,
            public_input_hash: foreign_public_input,
        },
        &BatchProofItem {
            a: ix.proof.a,
            b: ix.proof.b,
            c: ix.proof.c,
            public_input_hash: spp_hash,
        },
        ShieldedPoolError::InvalidTransactProofEncoding,
        ShieldedPoolError::TransactProofVerificationFailed,
    )?;
    drop(foreign_vk_data);

    settle_interface_transfers(&ix.interface_transfers, &ta.settlements)?;
    collect_forester_fee(
        ta.payer,
        ta.input_tree,
        ix.inputs.len() as u64,
        zkp_batch_size,
    )?;
    let event = build_transact_event(&ix, &ta.settlements, tree_write, &resolved_outputs);
    emit_general_event(EventKind::Transact, event)
}
