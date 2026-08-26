use custom_ring_interface::UpdateRecordIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::instruction_data::transact::InputUtxo;
use zolana_ring_policy::{Member, Record, RecordKind, RecordState};

use crate::{
    error::CustomRingError,
    instructions::policy_shared::{
        cpi_spp_records_signed, record_spend_input, MutationAccounts, RecordTransition,
    },
};

/// Spends the live version and recreates the record at the same address with
/// the version raised by one, in one SPP transact.
#[inline(never)]
pub fn process_update_record_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdateRecordIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let kind = RecordKind::try_from(ix.kind).map_err(|_| CustomRingError::InvalidRecordKind)?;
    let spent_state =
        RecordState::try_from(ix.spent_state).map_err(|_| CustomRingError::InvalidRecordState)?;
    let state = RecordState::try_from(ix.state).map_err(|_| CustomRingError::InvalidRecordState)?;
    let member =
        Member::from_bytes(ix.member).map_err(|_| CustomRingError::InvalidPolicyMember)?;

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts)?;
    parsed.check_mutator(kind, &member)?;

    let spent = Record {
        kind,
        member,
        state: spent_state,
        version: ix.spent_version,
        payload_hash: ix.spent_payload_hash,
    };
    let (spent_hash, nullifier) = record_spend_input(&parsed.owner, &spent)?;
    let version = ix
        .spent_version
        .checked_add(1)
        .ok_or(CustomRingError::RecordVersionOverflow)?;
    let transact = RecordTransition {
        record: Record {
            kind,
            member,
            state,
            version,
            payload_hash: ix.payload_hash,
        },
        input: InputUtxo {
            nullifier_hash: nullifier,
            nullifier_tree_root_index: ix.nullifier_tree_root_index,
            utxo_tree_root_index: ix.utxo_tree_root_index,
        },
        input_hash: spent_hash,
        address_utxo_hash: [0u8; 32],
        proof: ix.proof,
    }
    .into_transact(&parsed.owner, &parsed.records_address)?;

    cpi_spp_records_signed(
        &parsed.records_address,
        parsed.records_bump,
        accounts,
        &transact,
    )
}
