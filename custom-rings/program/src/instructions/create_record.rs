use custom_ring_interface::CreateRecordIxData;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::instruction_data::transact::InputUtxo;
use zolana_ring_policy::{Member, Record, RecordKind, RecordState};

use crate::{
    error::CustomRingError,
    instructions::policy_shared::{
        cpi_spp_records_signed, record_address_input, MutationAccounts, RecordTransition,
    },
};

/// The address slot inserts the derived address, a second create for the same
/// `(kind, member)` fails in SPP.
#[inline(never)]
pub fn process_create_record_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: CreateRecordIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let kind = RecordKind::try_from(ix.kind).map_err(|_| CustomRingError::InvalidRecordKind)?;
    let state = RecordState::try_from(ix.state).map_err(|_| CustomRingError::InvalidRecordState)?;
    let member = Member::from_bytes(ix.member).map_err(|_| CustomRingError::InvalidPolicyMember)?;

    let parsed = MutationAccounts::validate_and_parse(program_id, accounts, kind)?;
    parsed.check_mutator(kind, &member)?;

    let (address_utxo_hash, address) = record_address_input(&parsed.owner, kind, &member)?;
    let transact = RecordTransition {
        record: Record {
            kind,
            member,
            state,
            version: 0,
            payload_hash: ix.payload_hash,
        },
        input: InputUtxo {
            nullifier_hash: address,
            nullifier_tree_root_index: ix.nullifier_tree_root_index,
            utxo_tree_root_index: ix.utxo_tree_root_index,
        },
        input_hash: [0u8; 32],
        address_utxo_hash,
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
