use custom_ring_interface::{CompressedRegisterPublicInput, RegisterSpendIxData, HEAD_MAP_HEIGHT};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::instruction::instruction_data::transact::{InputUtxo, TreeContext};
use zolana_program::TransactInputs;
use zolana_ring_policy::{entry_nullifier, Member, SpendCounters, SpendRecord};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::load_head_map_root,
        policy_shared::{cpi_spp_namespace_signed, MutationAccounts, NamespaceWrite},
        verifier::verify_plain_groth16,
    },
    state::advance_head_map_root,
};

#[inline(never)]
pub fn process_register_spend_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: RegisterSpendIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let (head_account, mutation) = accounts
        .split_last_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !head_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    let parsed = MutationAccounts::validate_and_parse(program_id, mutation)?;
    if parsed.window_slots == 0 {
        return Err(CustomRingError::VelocityDisabled.into());
    }
    {
        let head = load_head_map_root(program_id, head_account)?;
        if head.root != ix.head_old_root {
            return Err(CustomRingError::StaleHeadMapRoot.into());
        }
        if head.next_index() != ix.head_next_index
            || ix.head_next_index >= (1u64 << HEAD_MAP_HEIGHT)
        {
            return Err(CustomRingError::InvalidHeadMapCursor.into());
        }
    }
    let member = Member::owner_tag(parsed.payer.address().as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    let address = parsed
        .owner
        .spend_address(&member, parsed.entries_tree_id)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let record = SpendRecord {
        member,
        version: 0,
        window: Clock::get()?.slot / parsed.window_slots,
        counters_commitment: SpendCounters::zero(&[])
            .commitment()
            .map_err(|_| CustomRingError::HashingFailed)?,
        blinding: ix.blinding,
    };
    let output_hash = record
        .utxo_hash(&parsed.owner, &address, parsed.entries_tree_id)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let genesis =
        entry_nullifier(&output_hash, &ix.blinding).map_err(|_| CustomRingError::HashingFailed)?;
    let public_input = CompressedRegisterPublicInput {
        head_old_root: &ix.head_old_root,
        head_new_root: &ix.head_new_root,
        member: member.as_bytes(),
        genesis: &genesis,
        new_index: ix.head_next_index,
    }
    .hash()
    .map_err(|_| CustomRingError::HashingFailed)?;
    verify_plain_groth16(
        &ix.head_proof,
        public_input,
        &custom_ring_interface::compressed_register_verifying_key::VERIFYINGKEY,
    )?;
    advance_head_map_root(head_account, &ix.head_old_root, ix.head_new_root, true)?;

    let content = record.to_output_data();
    let transact = NamespaceWrite {
        output_hash,
        content: &content,
        inputs: TransactInputs {
            inputs: vec![InputUtxo {
                nullifier_hash: address,
                tree_index: 0,
            }],
            tree_contexts: vec![TreeContext {
                nullifier_tree_root_index: ix.nullifier_tree_root_index,
                utxo_tree_root_index: ix.utxo_tree_root_index,
            }],
        },
        input_hash: [0u8; 32],
        address_nullifier: address,
        private_tx_blinding: ix.private_tx_blinding,
        proof: ix.proof,
    }
    .into_transact(&parsed.namespace_address)?;
    cpi_spp_namespace_signed(
        &parsed.namespace_address,
        parsed.namespace_bump,
        mutation,
        &transact,
    )
}
