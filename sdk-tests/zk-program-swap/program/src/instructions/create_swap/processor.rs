use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::SwapError,
    instructions::{create_swap::verify::CreatePublicInput, shared::cpi_spp_transact},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct MarkerData {
    pub escrow_utxo_hash: [u8; 32],
    pub maker_pubkey: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

const ESCROW_OUTPUT_INDEX: usize = 1;

#[inline(never)]
#[profile]
pub fn process_create_swap(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let maker_pubkey = *iter.next_signer_mut("payer")?.address().as_array();

    let mut cursor = data;
    let proof =
        CreateProof::deserialize(&mut cursor).map_err(|_| SwapError::InvalidInstructionData)?;
    let source_asset_id =
        u64::deserialize(&mut cursor).map_err(|_| SwapError::InvalidInstructionData)?;
    let maker_address =
        <[u8; 65]>::deserialize(&mut cursor).map_err(|_| SwapError::InvalidInstructionData)?;
    let mut transact =
        TransactIxData::deserialize(cursor).map_err(|_| SwapError::InvalidInstructionData)?;

    CreatePublicInput {
        private_tx_hash: &transact.private_tx_hash,
        source_asset_id,
        maker_address: &maker_address,
    }
    .verify(&proof)?;

    let escrow_utxo_hash = *transact
        .output_utxo_hashes
        .get(ESCROW_OUTPUT_INDEX)
        .ok_or(SwapError::InvalidInstructionData)?;
    let marker = MarkerData {
        escrow_utxo_hash,
        maker_pubkey,
    };
    transact
        .output_ciphertexts
        .last_mut()
        .ok_or(SwapError::InvalidInstructionData)?
        .data = borsh::to_vec(&marker).map_err(|_| SwapError::InvalidInstructionData)?;
    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;

    let spp_accounts = iter.remaining()?;
    cpi_spp_transact(spp_accounts, &transact_bytes)
}
