use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::SwapError,
    instructions::{
        shared::cpi_spp_transact,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::make,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct MarkerData {
    pub order_utxo_hash: [u8; 32],
    pub maker_pubkey: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MakeProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MakeIxData {
    pub proof: MakeProof,
    pub transact: TransactIxData,
}

const ORDER_OUTPUT_INDEX: usize = 1;

#[inline(never)]
#[profile]
pub fn process_make_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let maker_pubkey = *iter.next_signer_mut("payer")?.address().as_array();

    let MakeIxData {
        proof,
        mut transact,
    } = wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        transact.private_tx_hash,
        &make::VERIFYINGKEY,
    )?;
    let order_utxo_hash = transact
        .outputs
        .get(ORDER_OUTPUT_INDEX)
        .ok_or(SwapError::InvalidInstructionData)?
        .utxo_hash;
    let [marker_message] = transact.messages.as_mut_slice() else {
        return Err(SwapError::InvalidMarkerMessage.into());
    };
    if !marker_message.data.is_empty() {
        return Err(SwapError::MarkerDataNotEmpty.into());
    }
    let marker = MarkerData {
        order_utxo_hash,
        maker_pubkey,
    };
    marker_message.data = borsh::to_vec(&marker).map_err(|_| SwapError::InvalidInstructionData)?;
    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;

    let spp_accounts = iter.remaining()?;
    cpi_spp_transact(spp_accounts, &transact_bytes)
}
