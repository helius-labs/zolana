//! Batch incarnation of make: compose hub (no solo verify).

use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::SwapError,
    instructions::{
        make::{MakeIxData, MarkerData},
        shared::{compose_ix_data, cpi_spp_compose_signed},
    },
};

const ORDER_OUTPUT_INDEX: usize = 1;

#[inline(never)]
#[profile]
pub fn process_make_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let maker_pubkey = *iter.next_signer_mut("payer")?.address().as_array();

    let MakeIxData {
        proof,
        mut transact,
    } = wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

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

    let foreign_pi = transact.private_tx_hash;
    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let compose = compose_ix_data(
        &foreign_pi,
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &transact_bytes,
    );
    cpi_spp_compose_signed(iter.remaining()?, &compose)
}
