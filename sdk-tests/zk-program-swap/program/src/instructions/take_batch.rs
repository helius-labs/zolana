use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::aggregate_transact::AggregateTransactIxData;

use crate::{
    error::SwapError,
    instructions::{
        shared::{check_within_window, cpi_spp_aggregate_transact_signed},
        take::{TakeProof, TakePublicInput},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
};

/// Fills that settle against one recursive proof.
///
/// The swap circuit is not aggregated. The take circuit binds exactly one
/// order, so every leg keeps its own take proof and only the SPP legs batch.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TakeBatchIxData {
    /// One proof per leg, in leg order.
    #[wincode(with = "containers::Vec<TakeProof, FixIntLen<u8>>")]
    pub take_proofs: Vec<TakeProof>,
    pub aggregate: AggregateTransactIxData,
}

#[inline(never)]
#[profile]
pub fn process_take_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;

    let TakeBatchIxData {
        take_proofs,
        aggregate,
    } = wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;
    // Position pairs a proof with the leg it authorizes. A shorter proof vector
    // would leave the trailing legs unauthorized.
    if take_proofs.len() != aggregate.legs.len() {
        return Err(SwapError::TakeProofCountMismatch.into());
    }

    let clock = Clock::get()?;
    for (proof, leg) in take_proofs.iter().zip(&aggregate.legs) {
        check_within_window(clock.unix_timestamp, leg.expiry_unix_ts)?;
        verify_groth16(
            CompressedGroth16Proof {
                a: &proof.proof_a,
                b: &proof.proof_b,
                c: &proof.proof_c,
                commitment: None,
            },
            TakePublicInput {
                private_tx_hash: &leg.private_tx_hash,
                expiry: leg.expiry_unix_ts,
            }
            .hash()?,
            &crate::verifying_keys::take::VERIFYINGKEY,
        )?;
    }

    let aggregate_bytes = aggregate
        .serialize()
        .map_err(|_| SwapError::SerializationFailed)?;
    let spp_accounts = iter.remaining()?;
    cpi_spp_aggregate_transact_signed(spp_accounts, &aggregate_bytes)
}
