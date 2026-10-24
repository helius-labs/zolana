use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::transact::{canonical_shape, SppProofInputs, SppProofOutputUtxo},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
        Blinding,
    },
};

use crate::err;

/// The private transaction blinding and the first `n_outputs` output blindings
/// SPP derives from `first_nullifier` and `blinding_seed`.
pub fn transaction_blindings(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
    n_outputs: u32,
) -> Result<([u8; 32], Vec<Blinding>)> {
    let seed = derive_output_blinding_seed(first_nullifier, blinding_seed).map_err(err)?;
    let outputs = (0..n_outputs)
        .map(|index| derive_transact_output_blinding(first_nullifier, &seed, index).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    let private_tx_blinding =
        derive_private_tx_blinding(first_nullifier, blinding_seed).map_err(err)?;
    Ok((private_tx_blinding, outputs))
}

/// Appends compact output padding to `proof_inputs` up to the cheapest SPP
/// shape that fits its inputs and outputs. SPP has no circuit for some of the
/// real shapes here (1-in/1-out cancel and withdraw, 2-in/3-out settle), so the
/// spare slots are compact: each publishes hash 0, the instruction leaves it
/// out, and the private transaction hash the example circuits commit to does
/// not change. A compact slot's blinding is the transaction's derivation for
/// its index, which SPP checks for every output.
pub fn pad_spp_outputs(mut proof_inputs: SppProofInputs) -> Result<SppProofInputs> {
    let shape = canonical_shape(
        proof_inputs.input_utxos.len(),
        proof_inputs.output_utxos.len(),
    )
    .map_err(err)?;
    let first_nullifier = proof_inputs.first_nullifier().map_err(err)?;
    let seed =
        derive_output_blinding_seed(&first_nullifier, &proof_inputs.blinding_seed).map_err(err)?;
    for index in proof_inputs.output_utxos.len()..shape.n_outputs() {
        let index = u32::try_from(index).map_err(err)?;
        proof_inputs.output_utxos.push(SppProofOutputUtxo {
            blinding: derive_transact_output_blinding(&first_nullifier, &seed, index)
                .map_err(err)?,
            compact: true,
            ..Default::default()
        });
    }
    Ok(proof_inputs)
}

pub(crate) fn check_output_utxo(
    label: &str,
    output: &SppProofOutputUtxo,
    mint: &Address,
    amount: u64,
) -> Result<ShieldedAddress> {
    let owner = output
        .owner_address
        .ok_or_else(|| err(format!("{label} owner address missing")))?;
    if &output.asset.asset != mint {
        return Err(err(format!("{label} asset mismatch")));
    }
    if output.amount != amount {
        return Err(err(format!("{label} amount mismatch")));
    }
    if output.data_hash.is_some()
        || output.ring_data_hash.is_some()
        || output.ring_program_id.is_some()
    {
        return Err(err(format!(
            "{label} must not carry data or ring commitments"
        )));
    }
    Ok(owner)
}

/// Like [`check_output_utxo`], for a pool note: the data hash must commit
/// exactly `u64_right_align(booked)` and ring commitments stay forbidden.
pub(crate) fn check_pool_output_utxo(
    label: &str,
    output: &SppProofOutputUtxo,
    mint: &Address,
    amount: u64,
    booked: u64,
) -> Result<ShieldedAddress> {
    let owner = output
        .owner_address
        .ok_or_else(|| err(format!("{label} owner address missing")))?;
    if &output.asset.asset != mint {
        return Err(err(format!("{label} asset mismatch")));
    }
    if output.amount != amount {
        return Err(err(format!("{label} amount mismatch")));
    }
    if output.data_hash
        != Some(dynamic_swap_program::instructions::shared::u64_right_align(
            booked,
        ))
    {
        return Err(err(format!("{label} data hash does not commit booked")));
    }
    if output.ring_data_hash.is_some() || output.ring_program_id.is_some() {
        return Err(err(format!("{label} must not carry ring commitments")));
    }
    if booked > amount {
        return Err(err(format!("{label} booked exceeds amount")));
    }
    Ok(owner)
}
