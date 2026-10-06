use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::transact::{Shape, SppProofOutputUtxo},
    utxo::derive_transact_output_blinding,
};

use crate::err;

/// SPP circuit shape of `create_escrow` and `settle`. Both create three
/// outputs, and SPP has no 3-output circuit, so the fourth output slot is
/// compact padding: it publishes hash 0, the instruction leaves it out, and the
/// private transaction hash the example circuits commit to does not change.
pub const SPP_SHAPE: Shape = Shape::IN2_OUT4;

/// Appends compact padding to `outputs` up to [`SPP_SHAPE`]. SPP checks every
/// output blinding against the transaction's derivation, padding included.
pub fn pad_spp_outputs(
    mut outputs: Vec<SppProofOutputUtxo>,
    first_nullifier: &[u8; 32],
    output_blinding_seed: &[u8; 32],
) -> Result<Vec<SppProofOutputUtxo>> {
    if outputs.len() > SPP_SHAPE.n_outputs() {
        return Err(err(format!(
            "{} outputs exceed the {} output slots of the SPP shape",
            outputs.len(),
            SPP_SHAPE.n_outputs()
        )));
    }
    for index in outputs.len()..SPP_SHAPE.n_outputs() {
        let index = u32::try_from(index).map_err(err)?;
        outputs.push(SppProofOutputUtxo {
            blinding: derive_transact_output_blinding(first_nullifier, output_blinding_seed, index)
                .map_err(err)?,
            compact: true,
            ..Default::default()
        });
    }
    Ok(outputs)
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
