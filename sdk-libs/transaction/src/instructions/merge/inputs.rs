use zolana_keypair::ShieldedAddress;

use super::{merge_circuit_width, MergeProofInputs, MAX_MERGE_INPUTS};
use crate::{
    error::TransactionError, instructions::transact::real_slot_after_dummy,
    utxo::SppProofInputUtxo, Mint, WalletUtxo,
};

pub(crate) fn validate_merge_inputs(
    inputs: &[WalletUtxo],
    check: impl Fn(usize, &WalletUtxo) -> Result<(), TransactionError>,
) -> Result<MergeInputs, TransactionError> {
    if inputs.is_empty() {
        return Err(TransactionError::NoInputs);
    }
    let padded_input_count =
        merge_circuit_width(inputs.len()).ok_or(TransactionError::TooManyInputs {
            got: inputs.len(),
            max: MAX_MERGE_INPUTS,
        })?;

    let first = inputs.first().ok_or(TransactionError::NoInputs)?;
    let (asset, tree_id) = (first.utxo.asset, first.tree_id);
    validate_merge_asset(asset)?;
    let mut total = 0u64;
    for (index, input_utxo) in inputs.iter().enumerate() {
        if input_utxo.utxo.asset != asset {
            return Err(TransactionError::MergeInputAssetMismatch { index });
        }
        // A merge resolves the roots of one input tree.
        if input_utxo.tree_id != tree_id {
            return Err(TransactionError::MergeInputTreeMismatch { index });
        }
        check(index, input_utxo)?;
        total = total
            .checked_add(input_utxo.utxo.amount)
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
    }
    Ok(MergeInputs {
        asset,
        total,
        padded_input_count,
    })
}

fn validate_merge_asset(asset: Mint) -> Result<(), TransactionError> {
    // SOL has a zero mint address but a nonzero Poseidon asset identity.
    if crate::instructions::transact::asset_field(&asset.asset)? == [0; 32] {
        return Err(TransactionError::ZeroMergeAsset);
    }
    Ok(())
}

/// A merge preserves one common committed ring-data hash. Missing means zero.
/// Construction may infer that hash, while an already-built witness must match it.
pub fn merge_ring_data_hash(
    mut inputs: impl Iterator<Item = (usize, Option<[u8; 32]>)>,
    output_override: Option<[u8; 32]>,
) -> Result<Option<[u8; 32]>, TransactionError> {
    let (_, first) = inputs.next().ok_or(TransactionError::NoInputs)?;
    let expected = first.unwrap_or_default();
    if !zolana_hasher::primitives::is_canonical_bn254_scalar_be(&expected)
        || output_override
            .is_some_and(|hash| !zolana_hasher::primitives::is_canonical_bn254_scalar_be(&hash))
    {
        return Err(TransactionError::NonCanonicalField);
    }
    for (index, hash) in inputs {
        let hash = hash.unwrap_or_default();
        if !zolana_hasher::primitives::is_canonical_bn254_scalar_be(&hash) {
            return Err(TransactionError::NonCanonicalField);
        }
        if hash != expected {
            return Err(TransactionError::MergeInputRingDataMismatch { index });
        }
    }
    if output_override.is_some_and(|hash| hash != expected) {
        return Err(TransactionError::MergeOutputRingDataMismatch);
    }
    Ok((expected != [0; 32]).then_some(expected))
}

pub(crate) fn validate_merge_owner(
    sender: &ShieldedAddress,
    inputs: &[WalletUtxo],
) -> Result<(), TransactionError> {
    let owner = sender.signing_pubkey;
    for (index, input_utxo) in inputs.iter().enumerate() {
        if input_utxo.utxo.owner != owner {
            return Err(TransactionError::MergeInputOwnerMismatch { index });
        }
        if input_utxo.nullifier_pubkey != sender.nullifier_pubkey {
            return Err(TransactionError::MergeInputNullifierKeyMismatch { index });
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct MergeInputs {
    pub asset: Mint,
    pub total: u64,
    pub padded_input_count: usize,
}

/// Pad with one compact slot per entry of `dummy_nullifiers`, the slot's
/// derived merge dummy nullifier. A compact slot publishes 0, while the
/// circuit still proves the derived nullifier absent.
pub(crate) fn pad_with_compact(
    inputs: &mut Vec<SppProofInputUtxo>,
    padded_input_count: usize,
    dummy_nullifiers: &[[u8; 32]],
) -> Result<(), TransactionError> {
    let want =
        padded_input_count
            .checked_sub(inputs.len())
            .ok_or(TransactionError::TooManyInputs {
                got: inputs.len(),
                max: padded_input_count,
            })?;
    let tree_id = inputs.first().ok_or(TransactionError::NoInputs)?.tree_id;
    if dummy_nullifiers.len() != want {
        return Err(TransactionError::IncompleteDerivation {
            got: dummy_nullifiers.len(),
            want,
        });
    }
    for nullifier in dummy_nullifiers {
        let mut input = SppProofInputUtxo::compact(tree_id)?;
        input.nullifier = *nullifier;
        inputs.push(input);
    }
    Ok(())
}

impl MergeProofInputs {
    pub fn input_utxo_hashes(&self) -> Result<Vec<&SppProofInputUtxo>, TransactionError> {
        validate_merge_asset(self.output_utxo.asset)?;
        merge_ring_data_hash(
            self.input_utxos
                .iter()
                .enumerate()
                .filter(|(_, input)| !input.is_dummy())
                .map(|(index, input)| (index, input.ring_data_hash)),
            Some(self.output_utxo.ring_data_hash.unwrap_or_default()),
        )?;
        self.input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .enumerate()
            .map(|(index, input_utxo)| {
                let has_disqualifying_data = match self.ring_program_id {
                    Some(_) => {
                        input_utxo.data_hash.is_some() || input_utxo.utxo.data.utxo_data().is_some()
                    }
                    None => {
                        input_utxo.data_hash.is_some()
                            || input_utxo.ring_data_hash.is_some()
                            || !input_utxo.utxo.data.is_empty()
                    }
                };
                if has_disqualifying_data {
                    return Err(TransactionError::MergeInputHasData { index });
                }
                Ok(input_utxo)
            })
            .collect()
    }

    /// SPP fills compact padding back in at the end and picks the circuit from
    /// the sent count, so compact padding must come last and a merge carrying
    /// it must be exactly as wide as its sent inputs select.
    pub fn check_padding(&self) -> Result<(), TransactionError> {
        if let Some(index) =
            real_slot_after_dummy(self.input_utxos.iter().map(SppProofInputUtxo::is_compact))
        {
            return Err(TransactionError::InputAfterCompactPadding { index });
        }
        let width = self.input_utxos.len();
        let sent = self
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .count();
        if sent != width && merge_circuit_width(sent) != Some(width) {
            return Err(TransactionError::CompactMergeWidthMismatch { sent, width });
        }
        Ok(())
    }

    /// The nullifiers to fetch non-inclusion witnesses for besides the real
    /// spends: every padding slot, compact or not. Compact padding publishes 0
    /// but proves its derived nullifier absent.
    pub fn dummy_nullifiers(&self) -> Vec<[u8; 32]> {
        self.input_utxos
            .iter()
            .filter(|input| input.is_dummy())
            .map(|input| input.nullifier)
            .collect()
    }
}
