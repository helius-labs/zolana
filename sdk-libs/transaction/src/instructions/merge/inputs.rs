use zolana_keypair::ShieldedAddress;

use super::{MergeProofInputs, MAX_MERGE_INPUTS, MERGE_SUPPORTED_INPUT_COUNTS};
use crate::{error::TransactionError, utxo::SppProofInputUtxo, Mint, WalletUtxo};

pub fn merge_padded_input_count(real_inputs: usize) -> Option<usize> {
    MERGE_SUPPORTED_INPUT_COUNTS
        .iter()
        .copied()
        .filter(|supported| *supported >= real_inputs)
        .min()
}

pub(crate) fn validate_merge_inputs(
    inputs: &[WalletUtxo],
    check: impl Fn(usize, &WalletUtxo) -> Result<(), TransactionError>,
) -> Result<MergeInputs, TransactionError> {
    if inputs.is_empty() {
        return Err(TransactionError::NoInputs);
    }
    let padded_input_count =
        merge_padded_input_count(inputs.len()).ok_or(TransactionError::TooManyInputs {
            got: inputs.len(),
            max: MAX_MERGE_INPUTS,
        })?;

    let asset = inputs.first().ok_or(TransactionError::NoInputs)?.utxo.asset;
    let mut total = 0u64;
    for (index, input_utxo) in inputs.iter().enumerate() {
        if input_utxo.utxo.asset != asset {
            return Err(TransactionError::MergeInputAssetMismatch { index });
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

pub(crate) fn validate_merge_owner(
    sender: &ShieldedAddress,
    inputs: &[WalletUtxo],
) -> Result<(), TransactionError> {
    let owner = sender.signing_pubkey;
    let owner_rail = owner.curve()?;
    for (index, input_utxo) in inputs.iter().enumerate() {
        if input_utxo.utxo.owner.curve()? != owner_rail {
            return Err(TransactionError::MergeInputRailMismatch { index });
        }
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

pub(crate) fn pad_with_dummies(
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
    if dummy_nullifiers.len() != want {
        return Err(TransactionError::IncompleteDerivation {
            got: dummy_nullifiers.len(),
            want,
        });
    }
    let tree_id = inputs.first().ok_or(TransactionError::NoInputs)?.tree_id;
    for nullifier in dummy_nullifiers {
        let mut input = SppProofInputUtxo::dummy(tree_id)?;
        input.nullifier = *nullifier;
        inputs.push(input);
    }
    Ok(())
}

impl MergeProofInputs {
    pub fn input_utxo_hashes(&self) -> Result<Vec<&SppProofInputUtxo>, TransactionError> {
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

    pub fn dummy_nullifiers(&self) -> Vec<[u8; 32]> {
        self.input_utxos
            .iter()
            .filter(|input| input.is_dummy())
            .map(|input| input.nullifier)
            .collect()
    }
}
