use solana_address::Address;
use zolana_interface::MAX_INPUT_TREES;

use crate::{
    error::TransactionError,
    instructions::transact::{shape::Shape, SppProofInputs},
    utxo::SppProofInputUtxo,
};

/// Pad inputs to the shape with random dummies without moving existing slots.
pub fn pad_input_utxos(
    input_utxos: &mut Vec<SppProofInputUtxo>,
    shape: Shape,
) -> Result<(), TransactionError> {
    pad_inputs(input_utxos, shape, false)
}

/// Pad inputs to the shape without moving existing slots.
///
/// Steps:
/// 1. Reject an input count above the shape's capacity.
/// 2. Collect the declared tree IDs and select the padding tree.
/// 3. Append padding until the input count matches the shape.
pub(super) fn pad_inputs(
    input_utxos: &mut Vec<SppProofInputUtxo>,
    shape: Shape,
    compact: bool,
) -> Result<(), TransactionError> {
    // 1. Reject an input count above the shape's capacity.
    if input_utxos.len() > shape.n_inputs() {
        return Err(TransactionError::TooManyInputs {
            got: input_utxos.len(),
            max: shape.n_inputs(),
        });
    }
    // 2. Select the padding tree. Random dummy commitments and nullifiers use
    //    the last declared tree, as the prover does for those slots. Compact
    //    padding takes the first tree: SPP reads its omitted tree index as 0.
    let tree_ids = input_tree_ids(input_utxos)?;
    let padding_tree_id = *if compact {
        tree_ids.first()
    } else {
        tree_ids.last()
    }
    .ok_or(TransactionError::NoInputs)?;
    // 3. Append padding without moving existing slots.
    while input_utxos.len() < shape.n_inputs() {
        input_utxos.push(if compact {
            SppProofInputUtxo::compact(padding_tree_id)?
        } else {
            SppProofInputUtxo::dummy(padding_tree_id)?
        });
    }
    Ok(())
}

/// Collect the real inputs' tree IDs in first-use order.
///
/// Steps:
/// 1. Collect distinct tree IDs, ignoring dummies: a dummy joins a declared tree.
/// 2. Require at least one real input.
/// 3. Reject more than [`MAX_INPUT_TREES`] declared trees.
pub(super) fn input_tree_ids(inputs: &[SppProofInputUtxo]) -> Result<Vec<u16>, TransactionError> {
    // 1. Collect distinct tree IDs in first-use order, ignoring dummies.
    let mut tree_ids: Vec<u16> = Vec::with_capacity(1);
    for input_utxo in inputs.iter().filter(|input_utxo| !input_utxo.is_dummy()) {
        if !tree_ids.contains(&input_utxo.tree_id) {
            tree_ids.push(input_utxo.tree_id);
        }
    }
    // 2. Require at least one real input.
    if tree_ids.is_empty() {
        return Err(TransactionError::NoInputs);
    }
    // 3. Reject more trees than the proof supports.
    if tree_ids.len() > MAX_INPUT_TREES {
        return Err(TransactionError::TooManyInputTrees {
            got: tree_ids.len(),
            max: MAX_INPUT_TREES,
        });
    }
    Ok(tree_ids)
}

impl SppProofInputs {
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier())
    }

    /// The Solana signers the shielded pool lists as owner signers: the
    /// Ed25519 and PDA owners of real inputs and address slots, in slot order,
    /// then of outputs that carry data, deduplicated in that order. The circuit requires an output's owner to
    /// sign when its data hash is set. The fee payer is listed only when it is
    /// one of those owners.
    pub fn owner_signer_pubkeys(&self) -> Result<Vec<Address>, TransactionError> {
        let input_owners = self
            .input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .map(|input_utxo| &input_utxo.utxo.owner);
        let data_output_owners = self
            .output_utxos
            .iter()
            .filter(|output_utxo| {
                output_utxo
                    .data_hash
                    .is_some_and(|data_hash| data_hash != [0u8; 32])
            })
            .filter_map(|output_utxo| output_utxo.owner_address.as_ref())
            .map(|owner_address| &owner_address.signing_pubkey);
        let mut signers = Vec::new();
        let mut signer_hashes: Vec<[u8; 32]> = Vec::new();
        for owner in input_owners.chain(data_output_owners) {
            let address = Address::new_from_array(owner.confidential_view_tag()?);
            let hash = owner.owner_proof_input_hash()?;
            if signer_hashes.contains(&hash) {
                continue;
            }
            signer_hashes.push(hash);
            signers.push(address);
        }
        Ok(signers)
    }

    /// The owner-signed rails' public signer vector: every
    /// [`Self::owner_signer_pubkeys`] entry as its signer identity,
    /// zero-padded to `width`. The fee payer is not in it unless it is one of
    /// those owners, so paying never authorizes a spend.
    pub fn signer_pk_hashes(&self, width: usize) -> Result<Vec<[u8; 32]>, TransactionError> {
        let mut hashes = Vec::with_capacity(width);
        for signer in self.owner_signer_pubkeys()? {
            hashes.push(zolana_hasher::primitives::solana_owner_identity(
                signer.as_array(),
            )?);
        }
        if hashes.len() > width {
            return Err(TransactionError::UnsupportedShape {
                n_in: self.input_utxos.len(),
                n_out: self.output_utxos.len(),
            });
        }
        hashes.resize(width, [0u8; 32]);
        Ok(hashes)
    }

    /// The nullifiers of the slots that prove only non-inclusion, in slot
    /// order: every dummy (compact padding included), every cached input and
    /// every address slot, whose nullifier is the address. Compact padding
    /// publishes 0 but proves its derived nullifier absent. Every other slot
    /// is in [`Self::input_utxo_hashes`].
    pub fn dummy_nullifiers(&self) -> Vec<[u8; 32]> {
        self.input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.requires_inclusion())
            .map(|input_utxo| input_utxo.nullifier())
            .collect()
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<&SppProofInputUtxo>, TransactionError> {
        Ok(self
            .input_utxos
            .iter()
            .filter(|input_utxo| input_utxo.requires_inclusion())
            .collect())
    }
}
