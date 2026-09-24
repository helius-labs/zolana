use solana_address::Address;
use zolana_interface::MAX_INPUT_TREES;
use zolana_keypair::Curve;

use crate::{
    error::TransactionError,
    instructions::transact::{shape::Shape, SppProofInputs},
    utxo::SppProofInputUtxo,
};

/// Pad inputs to the shape without moving existing slots.
///
/// Steps:
/// 1. Reject an input count above the shape's capacity.
/// 2. Collect the declared tree IDs and select the last tree for padding.
/// 3. Append dummies until the input count matches the shape. For ordered
///    inputs, this extends the last tree's contiguous run.
pub fn pad_input_utxos(
    input_utxos: &mut Vec<SppProofInputUtxo>,
    shape: Shape,
) -> Result<(), TransactionError> {
    // 1. Reject an input count above the shape's capacity.
    if input_utxos.len() > shape.n_inputs() {
        return Err(TransactionError::TooManyInputs {
            got: input_utxos.len(),
            max: shape.n_inputs(),
        });
    }
    // 2. Select the last declared tree. Dummy commitments and nullifiers must
    //    use the same tree ID that the prover uses for those slots.
    let padding_tree_id = *input_tree_ids(input_utxos)?
        .last()
        .ok_or(TransactionError::NoInputs)?;
    // 3. Append dummies without moving existing slots.
    while input_utxos.len() < shape.n_inputs() {
        input_utxos.push(SppProofInputUtxo::dummy(padding_tree_id)?);
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

pub fn validate_input_tree_order(
    tree_ids: impl IntoIterator<Item = u16>,
) -> Result<(), TransactionError> {
    let mut seen = Vec::new();
    for (index, tree_id) in tree_ids.into_iter().enumerate() {
        if seen.last() == Some(&tree_id) {
            continue;
        }
        if seen.contains(&tree_id) {
            return Err(TransactionError::InterleavedInputTrees { index, tree_id });
        }
        seen.push(tree_id);
    }
    Ok(())
}

impl SppProofInputs {
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier())
    }

    /// Unique non-payer Ed25519 and PDA owners the proof binds as signers: the
    /// input owners in first-input order, then the owners of data-bearing
    /// outputs. The circuit requires a data-bearing output's owner to have
    /// signed, so a program PDA that owns such an output without spending an
    /// input takes an owner-signer slot too; the owning program flips its
    /// account to signer via CPI.
    pub fn owner_signer_pubkeys(&self) -> Result<Vec<Address>, TransactionError> {
        let input_owners = self
            .input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .map(|input_utxo| &input_utxo.utxo.owner);
        let data_output_owners = self
            .output_utxos
            .iter()
            .filter(|output| output.data_hash.is_some_and(|hash| hash != [0u8; 32]))
            .filter_map(|output| output.owner_address.as_ref())
            .map(|address| &address.signing_pubkey);
        let mut signers = Vec::new();
        let mut signer_hashes: Vec<[u8; 32]> = Vec::new();
        for owner in input_owners.chain(data_output_owners) {
            let address = match owner.curve()? {
                Curve::P256 => continue,
                Curve::Ed25519 | Curve::Pda => {
                    Address::new_from_array(owner.confidential_view_tag()?)
                }
            };
            let hash = owner.owner_proof_input_hash()?;
            if address == self.payer || signer_hashes.contains(&hash) {
                continue;
            }
            signer_hashes.push(hash);
            signers.push(address);
        }
        Ok(signers)
    }

    pub fn signer_pk_hashes(&self, width: usize) -> Result<Vec<[u8; 32]>, TransactionError> {
        let mut hashes = vec![zolana_hasher::primitives::solana_owner_identity(
            self.payer.as_array(),
        )?];
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

    pub fn dummy_nullifiers(&self) -> Vec<[u8; 32]> {
        self.input_utxos
            .iter()
            .filter(|input_utxo| input_utxo.is_dummy())
            .map(|input_utxo| input_utxo.nullifier())
            .collect()
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<&SppProofInputUtxo>, TransactionError> {
        validate_input_tree_order(self.input_utxos.iter().map(|input| input.tree_id))?;
        Ok(self
            .input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .collect())
    }
}
