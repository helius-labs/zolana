use zolana_hasher::primitives::hash_bytes;
use zolana_transaction::{Mint, SppProofOutputUtxo, WalletUtxo};

use super::transaction::SppTransactionBuilder;
use crate::{
    conversion::{to_bytes, FromCircuit},
    RelationError,
};

impl SppTransactionBuilder<'_> {
    pub(super) fn input_utxos(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<Vec<WalletUtxo>, RelationError> {
        let spent = self
            .checked
            .inputs
            .iter()
            .enumerate()
            .map(|(slot, hash)| {
                let hash = to_bytes(hash)?;
                if hash == [0u8; 32] {
                    return Ok(None);
                }
                self.records
                    .utxo(&hash)
                    .cloned()
                    .map(Some)
                    .ok_or(RelationError::Slot {
                        kind: "input",
                        slot,
                        problem: "is not an input of the proof inputs",
                    })
            })
            .collect::<Result<Vec<_>, RelationError>>()?;
        let first = spent
            .first()
            .and_then(Option::as_ref)
            .ok_or(RelationError::Violated(
                "input slot 0 must hold a real input: it is the first nullifier",
            ))?;
        if first.nullifier != *first_nullifier {
            return Err(RelationError::Violated(
                "the first nullifier is not slot 0's",
            ));
        }
        let mut tree_id = first.tree_id;
        spent
            .into_iter()
            .map(|input| match input {
                Some(input) => {
                    tree_id = input.tree_id;
                    Ok(input)
                }
                None => WalletUtxo::dummy(tree_id).map_err(RelationError::spp),
            })
            .collect()
    }

    pub(super) fn output_utxos(&self) -> Result<Vec<SppProofOutputUtxo>, RelationError> {
        self.checked
            .outputs
            .iter()
            .enumerate()
            .map(|(slot, checked)| {
                let problem = |problem| RelationError::Slot {
                    kind: "output",
                    slot,
                    problem,
                };
                let output = &checked.output;
                let owner = self
                    .records
                    .owner(&to_bytes(&output.owner)?)
                    .copied()
                    .ok_or(problem("has an owner no input names"))?;
                let asset_hash = to_bytes(&output.asset)?;
                let asset = match self.records.mint(&asset_hash) {
                    Some(mint) => *mint,
                    None if asset_hash == hash_bytes(Mint::SOL.asset.as_array())? => Mint::SOL,
                    None => return Err(problem("has an asset no input names")),
                };
                let amount = u64::from_circuit(&output.amount)
                    .map_err(|_| problem("has an amount that does not fit in u64"))?;
                let utxo =
                    SppProofOutputUtxo::new(asset, amount, owner).map_err(RelationError::spp)?;
                let data_hash = to_bytes(&output.data_hash)?;
                Ok(if data_hash == [0u8; 32] {
                    utxo
                } else {
                    utxo.with_utxo_data(output.data.clone().unwrap_or_default(), data_hash)
                })
            })
            .collect()
    }
}
