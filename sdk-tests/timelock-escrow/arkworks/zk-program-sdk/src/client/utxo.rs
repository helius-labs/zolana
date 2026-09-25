use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, SppProofOutputUtxo, WalletUtxo};

use super::transaction::SppTransactionBuilder;
use crate::{
    circuit::Asset,
    conversion::{to_bytes, FromCircuit},
    RelationError,
};

impl SppTransactionBuilder<'_> {
    pub(super) fn input_utxos(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<Vec<WalletUtxo>, RelationError> {
        let spent =
            self.checked
                .inputs
                .iter()
                .enumerate()
                .filter_map(|(slot, hash)| match to_bytes(hash) {
                    Ok(hash) if hash == [0u8; 32] => None,
                    Ok(hash) => Some(self.records.utxo(&hash).cloned().ok_or(
                        RelationError::Slot {
                            kind: "input",
                            slot,
                            problem: "is not an input of the proof inputs",
                        },
                    )),
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>, RelationError>>()?;
        let first = spent.first().ok_or(RelationError::Violated(
            "a transaction spends at least one input",
        ))?;
        if first.nullifier != *first_nullifier {
            return Err(RelationError::Violated(
                "the first nullifier is not the first input's",
            ));
        }
        Ok(spent)
    }

    pub(super) fn output_utxos(
        &self,
        sender: &ShieldedAddress,
    ) -> Result<Vec<SppProofOutputUtxo>, RelationError> {
        let sender_hash = sender.owner_hash().map_err(RelationError::spp)?;
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
                let owner_hash = to_bytes(&output.owner.hash()?)?;
                let owner = match self.records.owner(&owner_hash) {
                    Some(owner) => *owner,
                    None if owner_hash == sender_hash => *sender,
                    None => return Err(problem("has an owner no input names")),
                };
                let asset = self
                    .mint(&output.asset)?
                    .ok_or(problem("has an asset no input names"))?;
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

    pub(super) fn mint(&self, asset: &Asset) -> Result<Option<Mint>, RelationError> {
        let asset_hash = to_bytes(&asset.hash()?)?;
        Ok(match self.records.mint(&asset_hash) {
            Some(mint) => Some(*mint),
            None if asset_hash == hash_bytes(Mint::SOL.asset.as_array())? => Some(Mint::SOL),
            None => None,
        })
    }
}
