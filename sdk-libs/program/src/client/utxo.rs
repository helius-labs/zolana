use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, SppProofOutputUtxo, WalletUtxo};

use super::transaction::SppTransactionBuilder;
use crate::{
    circuit::Asset,
    conversion::{to_bytes, FromCircuit, MintRecords, OwnerRecords, UtxoRecords},
    ClientError, ClientErrorKind, SlotKind,
};

impl SppTransactionBuilder<'_> {
    pub(super) fn input_utxos(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<Vec<WalletUtxo>, ClientError> {
        let spent = self
            .checked
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(slot, hash)| match to_bytes(hash) {
                Ok(hash) if hash == [0u8; 32] => {
                    if self.checked.preserve_input_slots {
                        Some(
                            crate::conversion::u16_value(&self.checked.output_tree_id)
                                .map_err(ClientErrorKind::Circuit)
                                .and_then(|tree| {
                                    WalletUtxo::dummy(tree).map_err(ClientErrorKind::Transaction)
                                }),
                        )
                    } else {
                        None
                    }
                }
                Ok(hash) => Some(
                    self.records
                        .get::<UtxoRecords>()
                        .and_then(|records| records.get(&hash))
                        .cloned()
                        .ok_or(ClientErrorKind::Slot {
                            kind: SlotKind::Input,
                            index: slot,
                            problem: "is not an input of the proof inputs",
                        }),
                ),
                Err(error) => Some(Err(ClientErrorKind::Circuit(error))),
            })
            .collect::<Result<Vec<_>, ClientErrorKind>>()?;
        let first = match self.checked.addresses.first() {
            Some(address) => to_bytes(&address.address)?,
            None => spent.first().ok_or(ClientErrorKind::NoInputs)?.nullifier,
        };
        if first != *first_nullifier {
            return Err(ClientErrorKind::TransactionMismatch(
                "the first nullifier is not the first input's",
            )
            .into());
        }
        Ok(spent)
    }

    pub(super) fn address_inputs(
        &self,
    ) -> Result<Vec<zolana_transaction::utxo::SppProofInputUtxo>, ClientError> {
        self.checked
            .addresses
            .iter()
            .map(|created| {
                let owner_hash = to_bytes(&created.owner.hash()?)?;
                let owner = self
                    .records
                    .get::<OwnerRecords>()
                    .and_then(|records| records.get(&owner_hash))
                    .ok_or(ClientErrorKind::TransactionMismatch(
                        "an address owner is not named by the proof inputs",
                    ))?;
                let input = zolana_transaction::utxo::SppProofInputUtxo::new_address(
                    owner.signing_pubkey,
                    to_bytes(&created.seed)?,
                    zolana_instruction::ADDRESS_TREE_ID,
                )
                .map_err(ClientErrorKind::Transaction)?;
                if input.nullifier != to_bytes(&created.address)? {
                    return Err(ClientErrorKind::TransactionMismatch(
                        "the address does not match the circuit",
                    )
                    .into());
                }
                Ok(input)
            })
            .collect()
    }

    pub(super) fn output_utxos(
        &self,
        sender: &ShieldedAddress,
    ) -> Result<Vec<Option<SppProofOutputUtxo>>, ClientError> {
        let sender_hash = sender.owner_hash().map_err(ClientErrorKind::InvalidOwner)?;
        self.checked
            .outputs
            .iter()
            .enumerate()
            .map(|(slot, checked)| {
                if bool::from_circuit(&checked.empty)? {
                    return Ok(None);
                }
                let problem = |problem| ClientErrorKind::Slot {
                    kind: SlotKind::Output,
                    index: slot,
                    problem,
                };
                let output = &checked.output;
                let owner_hash = to_bytes(&output.owner.hash()?)?;
                let owner = match self
                    .records
                    .get::<OwnerRecords>()
                    .and_then(|records| records.get(&owner_hash))
                {
                    Some(owner) => *owner,
                    None if owner_hash == sender_hash => *sender,
                    None => return Err(problem("has an owner no input names").into()),
                };
                let asset = self
                    .mint(&output.asset)?
                    .ok_or(problem("has an asset no input names"))?;
                let amount = u64::from_circuit(&output.amount)
                    .map_err(|_| problem("has an amount that does not fit in u64"))?;
                let utxo = SppProofOutputUtxo::new(asset, amount, owner)
                    .map_err(ClientErrorKind::Transaction)?;
                let data_hash = to_bytes(&output.data_hash)?;
                Ok(Some(match output.data.clone() {
                    _ if data_hash == [0u8; 32] => utxo,
                    Some(data) => utxo.with_utxo_data(data, data_hash),
                    None => SppProofOutputUtxo {
                        data_hash: Some(data_hash),
                        ..utxo
                    },
                }))
            })
            .collect()
    }

    pub(super) fn mint(&self, asset: &Asset) -> Result<Option<Mint>, ClientError> {
        let asset_hash = to_bytes(&asset.hash()?)?;
        Ok(
            match self
                .records
                .get::<MintRecords>()
                .and_then(|records| records.get(&asset_hash))
            {
                Some(mint) => Some(*mint),
                None if asset_hash == hash_bytes(Mint::SOL.asset.as_array())? => Some(Mint::SOL),
                None => None,
            },
        )
    }
}
