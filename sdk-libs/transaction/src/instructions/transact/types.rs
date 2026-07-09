use borsh::BorshDeserialize;
use rings_event::OutputData;
use rings_keypair::{hash::poseidon, P256Pubkey, ShieldedAddress};
use solana_address::Address;

use super::external_data::ExternalData;
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::{owner_utxo_hash, utxo_hash, Blinding, Utxo},
};

/// Canonical ordering key for data records: `ZoneData` < `UtxoData` < `Memo`,
/// matching `Data::validate`.
fn canonical_data_order(record: &DataRecord) -> u8 {
    match record {
        DataRecord::ZoneData(_) => 0,
        DataRecord::UtxoData(_) => 1,
        DataRecord::Memo(_) => 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputUtxo {
    pub utxo: Utxo,
    pub nullifier_pk: [u8; 32],
    pub zone_data_hash: Option<[u8; 32]>,
    pub data_hash: Option<[u8; 32]>,
}

impl InputUtxo {
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        self.utxo.hash(
            &self.nullifier_pk,
            &self.data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OutputUtxo {
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub zone_program_id: Option<Address>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub data_hash: Option<[u8; 32]>,
    pub owner_address: Option<ShieldedAddress>,
    pub owner_tag: Option<[u8; 32]>,
    pub data: Data,
}

impl OutputUtxo {
    pub fn with_zone_data(
        mut self,
        zone_program_id: Address,
        zone_data: Vec<u8>,
        zone_data_hash: [u8; 32],
    ) -> Self {
        self.zone_data_hash = Some(zone_data_hash);
        self.zone_program_id = Some(zone_program_id);
        self.set_data_record(DataRecord::ZoneData(zone_data));
        self
    }

    pub fn with_utxo_data(mut self, utxo_data: Vec<u8>, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self.set_data_record(DataRecord::UtxoData(utxo_data));
        self
    }

    /// Attach a free-form memo to the output. The memo is encrypted into the
    /// recipient's note but not bound by the commitment, so unlike
    /// `with_utxo_data`/`with_zone_data` it sets no `data_hash`.
    pub fn with_memo(mut self, memo: Vec<u8>) -> Self {
        self.set_data_record(DataRecord::Memo(memo));
        self
    }

    fn set_data_record(&mut self, record: DataRecord) {
        let order = canonical_data_order(&record);
        self.data
            .records
            .retain(|existing| canonical_data_order(existing) != order);
        self.data.records.push(record);
        self.data.records.sort_by_key(canonical_data_order);
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], TransactionError> {
        match &self.owner_address {
            Some(address) => Ok(address.owner_hash()?),
            None => Ok([0u8; 32]),
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        utxo_hash(
            self.asset,
            self.amount,
            &self.data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
            self.zone_program_id,
            &owner_utxo_hash(&self.owner_hash()?, &self.blinding)?,
        )
    }

    pub fn is_dummy(&self) -> bool {
        self.owner_address.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedTransaction {
    pub inputs: Vec<InputUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub external_data: ExternalData,
}

impl EncryptedTransaction {
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let input_hashes = self
            .inputs
            .iter()
            .map(InputUtxo::hash)
            .collect::<Result<Vec<_>, _>>()?;
        let output_hashes = self
            .outputs
            .iter()
            .map(OutputUtxo::hash)
            .collect::<Result<Vec<_>, _>>()?;
        private_tx_hash(
            &input_hashes,
            &output_hashes,
            &no_address_hashes(input_hashes.len()),
            &self.external_data.hash()?,
        )
    }
}

pub fn private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    address_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    let input_chain = hash_chain(input_hashes)?;
    let output_chain = hash_chain(output_hashes)?;
    let address_chain = hash_chain(address_hashes)?;
    Ok(poseidon(&[
        &input_chain,
        &output_chain,
        &address_chain,
        external_data_hash,
    ])?)
}

pub fn no_address_hashes(n_inputs: usize) -> Vec<[u8; 32]> {
    vec![[0u8; 32]; n_inputs]
}

fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], TransactionError> {
    let mut iter = items.iter();
    let mut acc = match iter.next() {
        Some(first) => *first,
        None => return Ok([0u8; 32]),
    };
    for item in iter {
        acc = poseidon(&[&acc, item])?;
    }
    Ok(acc)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputContext {
    pub hash: [u8; 32],
    pub tree: Address,
    pub leaf_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSlot {
    pub view_tag: [u8; 32],
    pub output_context: OutputContext,
    pub payload: Vec<u8>,
}

impl OutputSlot {
    pub fn output_data(&self) -> Option<OutputData> {
        OutputData::try_from_slice(&self.payload).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: solana_signature::Signature,
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; 16]>,
    pub output_slots: Vec<OutputSlot>,
    pub nullifiers: Vec<[u8; 32]>,
    pub proofless: bool,
}
