use solana_address::Address;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_keypair::{random_blinding, shielded::ShieldedAddress};

use super::{dummy_utxo_hash, owner_utxo_hash, program_id_proof_input_hash, Blinding, UTXO_DOMAIN};
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    Mint,
};

/// Canonical ordering key for data records: `RingData` < `UtxoData` < `Memo`,
/// matching `Data::validate`.
fn canonical_data_order(record: &DataRecord) -> u8 {
    match record {
        DataRecord::RingData(_) => 0,
        DataRecord::UtxoData(_) => 1,
        DataRecord::Memo(_) => 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SppProofOutputUtxo {
    pub asset: Mint,
    pub amount: u64,
    pub blinding: Blinding,
    pub ring_program_id: Option<Address>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub data_hash: Option<[u8; 32]>,
    pub owner_address: Option<ShieldedAddress>,
    pub owner_tag: Option<[u8; 32]>,
    pub data: Data,
}

impl SppProofOutputUtxo {
    pub fn new(
        asset: Mint,
        amount: u64,
        owner_address: ShieldedAddress,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            asset,
            amount,
            blinding: random_blinding(),
            owner_tag: Some(owner_address.signing_pubkey.confidential_view_tag()?),
            owner_address: Some(owner_address),
            ..Default::default()
        })
    }

    pub fn with_ring_data(
        mut self,
        ring_program_id: Address,
        ring_data: Vec<u8>,
        ring_data_hash: [u8; 32],
    ) -> Self {
        self = self.with_ring_data_hash(ring_program_id, ring_data_hash);
        self.set_data_record(DataRecord::RingData(ring_data));
        self
    }

    pub fn with_ring_program_id(mut self, ring_program_id: Address) -> Self {
        self.ring_program_id = Some(ring_program_id);
        self
    }

    /// Bind an output to policy-ring state when only its commitment hash belongs
    /// in the merge witness. The ring is responsible for making the corresponding
    /// preimage available to the owner according to its policy protocol.
    pub fn with_ring_data_hash(
        mut self,
        ring_program_id: Address,
        ring_data_hash: [u8; 32],
    ) -> Self {
        self.ring_program_id = Some(ring_program_id);
        self.ring_data_hash = Some(ring_data_hash);
        self
    }

    pub fn with_utxo_data(mut self, utxo_data: Vec<u8>, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self.set_data_record(DataRecord::UtxoData(utxo_data));
        self
    }

    /// Attach a free-form memo to the output. The memo is encrypted into the
    /// recipient's note but not bound by the commitment, so unlike
    /// `with_utxo_data`/`with_ring_data` it sets no `data_hash`.
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

    /// Commitment of this output under the raw id of the tree it is appended
    /// to. The tree id is transaction context, not an output field: the same
    /// output body commits differently in every tree.
    pub fn hash(&self, tree_id: u16) -> Result<[u8; 32], TransactionError> {
        if self.is_dummy() {
            return dummy_utxo_hash(&self.blinding, tree_id);
        }
        let owner_hash = self.owner_hash()?;
        let asset = hash_bytes(self.asset.asset.as_array())?;
        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let ring_hash =
            Poseidon::hashv(&[&self.ring_data_hash.unwrap_or_default(), &ring_program_id])?;
        let owner_hash = owner_utxo_hash(&owner_hash, &self.blinding)?;
        Ok(Poseidon::hashv(&[
            &right_align(&UTXO_DOMAIN.to_be_bytes()),
            &tree_id_field(tree_id),
            &asset,
            &right_align(&self.amount.to_be_bytes()),
            &self.data_hash.unwrap_or_default(),
            &ring_hash,
            &owner_hash,
        ])?)
    }

    pub fn is_dummy(&self) -> bool {
        self.owner_address.is_none()
    }
}
