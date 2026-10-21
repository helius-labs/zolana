use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{MessageData, OutputDataEncoding};
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{state::cache::CACHE_CAPACITY, tree_slot::tree_id_field};
use zolana_keypair::{constants::SALT_LEN, random_blinding, shielded::ShieldedAddress, ViewingKey};

use super::{dummy_utxo_hash, owner_utxo_hash, program_id_proof_input_hash, Blinding, UTXO_DOMAIN};
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    EncryptedScheme, Mint,
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
// Serialize-only. These values are produced while finalizing a transaction and
// never decoded; a deserializer would turn a misspelled field into a dummy.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(
    feature = "tsify",
    derive(tsify::Tsify),
    tsify(large_number_types_as_bigints)
)]
pub struct SppProofOutputUtxo {
    pub asset: Mint,
    pub amount: u64,
    #[cfg_attr(
        feature = "serde",
        serde(with = "zolana_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub blinding: Blinding,
    /// Ring outputs only, the audit proof binds it.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub ring_secret: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::option_address"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "string"))]
    pub ring_program_id: Option<Address>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub ring_data_hash: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub data_hash: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub owner_address: Option<ShieldedAddress>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub owner_tag: Option<[u8; 32]>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub data: Data,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub cache_slot: Option<u8>,
    /// Compact padding: a dummy that publishes hash 0, so the instruction leaves
    /// it out and SPP appends nothing for it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "core::ops::Not::not")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub compact: bool,
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

    pub fn with_cache_slot(mut self, slot: u8) -> Result<Self, TransactionError> {
        if usize::from(slot) >= CACHE_CAPACITY {
            return Err(TransactionError::CacheSlotOutOfRange { slot });
        }
        if self.is_dummy() {
            return Err(TransactionError::CachedDummyOutput);
        }
        self.cache_slot = Some(slot);
        Ok(self)
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

    /// Attach application data and its commitment. SPP commits `data_hash`
    /// unchecked: nothing verifies that it hashes `utxo_data`, so a reader must
    /// recompute it under the application's encoding before trusting the
    /// payload, and must reject non-empty data with a zero `data_hash`, which
    /// no owner authorized.
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

    /// The owner's confidential message for slot `slot_index`, under the ring scheme byte inside a ring.
    pub fn seal(
        &self,
        slot_index: u32,
        tx: &ViewingKey,
        salt: [u8; SALT_LEN],
    ) -> Result<MessageData, TransactionError> {
        let (address, plaintext, cx) = self.confidential_parts(slot_index, tx, salt)?;
        let mut message = Confidential::encode_plaintext(
            &plaintext,
            address.signing_pubkey.confidential_view_tag()?,
            &cx,
        )?;
        if self.ring_program_id.is_some() {
            let decode = |error: std::io::Error| TransactionError::Deserialize(error.to_string());
            let OutputDataEncoding::Encrypted(mut blob) =
                OutputDataEncoding::try_from_slice(&message.data).map_err(decode)?
            else {
                return Err(TransactionError::BadDiscriminator(
                    EncryptedScheme::Confidential.as_byte(),
                ));
            };
            *blob.first_mut().ok_or(TransactionError::MissingOutput)? =
                EncryptedScheme::RingConfidential.as_byte();
            message.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).map_err(decode)?;
        }
        Ok(message)
    }

    fn confidential_parts(
        &self,
        slot_index: u32,
        tx: &ViewingKey,
        salt: [u8; SALT_LEN],
    ) -> Result<
        (
            ShieldedAddress,
            ConfidentialOutputPlaintext,
            ConfidentialEncode,
        ),
        TransactionError,
    > {
        let address = self
            .owner_address
            .ok_or(TransactionError::OutputWithoutOwner {
                slot_index: slot_index as usize,
            })?;
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: self.asset.asset_id,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: self.data.clone(),
        };
        let cx = ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: address.viewing_pubkey,
            salt,
            slot_index,
        };
        Ok((address, plaintext, cx))
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
        if self.is_compact() {
            return Ok([0u8; 32]);
        }
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

    pub fn is_ring_output(&self) -> bool {
        !self.is_dummy() && self.ring_program_id.is_some()
    }

    pub fn is_compact(&self) -> bool {
        self.is_dummy() && self.compact
    }
}
