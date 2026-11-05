use solana_address::Address;
use spr_keypair::{NullifierKey, PublicKey};

use super::{Blinding, ProofInputUtxo};
use crate::{
    data::Data, error::TransactionError, serialization::confidential::ConfidentialOutputPlaintext,
    Mint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
#[cfg_attr(
    feature = "tsify",
    derive(tsify::Tsify),
    tsify(large_number_types_as_bigints)
)]
pub struct Utxo {
    pub owner: PublicKey,
    /// The resolved mint. Commitments use its address; payloads use its ID.
    pub asset: Mint,
    pub amount: u64,
    #[cfg_attr(feature = "serde", serde(with = "spr_keypair::serde_helpers::bytes"))]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub blinding: Blinding,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "spr_keypair::serde_helpers::option_address"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "string"))]
    pub ring_program_id: Option<Address>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub data: Data,
}

pub(crate) fn resolve_ring_program_id(
    ring_program_id: Option<Address>,
    data: &Data,
) -> Result<Option<Address>, TransactionError> {
    if data.ring_data().is_none() {
        return Ok(None);
    }
    if ring_program_id.is_none() {
        return Err(TransactionError::MissingRingProgramId);
    }
    Ok(ring_program_id)
}

impl Utxo {
    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        data_hash: &[u8; 32],
        ring_data_hash: &[u8; 32],
        tree_id: u16,
    ) -> Result<[u8; 32], TransactionError> {
        let owner_hash = spr_keypair::hash::owner_hash(&self.owner, nullifier_pk)?;
        ProofInputUtxo::new(
            owner_hash,
            &self.asset.asset,
            self.amount,
            &self.blinding,
            tree_id,
        )?
        .with_data_hash(*data_hash)
        .with_ring(*ring_data_hash, &self.ring_program_id)?
        .hash()
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        nullifier_key: &NullifierKey,
    ) -> Result<[u8; 32], TransactionError> {
        Ok(nullifier_key.nullifier(utxo_hash, &self.blinding)?)
    }

    pub fn to_confidential_output_plaintext(&self) -> ConfidentialOutputPlaintext {
        ConfidentialOutputPlaintext {
            asset_id: self.asset.asset_id,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: self.data.clone(),
        }
    }
}
