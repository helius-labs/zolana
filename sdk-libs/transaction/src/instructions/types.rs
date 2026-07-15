use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, viewing_key::random_blinding, NullifierKey, PublicKey,
};

use crate::{
    data::Data,
    error::TransactionError,
    utxo::{owner_utxo_hash, utxo_hash, Utxo},
};

#[derive(Clone)]
pub struct SppProofInputUtxo {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
}

impl SppProofInputUtxo {
    pub fn new(utxo: Utxo, nullifier_key: impl AsRef<NullifierKey>) -> Self {
        Self {
            utxo,
            nullifier_key: nullifier_key.as_ref().clone(),
            data_hash: None,
            zone_data_hash: None,
        }
    }

    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self
    }

    pub fn with_zone_data_hash(mut self, zone_data_hash: [u8; 32]) -> Self {
        self.zone_data_hash = Some(zone_data_hash);
        self
    }

    pub fn new_dummy() -> Self {
        let utxo = Utxo {
            owner: PublicKey::zeroed(),
            asset: Address::default(),
            amount: 0,
            blinding: random_blinding(),
            zone_program_id: None,
            data: Data::default(),
        };
        Self {
            utxo,
            nullifier_key: NullifierKey::from_secret([0u8; BLINDING_LEN]),
            data_hash: None,
            zone_data_hash: None,
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        // A dummy's zeroed owner is not a parseable key; it contributes a zero
        // owner hash instead. The circuit skips ownership for dummies, so the
        // value only pads the hash chain.
        if self.is_dummy() {
            return utxo_hash(
                self.utxo.asset,
                self.utxo.amount,
                &self.data_hash.unwrap_or_default(),
                &self.zone_data_hash.unwrap_or_default(),
                self.utxo.zone_program_id,
                &owner_utxo_hash(&[0u8; 32], &self.utxo.blinding)?,
            );
        }
        let nullifier_pubkey = self.nullifier_key.pubkey()?;
        self.utxo.hash(
            &nullifier_pubkey,
            &self.data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
        )
    }

    pub fn nullifier(&self) -> Result<[u8; 32], TransactionError> {
        let utxo_hash = self.hash()?;
        Ok(self
            .nullifier_key
            .nullifier(&utxo_hash, &self.utxo.blinding)?)
    }
}

pub struct InputUtxoContext {
    pub index: usize,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}
