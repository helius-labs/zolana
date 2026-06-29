use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, shielded::ShieldedKeypair, viewing_key::random_blinding, NullifierKey,
    PublicKey,
};

use crate::{data::Data, utxo::Utxo};

#[derive(Clone)]
pub struct SpendUtxo {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub program_data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
}

impl SpendUtxo {
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
            program_data_hash: None,
            zone_data_hash: None,
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }

    pub fn from_keypair(utxo: Utxo, keypair: &ShieldedKeypair) -> Self {
        Self::from_nullifier_key(utxo, &keypair.nullifier_key)
    }

    pub fn from_nullifier_key(utxo: Utxo, nullifier_key: &NullifierKey) -> Self {
        Self {
            utxo,
            nullifier_key: nullifier_key.clone(),
            program_data_hash: None,
            zone_data_hash: None,
        }
    }
}

pub struct InputCommitment {
    pub index: usize,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}
