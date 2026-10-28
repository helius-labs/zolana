use anyhow::Result;
pub use compression_example_program::state::AccountState;
use solana_address::Address;
use spr_keypair::{PublicKey, ShieldedAddress, ViewingKey};
use spr_program::hasher::{unique_data_hash, DataHasher};
use spr_transaction::{Data, DataRecord, Mint, SppProofOutputUtxo, Utxo};

use crate::shared::zero_nullifier_key;

pub fn decode_state(data: &[u8]) -> Result<([u8; 32], AccountState)> {
    let (address, encoded) = data
        .split_first_chunk::<32>()
        .ok_or_else(|| anyhow::anyhow!("unique UTXO payload has no address"))?;
    Ok((*address, borsh::from_slice(encoded)?))
}

#[derive(Clone, Debug)]
pub struct AccountUtxo {
    pub pda: Address,
    pub address: [u8; 32],
    pub state: AccountState,
    pub blinding: [u8; 32],
}

impl AccountUtxo {
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        Ok(unique_data_hash(&self.address, &self.state.hash()?)?)
    }

    pub fn utxo_data(&self) -> Result<Vec<u8>> {
        let mut data = self.address.to_vec();
        data.extend(borsh::to_vec(&self.state)?);
        Ok(data)
    }

    pub fn utxo(&self) -> Result<Utxo> {
        Ok(Utxo {
            owner: PublicKey::from_pda(&self.pda),
            asset: Mint::SOL,
            amount: 0,
            blinding: self.blinding,
            ring_program_id: None,
            data: Data::new(vec![DataRecord::UtxoData(self.utxo_data()?)]),
        })
    }

    pub fn output_utxo(&self) -> Result<SppProofOutputUtxo> {
        Ok(SppProofOutputUtxo {
            asset: Mint::SOL,
            amount: 0,
            blinding: self.blinding,
            data_hash: Some(self.data_hash()?),
            owner_address: Some(pda_shielded_address(&self.pda)?),
            owner_tag: Some(self.pda.to_bytes()),
            data: self.utxo()?.data,
            ..SppProofOutputUtxo::default()
        })
    }
}

pub fn pda_shielded_address(pda: &Address) -> Result<ShieldedAddress> {
    Ok(ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(pda),
        nullifier_pubkey: zero_nullifier_key().pubkey()?,
        viewing_pubkey: ViewingKey::from_bytes(&[5u8; 32]).pubkey(),
    })
}
