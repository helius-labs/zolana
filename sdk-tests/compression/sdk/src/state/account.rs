use anyhow::Result;
use borsh::BorshDeserialize;
pub use compression_example_program::state::AccountState;
use solana_address::Address;
use zolana_keypair::{PublicKey, ShieldedAddress, ViewingKey};
use zolana_transaction::{Data, DataRecord, SppProofOutputUtxo, Utxo, SOL_MINT};

use crate::{err, shared::zero_nullifier_key};

pub fn decode_state(data: &[u8]) -> Result<AccountState> {
    AccountState::try_from_slice(data).map_err(err)
}

#[derive(Clone, Debug)]
pub struct AccountUtxo {
    pub pda: Address,
    pub state: AccountState,
}

impl AccountUtxo {
    pub fn utxo(&self) -> Result<Utxo> {
        Ok(Utxo {
            owner: PublicKey::from_pda(&self.pda),
            asset: SOL_MINT,
            amount: 0,
            blinding: self.state.blinding(),
            ring_program_id: None,
            data: Data::new(vec![DataRecord::UtxoData(
                self.state.to_vec().map_err(err)?,
            )]),
        })
    }

    pub fn output_utxo(&self) -> Result<SppProofOutputUtxo> {
        Ok(SppProofOutputUtxo {
            asset: SOL_MINT,
            amount: 0,
            blinding: self.state.blinding(),
            data_hash: Some(self.state.data_hash().map_err(err)?),
            owner_address: Some(pda_shielded_address(&self.pda)?),
            owner_tag: Some(self.pda.to_bytes()),
            data: self.utxo()?.data,
            ..SppProofOutputUtxo::default()
        })
    }

    pub fn output_data(&self) -> Result<Vec<u8>> {
        self.state.to_output_data().map_err(err)
    }
}

pub fn pda_shielded_address(pda: &Address) -> Result<ShieldedAddress> {
    Ok(ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(pda),
        nullifier_pubkey: zero_nullifier_key().pubkey()?,
        viewing_pubkey: ViewingKey::from_bytes(&[5u8; 32])?.pubkey(),
    })
}
