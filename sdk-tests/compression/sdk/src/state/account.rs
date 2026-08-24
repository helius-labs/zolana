use anyhow::{anyhow, Result};
use compression_example_program::state::{account_data_hash, RECIPIENT_POSITION, STATE_DATA_LEN};
use solana_address::Address;
use zolana_keypair::{PublicKey, ShieldedAddress, ViewingKey};
use zolana_transaction::{
    serialization::{
        plaintext::{PlaintextEncode, PlaintextTransfer},
        OwnerCx, UtxoSerialization,
    },
    AssetRegistry, Data, DataRecord, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::{err, shared::zero_nullifier_key};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub address: [u8; 32],
    pub authority: [u8; 32],
    pub value: u64,
}

impl AccountState {
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(STATE_DATA_LEN);
        data.extend_from_slice(&self.address);
        data.extend_from_slice(&self.authority);
        data.extend_from_slice(&self.value.to_le_bytes());
        data
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != STATE_DATA_LEN {
            return Err(anyhow!(
                "state data has {} bytes, expected {STATE_DATA_LEN}",
                data.len()
            ));
        }
        let address = data
            .get(..32)
            .ok_or_else(|| anyhow!("missing address"))?
            .try_into()
            .map_err(|_| anyhow!("invalid address"))?;
        let authority = data
            .get(32..64)
            .ok_or_else(|| anyhow!("missing authority"))?
            .try_into()
            .map_err(|_| anyhow!("invalid authority"))?;
        let value = u64::from_le_bytes(
            data.get(64..72)
                .ok_or_else(|| anyhow!("missing value"))?
                .try_into()
                .map_err(|_| anyhow!("invalid value"))?,
        );
        Ok(Self {
            address,
            authority,
            value,
        })
    }

    pub fn data_hash(&self) -> Result<[u8; 32]> {
        account_data_hash(&self.address, &self.authority, self.value).map_err(err)
    }
}

#[derive(Clone, Debug)]
pub struct AccountUtxo {
    pub pda: Address,
    pub state: AccountState,
    pub output_seed: [u8; 32],
}

impl AccountUtxo {
    pub fn blinding(&self) -> [u8; 32] {
        zolana_transaction::derive_blinding(&self.output_seed, RECIPIENT_POSITION)
    }

    pub fn utxo(&self) -> Utxo {
        Utxo {
            owner: PublicKey::from_pda(&self.pda),
            asset: SOL_MINT,
            amount: 0,
            blinding: self.blinding(),
            ring_program_id: None,
            data: Data::new(vec![DataRecord::UtxoData(self.state.encode())]),
        }
    }

    pub fn output_utxo(&self) -> Result<SppProofOutputUtxo> {
        Ok(SppProofOutputUtxo {
            asset: SOL_MINT,
            amount: 0,
            blinding: self.blinding(),
            data_hash: Some(self.state.data_hash()?),
            owner_address: Some(pda_shielded_address(&self.pda)?),
            owner_tag: Some(self.pda.to_bytes()),
            data: self.utxo().data,
            ..SppProofOutputUtxo::default()
        })
    }

    pub fn plaintext_payload(&self) -> Result<Vec<u8>> {
        let utxo = self.utxo();
        let encoded = PlaintextTransfer::encode(
            core::slice::from_ref(&utxo),
            &OwnerCx {
                owner: utxo.owner,
                assets: &AssetRegistry::default(),
                ring_program_id: None,
            },
            self.pda.to_bytes(),
            &PlaintextEncode {
                blinding_seed: self.output_seed,
            },
        )?;
        Ok(encoded.data)
    }
}

pub fn pda_shielded_address(pda: &Address) -> Result<ShieldedAddress> {
    Ok(ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(pda),
        nullifier_pubkey: zero_nullifier_key().pubkey()?,
        viewing_pubkey: ViewingKey::from_bytes(&[5u8; 32])?.pubkey(),
    })
}
