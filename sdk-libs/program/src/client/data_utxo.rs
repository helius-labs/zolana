use spr_transaction::WalletUtxo;
use super::transaction::fail;

use crate::{
    hasher::{data_hash, unique_data_hash, DataHasher},
    ClientError, EncryptionCodec,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUtxo<T> {
    pub utxo: WalletUtxo,
    pub data: T,
    /// Reserved address for a unique data UTXO. Ordinary data UTXOs have none.
    pub address: Option<[u8; 32]>,
}

impl<T: EncryptionCodec + DataHasher> TryFrom<WalletUtxo> for DataUtxo<T> {
    type Error = ClientError;

    fn try_from(mut utxo: WalletUtxo) -> Result<Self, ClientError> {
        let bytes = utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| fail("the utxo carries no data"))?;
        let matches = |hash: &[u8; 32]| -> Result<bool, ClientError> {
            Ok(utxo
                .utxo
                .hash(
                    &utxo.nullifier_pubkey,
                    hash,
                    &utxo.ring_data_hash.unwrap_or_default(),
                    utxo.tree_id,
                )
                .map_err(fail)?
                == utxo.utxo_hash)
        };
        let ordinary = T::deserialize_after_decryption(bytes);
        if let Ok(data) = &ordinary {
            let hash = data_hash(&data.hash().map_err(fail)?).map_err(fail)?;
            if matches(&hash)? {
                utxo.data_hash = Some(hash);
                return Ok(Self {
                    utxo,
                    data: ordinary.map_err(fail)?,
                    address: None,
                });
            }
        }
        if let Some((address, encoded)) = bytes.split_first_chunk::<32>() {
            if let Ok(data) = T::deserialize_after_decryption(encoded) {
                let address = *address;
                let hash = unique_data_hash(&address, &data.hash().map_err(fail)?).map_err(fail)?;
                if matches(&hash)? {
                    utxo.data_hash = Some(hash);
                    return Ok(Self {
                        utxo,
                        data,
                        address: Some(address),
                    });
                }
                return Err(ClientError::DataHashMismatch);
            }
        }
        match ordinary {
            Ok(_) => Err(ClientError::DataHashMismatch),
            Err(error) => Err(fail(error)),
        }
    }
}
