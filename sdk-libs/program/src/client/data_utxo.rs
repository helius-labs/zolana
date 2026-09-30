use borsh::BorshDeserialize;
use zolana_transaction::WalletUtxo;

use crate::{
    hasher::{data_hash, DataHasher, Poseidon},
    ClientError, ClientErrorKind,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUtxo<T> {
    pub utxo: WalletUtxo,
    pub data: T,
}

impl<T: BorshDeserialize + DataHasher> TryFrom<WalletUtxo> for DataUtxo<T> {
    type Error = ClientError;

    fn try_from(mut utxo: WalletUtxo) -> Result<Self, ClientError> {
        let bytes = utxo
            .utxo
            .data
            .utxo_data()
            .ok_or(ClientErrorKind::NoUtxoData)?;
        let data = T::try_from_slice(bytes).map_err(ClientErrorKind::UtxoDataEncoding)?;
        let data_hash = data_hash(&data.hash::<Poseidon>()?)?;
        let utxo_hash = utxo
            .utxo
            .hash(
                &utxo.nullifier_pubkey,
                &data_hash,
                &utxo.ring_data_hash.unwrap_or_default(),
                utxo.tree_id,
            )
            .map_err(ClientErrorKind::InvalidUtxo)?;
        if utxo_hash != utxo.utxo_hash {
            return Err(ClientErrorKind::DataHashMismatch.into());
        }
        utxo.data_hash = Some(data_hash);
        Ok(Self { utxo, data })
    }
}
