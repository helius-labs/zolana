use borsh::BorshDeserialize;
use rings_event::ProoflessOutput;
use solana_address::Address;

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::Utxo,
    EncryptedScheme,
};

pub struct ProoflessEncode {
    pub owner_hash: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
}

pub struct Proofless;

impl UtxoSerialization for Proofless {
    const SCHEME: EncryptedScheme = EncryptedScheme::Proofless;
    type Plaintext = ProoflessOutput;
    type EncodeCx = ProoflessEncode;

    fn decrypt(body: &[u8], _cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(body.to_vec())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        ProoflessOutput::try_from_slice(bytes)
            .map_err(|e| TransactionError::Deserialize(e.to_string()))
    }

    fn into_utxos(output: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        let mut records = Vec::new();
        if let Some(zone_data) = output.zone_data {
            records.push(DataRecord::ZoneData(zone_data));
        }
        if let Some(utxo_data) = output.utxo_data {
            records.push(DataRecord::UtxoData(utxo_data));
        }
        if let Some(memo) = output.memo {
            records.push(DataRecord::Memo(memo));
        }
        Ok(vec![Utxo {
            owner: cx.owner,
            asset: Address::new_from_array(output.asset),
            amount: output.amount,
            blinding: output.blinding,
            zone_program_id: output.zone_program_id.map(Address::new_from_array),
            data: Data::new(records),
        }])
    }

    fn from_utxos(
        utxos: &[Utxo],
        _owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let utxo = utxos.first().ok_or(TransactionError::MissingOutput)?;
        Ok(ProoflessOutput {
            owner: cx.owner_hash,
            blinding: utxo.blinding,
            asset: utxo.asset.to_bytes(),
            amount: utxo.amount,
            data_hash: cx.data_hash,
            utxo_data: utxo.data.utxo_data().map(<[u8]>::to_vec),
            zone_program_id: utxo.zone_program_id.map(|address| address.to_bytes()),
            zone_data_hash: cx.zone_data_hash,
            zone_data: utxo.data.zone_data().map(<[u8]>::to_vec),
            memo: utxo.data.memo().map(<[u8]>::to_vec),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        borsh::to_vec(plaintext).map_err(|e| TransactionError::Deserialize(e.to_string()))
    }

    fn encrypt(bytes: &[u8], _cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use rings_keypair::PublicKey;

    use super::*;
    use crate::{AssetRegistry, SOL_MINT};

    #[test]
    fn memo_round_trips_through_proofless_serialization() {
        let owner = PublicKey::zeroed();
        let utxo = Utxo {
            owner,
            asset: SOL_MINT,
            amount: 42,
            blinding: [3u8; 31],
            zone_program_id: None,
            data: Data::new(vec![DataRecord::Memo(b"gm".to_vec())]),
        };
        let assets = AssetRegistry::default();
        let owner_cx = OwnerCx {
            owner,
            assets: &assets,
            zone_program_id: None,
        };
        let encode_cx = ProoflessEncode {
            owner_hash: [0u8; 32],
            data_hash: None,
            zone_data_hash: None,
        };

        let plaintext = Proofless::from_utxos(&[utxo], &owner_cx, &encode_cx).unwrap();
        assert_eq!(plaintext.memo.as_deref(), Some(b"gm".as_slice()));

        let bytes = Proofless::serialize(&plaintext).unwrap();
        let parsed = Proofless::deserialize(&bytes).unwrap();
        let utxos = Proofless::into_utxos(parsed, &owner_cx).unwrap();
        let recovered = utxos.first().expect("one utxo");
        assert_eq!(recovered.data.memo(), Some(b"gm".as_slice()));
    }
}
