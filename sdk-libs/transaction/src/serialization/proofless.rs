use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::ProoflessOutput;

use super::{DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::Utxo,
    EncryptedScheme,
};

pub struct ProoflessEncode {
    pub owner_hash: [u8; 32],
    pub program_data_hash: Option<[u8; 32]>,
    pub policy_data_hash: Option<[u8; 32]>,
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
        if let Some(program_data) = output.program_data {
            records.push(DataRecord::ProgramData(program_data));
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
            program_data_hash: cx.program_data_hash,
            program_data: utxo.data.program_data().map(<[u8]>::to_vec),
            zone_program_id: utxo.zone_program_id.map(|address| address.to_bytes()),
            policy_data_hash: cx.policy_data_hash,
            zone_data: utxo.data.zone_data().map(<[u8]>::to_vec),
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        borsh::to_vec(plaintext).map_err(|e| TransactionError::Deserialize(e.to_string()))
    }

    fn encrypt(bytes: &[u8], _cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(bytes.to_vec())
    }
}
