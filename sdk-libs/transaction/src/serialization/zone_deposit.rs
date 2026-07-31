use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_event::EncryptedZoneDepositData as EventEncryptedZoneDepositData;
use zolana_interface::instruction::EncryptedZoneDepositData;
use zolana_keypair::{random_salt, P256Pubkey, PublicKey, ViewingKey};

use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::{Blinding, Utxo},
};

/// Private preimages delivered to the owner of a proofless zone deposit.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ZoneDepositPlaintext {
    pub blinding: Blinding,
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub utxo_data: Option<Vec<u8>>,
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub memo: Option<Vec<u8>>,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub zone_data: Vec<u8>,
}

impl ZoneDepositPlaintext {
    pub fn encrypt(
        &self,
        recipient: &P256Pubkey,
    ) -> Result<EncryptedZoneDepositData, TransactionError> {
        let tx_viewing_key = ViewingKey::new();
        let salt = random_salt();
        let plaintext = wincode::serialize(self)?;
        let ciphertext = tx_viewing_key.encrypt_zone_deposit(recipient, &plaintext, salt)?;
        Ok(EncryptedZoneDepositData {
            tx_viewing_pk: *tx_viewing_key.pubkey().as_bytes(),
            salt,
            ciphertext,
        })
    }

    pub fn decrypt(
        encrypted: &EventEncryptedZoneDepositData,
        viewing_key: &ViewingKey,
    ) -> Result<Self, TransactionError> {
        let tx_viewing_pk = P256Pubkey::from_bytes(encrypted.tx_viewing_pk)?;
        let plaintext = viewing_key.decrypt_zone_deposit(
            &encrypted.ciphertext,
            &tx_viewing_pk,
            encrypted.salt,
        )?;
        Ok(wincode::deserialize_exact(&plaintext)?)
    }

    pub fn into_utxo(
        self,
        owner: PublicKey,
        asset: Address,
        amount: u64,
        zone_program_id: Address,
    ) -> Utxo {
        let mut records = vec![DataRecord::ZoneData(self.zone_data)];
        if let Some(data) = self.utxo_data {
            records.push(DataRecord::UtxoData(data));
        }
        if let Some(memo) = self.memo {
            records.push(DataRecord::Memo(memo));
        }
        Utxo {
            owner,
            asset,
            amount,
            blinding: self.blinding,
            zone_program_id: Some(zone_program_id),
            data: Data::new(records),
        }
    }
}
