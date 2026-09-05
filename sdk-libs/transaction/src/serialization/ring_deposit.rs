use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_interface::instruction::EncryptedRingDepositData;
use zolana_keypair::{random_salt, P256Pubkey, PublicKey, ViewingKey};

use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::{Blinding, Utxo},
};

/// Private preimages delivered to the owner of a proofless ring deposit.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RingDepositPlaintext {
    pub blinding: Blinding,
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub utxo_data: Option<Vec<u8>>,
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub memo: Option<Vec<u8>>,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub ring_data: Vec<u8>,
}

impl RingDepositPlaintext {
    pub fn encrypt(
        &self,
        recipient: &P256Pubkey,
    ) -> Result<EncryptedRingDepositData, TransactionError> {
        let tx_viewing_key = ViewingKey::new();
        let salt = random_salt();
        let plaintext = wincode::serialize(self)?;
        let ciphertext = tx_viewing_key.encrypt_ring_deposit(recipient, &plaintext, salt)?;
        Ok(EncryptedRingDepositData {
            tx_viewing_pk: *tx_viewing_key.pubkey().as_bytes(),
            salt,
            ciphertext,
        })
    }

    pub fn decrypt(
        encrypted: &EncryptedRingDepositData,
        viewing_key: &ViewingKey,
    ) -> Result<Self, TransactionError> {
        let tx_viewing_pk = P256Pubkey::from_bytes(encrypted.tx_viewing_pk)?;
        let plaintext = viewing_key.decrypt_ring_deposit(
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
        ring_program_id: Address,
    ) -> Utxo {
        let mut records = vec![DataRecord::RingData(self.ring_data)];
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
            ring_program_id: Some(ring_program_id),
            data: Data::new(records),
        }
    }
}
