use anyhow::{anyhow, Result};
use dynamic_swap_program::instructions::shared::u64_right_align;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{owner_hash, poseidon},
    NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::err;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowTerms {
    pub recipient_owner_hash: [u8; 32],
    pub max_price: u64,
    pub created_at_unix_ts: i64,
    pub expires_at_unix_ts: i64,
    pub execution_price: u64,
    pub quote_version: u64,
}

impl EscrowTerms {
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        let created = u64::try_from(self.created_at_unix_ts)
            .map_err(|_| anyhow!("created_at must be non-negative"))?;
        let expires = u64::try_from(self.expires_at_unix_ts)
            .map_err(|_| anyhow!("expires_at must be non-negative"))?;
        poseidon(&[
            &self.recipient_owner_hash,
            &u64_right_align(self.max_price),
            &u64_right_align(created),
            &u64_right_align(expires),
            &u64_right_align(self.execution_price),
            &u64_right_align(self.quote_version),
        ])
        .map_err(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowUtxo {
    pub terms: EscrowTerms,
    pub asset: Address,
    pub order_amount: u64,
    pub blinding: Blinding,
}

impl EscrowUtxo {
    fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    fn pda_owner(pair: &Pubkey) -> PublicKey {
        PublicKey::from_ed25519(crate::escrow_authority_pda(pair).as_array())
    }

    pub fn order_utxo_owner_hash(pair: &Pubkey) -> Result<[u8; 32]> {
        owner_hash(
            &Self::pda_owner(pair),
            &Self::nullifier_key().pubkey().map_err(err)?,
        )
        .map_err(err)
    }

    pub fn data_hash(&self) -> Result<[u8; 32]> {
        self.terms.data_hash()
    }

    /// The standard confidential output is addressed to the maker's viewing
    /// pubkey. The transaction viewing key retained by the taker can decrypt
    /// this same slot through the sender path.
    pub fn output_utxo(
        &self,
        pair: &Pubkey,
        maker_viewing_pubkey: P256Pubkey,
    ) -> Result<SppProofOutputUtxo> {
        let owner_address = ShieldedAddress {
            signing_pubkey: Self::pda_owner(pair),
            nullifier_pubkey: Self::nullifier_key().pubkey().map_err(err)?,
            viewing_pubkey: maker_viewing_pubkey,
        };
        Ok(SppProofOutputUtxo {
            asset: self.asset,
            amount: self.order_amount,
            blinding: self.blinding,
            owner_address: Some(owner_address),
            ..Default::default()
        }
        .with_utxo_data(encode_order_note(&self.terms), self.data_hash()?))
    }

    pub fn to_input_utxo(&self, pair: &Pubkey) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: Self::pda_owner(pair),
            asset: self.asset,
            amount: self.order_amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, Self::nullifier_key()).with_data_hash(self.data_hash()?))
    }
}

const ORDER_NOTE_LEN: usize = 32 + 8 * 5;

pub fn encode_order_note(terms: &EscrowTerms) -> Vec<u8> {
    let mut note = Vec::with_capacity(ORDER_NOTE_LEN);
    note.extend_from_slice(&terms.recipient_owner_hash);
    note.extend_from_slice(&terms.max_price.to_le_bytes());
    note.extend_from_slice(&terms.created_at_unix_ts.to_le_bytes());
    note.extend_from_slice(&terms.expires_at_unix_ts.to_le_bytes());
    note.extend_from_slice(&terms.execution_price.to_le_bytes());
    note.extend_from_slice(&terms.quote_version.to_le_bytes());
    note
}

pub fn decode_order_note(data: &Data) -> Result<EscrowTerms> {
    let bytes = data
        .utxo_data()
        .ok_or_else(|| anyhow!("order output carries no encrypted note"))?;
    if bytes.len() != ORDER_NOTE_LEN {
        return Err(anyhow!(
            "order note is {} bytes, expected {ORDER_NOTE_LEN}",
            bytes.len()
        ));
    }
    let mut recipient_owner_hash = [0u8; 32];
    recipient_owner_hash.copy_from_slice(
        bytes
            .get(..32)
            .ok_or_else(|| anyhow!("invalid order note recipient"))?,
    );
    let read_u64 = |offset: usize| -> Result<u64> {
        let end = offset
            .checked_add(8)
            .ok_or_else(|| anyhow!("invalid order note field offset"))?;
        Ok(u64::from_le_bytes(
            bytes
                .get(offset..end)
                .ok_or_else(|| anyhow!("invalid order note field"))?
                .try_into()
                .map_err(|_| anyhow!("invalid order note field"))?,
        ))
    };
    let created_at_unix_ts = i64::try_from(read_u64(40)?)
        .map_err(|_| anyhow!("order creation time is outside the i64 range"))?;
    let expires_at_unix_ts = i64::try_from(read_u64(48)?)
        .map_err(|_| anyhow!("order expiry is outside the i64 range"))?;
    Ok(EscrowTerms {
        recipient_owner_hash,
        max_price: read_u64(32)?,
        created_at_unix_ts,
        expires_at_unix_ts,
        execution_price: read_u64(56)?,
        quote_version: read_u64(64)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;
    use zolana_interface::event::OutputDataEncoding;
    use zolana_keypair::{constants::P256_PUBKEY_LEN, ViewingKey};
    use zolana_transaction::{
        instructions::transact::encrypt_transaction_data,
        serialization::confidential::ConfidentialOutputPlaintext, AssetRegistry, DataRecord,
        SOL_MINT,
    };

    #[test]
    fn order_note_round_trips() {
        let terms = EscrowTerms {
            recipient_owner_hash: [7; 32],
            max_price: 6,
            created_at_unix_ts: 100,
            expires_at_unix_ts: 700,
            execution_price: 5,
            quote_version: 2,
        };
        let data = Data::new(vec![DataRecord::UtxoData(encode_order_note(&terms))]);
        assert_eq!(decode_order_note(&data).unwrap(), terms);
    }

    #[test]
    fn exact_order_note_is_decryptable_by_maker_and_taker() {
        let terms = EscrowTerms {
            recipient_owner_hash: [9; 32],
            max_price: 6,
            created_at_unix_ts: 1_700_000_000,
            expires_at_unix_ts: 1_700_000_600,
            execution_price: 5,
            quote_version: 3,
        };
        let expected_note = encode_order_note(&terms);
        let pair = Pubkey::new_unique();
        let taker_viewing_key = ViewingKey::new();
        let maker_viewing_key = ViewingKey::new();
        let tx_viewing_key = taker_viewing_key
            .get_transaction_viewing_key(&[11; 32])
            .unwrap();
        let order_output = EscrowUtxo {
            terms,
            asset: SOL_MINT,
            order_amount: 1,
            blinding: [7; 32],
        }
        .output_utxo(&pair, maker_viewing_key.pubkey())
        .unwrap();
        let encoded =
            encrypt_transaction_data(&[order_output], &AssetRegistry::default(), &tx_viewing_key)
                .unwrap();
        let output_data = encoded
            .outputs
            .first()
            .and_then(|output| output.data.as_ref())
            .expect("encrypted order output");
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(output_data).unwrap()
        else {
            panic!("order note must use confidential encryption");
        };
        let (_, body) = blob.split_first().expect("confidential scheme byte");
        let (recipient_pubkey, ciphertext) = body
            .split_at_checked(P256_PUBKEY_LEN)
            .expect("embedded maker viewing pubkey");
        assert_eq!(recipient_pubkey, maker_viewing_key.pubkey().as_bytes());

        let maker_plaintext = maker_viewing_key
            .decrypt_utxo(ciphertext, &tx_viewing_key.pubkey(), encoded.salt, 0)
            .unwrap();
        let taker_plaintext = tx_viewing_key
            .decrypt_slot_ephemeral(&maker_viewing_key.pubkey(), ciphertext, encoded.salt, 0)
            .unwrap();

        assert_eq!(maker_plaintext, taker_plaintext);
        let plaintext = ConfidentialOutputPlaintext::deserialize(&maker_plaintext).unwrap();
        assert_eq!(plaintext.data.utxo_data().unwrap(), expected_note);
    }
}
