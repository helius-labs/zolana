use solana_address::Address;
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN, VIEW_TAG_LEN};
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{P256Pubkey, PublicKey};

use crate::asset::{AssetRegistry, SOL_MINT};
use crate::data::Data;
use crate::error::TransactionError;
use crate::utxo::{derive_blinding, resolve_zone_program_id, Utxo};
use crate::{P256PubkeySchema, PublicKeySchema, TRANSFER};

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0 (and the sender bundle ciphertext), SOL change at slot 1. Recipients
/// always start at slot 2, so any party maps an output position to its ciphertext
/// slot index (`position - SENDER_SLOT_COUNT + 1`) without the sender bundle.
pub const SENDER_SLOT_COUNT: usize = 2;

/// Byte length of a recipient ciphertext slot: the fixed-size
/// [`TransferRecipientPlaintext`] (with `Data::default()`) plus the 16-byte AES-GCM
/// tag. Every real recipient ciphertext is exactly this long, so a dummy slot uses
/// the same length to stay indistinguishable. Pinned by a test in this module.
pub const RECIPIENT_CIPHERTEXT_LEN: usize = 131;

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferRecipientPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    #[wincode(with = "P256PubkeySchema")]
    pub sender_pubkey: P256Pubkey,
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub data: Data,
}

impl TransferRecipientPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxo(
        self,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Utxo, TransactionError> {
        Ok(Utxo {
            owner: self.owner_pubkey,
            asset: assets.resolve(self.asset_id)?,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: resolve_zone_program_id(zone_program_id, &self.data)?,
            data: self.data,
        })
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferSenderPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub spl_asset_id: u64,
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding_seed: [u8; BLINDING_LEN],
    #[wincode(with = "containers::Vec<P256PubkeySchema, FixIntLen<u8>>")]
    pub recipient_viewing_pks: Vec<P256Pubkey>,
    pub spl_data: Data,
    pub sol_data: Data,
}

impl TransferSenderPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.spl_data.validate()?;
        self.sol_data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.spl_data.validate()?;
        parsed.sol_data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxos(
        self,
        assets: &AssetRegistry,
        zone_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        if self.spl_amount == 0 && !self.spl_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        if self.sol_amount == 0 && !self.sol_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let mut utxos = Vec::new();
        if self.spl_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: assets.resolve(self.spl_asset_id)?,
                amount: self.spl_amount,
                blinding: derive_blinding(&self.blinding_seed, 0),
                zone_program_id: resolve_zone_program_id(zone_program_id, &self.spl_data)?,
                data: self.spl_data,
            });
        }
        if self.sol_amount > 0 {
            utxos.push(Utxo {
                owner: self.owner_pubkey,
                asset: SOL_MINT,
                amount: self.sol_amount,
                blinding: derive_blinding(&self.blinding_seed, 1),
                zone_program_id: resolve_zone_program_id(zone_program_id, &self.sol_data)?,
                data: self.sol_data,
            });
        }
        Ok(utxos)
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct RecipientSlot {
    pub view_tag: ViewTag,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientOutput {
    pub view_tag: ViewTag,
    pub plaintext: TransferRecipientPlaintext,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct TransferEncryptedUtxos {
    pub type_prefix: u8,
    #[wincode(with = "P256PubkeySchema")]
    pub tx_viewing_pk: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub sender_ciphertext: Vec<u8>,
    #[wincode(with = "containers::Vec<RecipientSlot, FixIntLen<u8>>")]
    pub recipient_slots: Vec<RecipientSlot>,
}

impl TransferEncryptedUtxos {
    pub fn num_recipients(&self) -> usize {
        self.recipient_slots.len()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        if parsed.type_prefix != TRANSFER {
            return Err(TransactionError::BadDiscriminator(parsed.type_prefix));
        }
        Ok(parsed)
    }

    /// Spread the bundle across `n_outputs` output slots in canonical
    /// order. Slot 0 holds the sender bundle ciphertext under `sender_view_tag`.
    /// The next `sender_slot_count - 1` slots are the sender's remaining change
    /// outputs, covered by the slot-0 bundle, so they hold empty data. The
    /// following slots hold each recipient ciphertext under its own view tag, and
    /// any remaining slots are empty padding. `tx_viewing_pk` and `salt` are shared
    /// at the transaction level and are not part of a slot.
    pub fn to_output_ciphertexts(
        &self,
        sender_view_tag: ViewTag,
        sender_slot_count: usize,
        n_outputs: usize,
    ) -> Result<Vec<OutputCiphertext>, TransactionError> {
        if sender_slot_count == 0 {
            return Err(TransactionError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        }
        let used = sender_slot_count + self.recipient_slots.len();
        if used > n_outputs {
            return Err(TransactionError::InvalidLength {
                expected: used,
                actual: n_outputs,
            });
        }
        let mut slots = Vec::with_capacity(n_outputs);
        slots.push(OutputCiphertext {
            view_tag: sender_view_tag,
            data: self.sender_ciphertext.clone(),
        });
        for _ in 1..sender_slot_count {
            slots.push(OutputCiphertext::empty());
        }
        for recipient in &self.recipient_slots {
            slots.push(OutputCiphertext {
                view_tag: recipient.view_tag,
                data: recipient.ciphertext.clone(),
            });
        }
        while slots.len() < n_outputs {
            slots.push(OutputCiphertext::empty());
        }
        Ok(slots)
    }

    /// Rebuild the bundle from the transaction-level `tx_viewing_pk` + `salt` and
    /// the ordered output ciphertexts. Slot 0 is the sender bundle; the first
    /// `sender_slot_count` slots are sender-owned (slots 1.. hold empty data);
    /// every later slot with non-empty data is a recipient ciphertext in order.
    pub fn from_output_ciphertexts(
        tx_viewing_pk: P256Pubkey,
        salt: [u8; SALT_LEN],
        slots: &[OutputCiphertext],
        sender_slot_count: usize,
    ) -> Result<Self, TransactionError> {
        if sender_slot_count == 0 || sender_slot_count > slots.len() {
            return Err(TransactionError::InvalidLength {
                expected: sender_slot_count,
                actual: slots.len(),
            });
        }
        let sender = slots.first().ok_or(TransactionError::InvalidLength {
            expected: 1,
            actual: 0,
        })?;
        let recipient_region =
            slots
                .get(sender_slot_count..)
                .ok_or(TransactionError::InvalidLength {
                    expected: sender_slot_count,
                    actual: slots.len(),
                })?;
        let recipient_slots = recipient_region
            .iter()
            .filter(|slot| !slot.data.is_empty())
            .map(|slot| RecipientSlot {
                view_tag: slot.view_tag,
                ciphertext: slot.data.clone(),
            })
            .collect();
        Ok(Self {
            type_prefix: TRANSFER,
            tx_viewing_pk,
            salt,
            sender_ciphertext: sender.data.clone(),
            recipient_slots,
        })
    }
}

/// One output slot's encryption payload: its view tag and the per-output
/// ciphertext (`OutputUtxo::data`). Empty `data` marks a slot with no ciphertext
/// of its own (sender change covered by the slot-0 bundle, or padding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputCiphertext {
    pub view_tag: ViewTag,
    pub data: Vec<u8>,
}

impl OutputCiphertext {
    fn empty() -> Self {
        Self {
            view_tag: [0u8; VIEW_TAG_LEN],
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_keypair::ViewingKey;

    fn bundle(recipient_views: &[u8]) -> TransferEncryptedUtxos {
        TransferEncryptedUtxos {
            type_prefix: TRANSFER,
            tx_viewing_pk: ViewingKey::new().pubkey(),
            salt: [3u8; SALT_LEN],
            sender_ciphertext: vec![1, 2, 3, 4],
            recipient_slots: recipient_views
                .iter()
                .map(|tag| RecipientSlot {
                    view_tag: [*tag; VIEW_TAG_LEN],
                    ciphertext: vec![*tag, tag.wrapping_add(1)],
                })
                .collect(),
        }
    }

    #[test]
    fn recipient_ciphertext_len_is_pinned() {
        let plaintext = TransferRecipientPlaintext {
            owner_pubkey: PublicKey::from_ed25519(&[0u8; 32]),
            sender_pubkey: ViewingKey::new().pubkey(),
            asset_id: 0,
            amount: 0,
            blinding: [0u8; BLINDING_LEN],
            data: Data::default(),
        };
        const GCM_TAG_LEN: usize = 16;
        assert_eq!(
            plaintext.serialize().expect("serialize").len() + GCM_TAG_LEN,
            RECIPIENT_CIPHERTEXT_LEN,
        );
    }

    fn round_trip(recipient_views: &[u8], sender_slot_count: usize, n_outputs: usize) {
        let original = bundle(recipient_views);
        let sender_view_tag = [42u8; VIEW_TAG_LEN];
        let slots = original
            .to_output_ciphertexts(sender_view_tag, sender_slot_count, n_outputs)
            .expect("spread");

        assert_eq!(slots.len(), n_outputs);
        assert_eq!(slots[0].view_tag, sender_view_tag);
        assert_eq!(slots[0].data, original.sender_ciphertext);
        for empty in &slots[1..sender_slot_count] {
            assert_eq!(*empty, OutputCiphertext::empty());
        }
        for tail in &slots[sender_slot_count + recipient_views.len()..] {
            assert_eq!(*tail, OutputCiphertext::empty());
        }

        let rebuilt = TransferEncryptedUtxos::from_output_ciphertexts(
            original.tx_viewing_pk,
            original.salt,
            &slots,
            sender_slot_count,
        )
        .expect("reassemble");
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn round_trips_one_sender_slot_no_recipients() {
        round_trip(&[], 1, 3);
    }

    #[test]
    fn round_trips_one_sender_slot_with_recipients() {
        round_trip(&[5, 6], 1, 3);
    }

    #[test]
    fn round_trips_two_sender_slots_with_recipient_and_padding() {
        round_trip(&[7], 2, 5);
    }

    #[test]
    fn rejects_zero_sender_slots() {
        let err = bundle(&[5]).to_output_ciphertexts([0u8; VIEW_TAG_LEN], 0, 3);
        assert!(err.is_err());
    }

    #[test]
    fn rejects_too_few_output_slots() {
        let err = bundle(&[5, 6]).to_output_ciphertexts([0u8; VIEW_TAG_LEN], 1, 2);
        assert!(err.is_err());
    }
}
