use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_keypair::{constants::SALT_LEN, PublicKey, ViewingKey, X25519Pubkey};

use super::{change_slots, DecodeCx, OwnerCx, UtxoSerialization};
use crate::{
    data::Data,
    error::TransactionError,
    utxo::{derive_transact_output_blinding, resolve_ring_program_id, Utxo},
    AssetRegistry, EncryptedScheme, Mint, PublicKeySchema, X25519PubkeySchema,
};

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferRecipientPlaintext {
    pub verified: VerifiedRecipientPlaintext,
    pub unverified: UnverifiedRecipientPlaintext,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecipientPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub mint: Address,
    pub amount: u64,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedRecipientPlaintext {
    /// Unauthenticated, the recipient pairs with whichever key the sender writes.
    #[wincode(with = "X25519PubkeySchema")]
    pub sender_pubkey: X25519Pubkey,
    pub blinding: [u8; 32],
    pub data: Data,
}

impl AnonymousTransferRecipientPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.unverified.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.unverified.data.validate()?;
        Ok(parsed)
    }

    pub fn into_utxo(
        self,
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Utxo, TransactionError> {
        let Self {
            verified,
            unverified,
        } = self;
        // Anonymous recipients may carry a memo, but not ring or utxo data.
        if unverified.data.ring_data().is_some() || unverified.data.utxo_data().is_some() {
            return Err(TransactionError::UnsupportedOutputData);
        }
        Ok(Utxo {
            owner: verified.owner_pubkey,
            asset: assets.mint(&verified.mint)?,
            amount: verified.amount,
            blinding: unverified.blinding,
            ring_program_id: resolve_ring_program_id(ring_program_id, &unverified.data)?,
            data: unverified.data,
        })
    }
}

/// Published as a message, its change outputs carry no ciphertext.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferSenderPlaintext {
    pub verified: VerifiedSenderPlaintext,
    pub unverified: UnverifiedSenderPlaintext,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSenderPlaintext {
    #[wincode(with = "PublicKeySchema")]
    pub owner_pubkey: PublicKey,
    pub spl_mint: Address,
    pub spl_amount: u64,
    pub sol_amount: u64,
    /// One per recipient output, in output order.
    #[wincode(with = "containers::Vec<X25519PubkeySchema, FixIntLen<u8>>")]
    pub recipient_viewing_pks: Vec<X25519Pubkey>,
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedSenderPlaintext {
    pub blinding_seed: [u8; 32],
    pub spl_data: Data,
    pub sol_data: Data,
}

impl AnonymousTransferSenderPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.unverified.spl_data.validate()?;
        self.unverified.sol_data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.unverified.spl_data.validate()?;
        parsed.unverified.sol_data.validate()?;
        Ok(parsed)
    }

    /// A zero amount marks a change output as absent. The present change
    /// outputs lead the transaction, the SPL change first, so the SOL change
    /// sits at slot 1 only when an SPL change precedes it. `first_nullifier`
    /// is the transaction's; it is what makes each derived blinding unique to
    /// that transaction.
    pub fn into_utxos(
        self,
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
        ring_program_id: Option<Address>,
    ) -> Result<Vec<Utxo>, TransactionError> {
        let Self {
            verified,
            unverified,
        } = self;
        if verified.spl_amount == 0 && !unverified.spl_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        if verified.sol_amount == 0 && !unverified.sol_data.is_empty() {
            return Err(TransactionError::DataWithoutOutput);
        }
        let slots = change_slots(verified.spl_amount > 0, verified.sol_amount > 0);
        let blinding = |slot| {
            derive_transact_output_blinding(first_nullifier, &unverified.blinding_seed, slot)
        };
        let mut utxos = Vec::new();
        if verified.spl_amount > 0 {
            utxos.push(Utxo {
                owner: verified.owner_pubkey,
                asset: assets.mint(&verified.spl_mint)?,
                amount: verified.spl_amount,
                blinding: blinding(slots.spl)?,
                ring_program_id: resolve_ring_program_id(ring_program_id, &unverified.spl_data)?,
                data: unverified.spl_data,
            });
        }
        if verified.sol_amount > 0 {
            utxos.push(Utxo {
                owner: verified.owner_pubkey,
                asset: Mint::SOL,
                amount: verified.sol_amount,
                blinding: blinding(slots.sol)?,
                ring_program_id: resolve_ring_program_id(ring_program_id, &unverified.sol_data)?,
                data: unverified.sol_data,
            });
        }
        Ok(utxos)
    }
}

pub struct AnonymousRecipientEncode {
    pub tx: ViewingKey,
    pub recipient_pubkey: X25519Pubkey,
    pub sender_pubkey: X25519Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct AnonymousRecipient;

impl UtxoSerialization for AnonymousRecipient {
    const SCHEME: EncryptedScheme = EncryptedScheme::AnonymousRecipient;
    type Plaintext = AnonymousTransferRecipientPlaintext;
    type EncodeCx = AnonymousRecipientEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        Ok(cx
            .viewing_key
            .decrypt_utxo(body, &tx_viewing_pk, salt, cx.slot_index)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        AnonymousTransferRecipientPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Ok(vec![plaintext.into_utxo(cx.assets, cx.ring_program_id)?])
    }

    fn from_utxos(
        utxos: &[Utxo],
        _: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        Ok(AnonymousTransferRecipientPlaintext {
            verified: VerifiedRecipientPlaintext {
                owner_pubkey: first.owner,
                mint: first.asset.asset,
                amount: first.amount,
            },
            unverified: UnverifiedRecipientPlaintext {
                sender_pubkey: cx.sender_pubkey,
                blinding: first.blinding,
                data: first.data.clone(),
            },
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(cx
            .tx
            .encrypt_slot(&cx.recipient_pubkey, bytes, cx.salt, cx.slot_index)?)
    }
}

pub struct AnonymousSenderEncode {
    pub tx: ViewingKey,
    pub self_pubkey: X25519Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
    pub blinding_seed: [u8; 32],
    pub recipient_viewing_pks: Vec<X25519Pubkey>,
}

pub struct AnonymousSenderBundle;

impl UtxoSerialization for AnonymousSenderBundle {
    const SCHEME: EncryptedScheme = EncryptedScheme::AnonymousSender;
    type Plaintext = AnonymousTransferSenderPlaintext;
    type EncodeCx = AnonymousSenderEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        Ok(cx
            .viewing_key
            .decrypt_utxo(body, &tx_viewing_pk, salt, cx.slot_index)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        AnonymousTransferSenderPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        let first_nullifier = cx
            .first_nullifier
            .ok_or(TransactionError::MissingFirstNullifier)?;
        plaintext.into_utxos(&first_nullifier, cx.assets, cx.ring_program_id)
    }

    fn from_utxos(
        utxos: &[Utxo],
        _: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        let first = utxos.first().ok_or(TransactionError::MissingOutput)?;
        let mut verified = VerifiedSenderPlaintext {
            owner_pubkey: first.owner,
            spl_mint: Address::default(),
            spl_amount: 0,
            sol_amount: 0,
            recipient_viewing_pks: cx.recipient_viewing_pks.clone(),
        };
        let mut unverified = UnverifiedSenderPlaintext {
            blinding_seed: cx.blinding_seed,
            spl_data: Data::default(),
            sol_data: Data::default(),
        };
        for utxo in utxos {
            if utxo.asset.asset == Mint::SOL.asset {
                verified.sol_amount = utxo.amount;
                unverified.sol_data = utxo.data.clone();
            } else {
                verified.spl_mint = utxo.asset.asset;
                verified.spl_amount = utxo.amount;
                unverified.spl_data = utxo.data.clone();
            }
        }
        Ok(AnonymousTransferSenderPlaintext {
            verified,
            unverified,
        })
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(cx
            .tx
            .encrypt_slot(&cx.self_pubkey, bytes, cx.salt, cx.slot_index)?)
    }
}
