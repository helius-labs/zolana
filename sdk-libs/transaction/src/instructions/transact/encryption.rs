use borsh::BorshDeserialize;
use solana_address::Address;
use spr_event::{MessageData, OutputDataEncoding};
use spr_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use spr_keypair::{
    random_salt, x25519::X25519Keypair, PublicKey, ShieldedAddress, ViewingKey, X25519Pubkey,
};

use super::{sender_owner_tag, ConfidentialTransaction, FinalizedTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    keys::{first_input_transaction_key, ShieldedKeys},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    EncryptedScheme,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    pub resolved: [u8; 32],
}

pub trait OutputEncoder {
    /// One tag per output slot, in slot order.
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError>;

    fn encode_slot(
        &self,
        plaintext: &ConfidentialOutputPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError>;

    /// A dummy slot under `view_tag` with the frame, scheme, embedded key and
    /// length of a real slot in `ring_program_id` that carries no data,
    /// encrypted to `cx.recipient_pubkey` like one. It decrypts to padding,
    /// never to an output.
    fn encode_padding(
        &self,
        ring_program_id: Option<Address>,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError>;
}

impl OutputEncoder for Confidential {
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        transaction.owner_tags(&sender.signing_pubkey)
    }

    fn encode_slot(
        &self,
        plaintext: &ConfidentialOutputPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError> {
        let mut message = Confidential::encode_plaintext(plaintext, view_tag, cx)?;
        if plaintext.ring_program_id.is_some() {
            let OutputDataEncoding::Encrypted(mut blob) =
                OutputDataEncoding::try_from_slice(&message.data)
                    .map_err(|error| TransactionError::Deserialize(error.to_string()))?
            else {
                return Err(TransactionError::BadDiscriminator(
                    EncryptedScheme::Confidential.as_byte(),
                ));
            };
            *blob.first_mut().ok_or(TransactionError::MissingOutput)? =
                EncryptedScheme::RingConfidential.as_byte();
            message.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
                .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
        }
        Ok(message)
    }

    fn encode_padding(
        &self,
        ring_program_id: Option<Address>,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError> {
        let scheme = match ring_program_id {
            Some(_) => EncryptedScheme::RingConfidential,
            None => EncryptedScheme::Confidential,
        };
        let body =
            Confidential::encrypt(&ConfidentialOutputPlaintext::padding(ring_program_id)?, cx)?;
        let mut blob = Vec::with_capacity(1 + body.len());
        blob.push(scheme.as_byte());
        blob.extend_from_slice(&body);
        let data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
            .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
        Ok(MessageData { view_tag, data })
    }
}

pub struct OutputEncryption<'a, E> {
    pub sender: &'a ShieldedAddress,
    pub tx_viewing_key: &'a ViewingKey,
    pub encoder: &'a E,
}

impl<E: OutputEncoder> OutputEncryption<'_, E> {
    pub fn encrypt(
        self,
        transaction: ConfidentialTransaction,
    ) -> Result<SppProofInputs, TransactionError> {
        transaction
            .finalize_with(self.sender, self.encoder)?
            .encrypt_with(self.tx_viewing_key, self.encoder)
    }
}

impl ConfidentialTransaction {
    /// Finalize the transaction, then encrypt it with keys from `shielded_keys`.
    ///
    /// Steps:
    /// 1. Get the sender address from `shielded_keys`.
    /// 2. Delegate to [`Self::finalize`] and [`FinalizedTransaction::encrypt_with_keys`].
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Get the sender address.
        let sender = shielded_keys.address()?;
        // 2. Finalize and encrypt.
        self.finalize(&sender)?
            .encrypt_with_sender_keys(shielded_keys)
    }

    /// Finalize the transaction, then encrypt it with the supplied transaction
    /// viewing key. See [`Self::finalize`] and
    /// [`FinalizedTransaction::encrypt_with_viewing_key`].
    pub fn encrypt_with_viewing_key(
        self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        self.finalize(sender)?
            .encrypt_with_viewing_key(tx_viewing_key)
    }

    pub fn sender_owner_tag(
        &self,
        sender: &PublicKey,
    ) -> Result<ResolvedOwnerTag, TransactionError> {
        let (tag, resolved) = sender_owner_tag(sender, &self.payer)?;
        Ok(ResolvedOwnerTag { tag, resolved })
    }

    pub fn owner_tags(
        &self,
        sender: &PublicKey,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        let sender_tag = self.sender_owner_tag(sender)?;
        let mut owner_tags = Vec::with_capacity(self.outputs.len());
        for (slot_index, output) in self.outputs.iter().enumerate() {
            if output.is_compact() {
                owner_tags.push(ResolvedOwnerTag {
                    tag: OwnerTag::Inline([0u8; 32]),
                    resolved: [0u8; 32],
                });
                continue;
            }
            let resolved = match output.owner_address {
                Some(address) => address.signing_pubkey.confidential_view_tag()?,
                None => output
                    .owner_tag
                    .ok_or(TransactionError::DummyOutputWithoutOwnerTag { slot_index })?,
            };
            // Padding that borrows the sender's tag takes the sender's encoding.
            // A different encoding would mark the slot as padding.
            owner_tags.push(if resolved == sender_tag.resolved {
                sender_tag
            } else {
                ResolvedOwnerTag {
                    tag: OwnerTag::Inline(resolved),
                    resolved,
                }
            });
        }
        Ok(owner_tags)
    }
}

impl FinalizedTransaction {
    /// Derive the transaction viewing key from `shielded_keys`, then encrypt.
    ///
    /// Steps:
    /// 1. Require `shielded_keys` to hold the sender this transaction was
    ///    finalized for.
    /// 2. Derive the transaction viewing key from the first nullifier.
    /// 3. Delegate to [`Self::encrypt_with_viewing_key`].
    pub fn encrypt_with_keys<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Require the finalized sender.
        if shielded_keys.address()? != self.sender {
            return Err(TransactionError::SenderAddressMismatch);
        }
        // 2.-3. Derive the transaction viewing key and encrypt.
        self.encrypt_with_sender_keys(shielded_keys)
    }

    pub fn encrypt(self) -> Result<SppProofInputs, TransactionError> {
        let secret = self
            .tx_viewing_key
            .ok_or(TransactionError::MissingSyncedTransactionKey)?;
        let key = ViewingKey::from_canonical_bytes(&secret)?;
        self.encrypt_with_viewing_key(&key)
    }

    fn encrypt_with_sender_keys<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        let tx_viewing_key = first_input_transaction_key(
            shielded_keys,
            self.sender.viewing_pubkey,
            self.first_nullifier()?,
            self.tx_viewing_key,
        )?;
        self.encrypt_with_viewing_key(&tx_viewing_key)
    }

    /// Consume the transaction and encrypt with its supplied transaction viewing key.
    ///
    /// Steps:
    /// 1. Require one owner tag per output slot.
    /// 2. Encrypt each real output using a fresh salt from the OS RNG, and
    ///    each random dummy as padding, to the viewing key a real slot under
    ///    its tag carries.
    /// 3. Check each encrypted slot's owner tag and assemble its commitment,
    ///    owner tag and ciphertext in output order; compact padding is left
    ///    out.
    /// 4. Build the external data and return the assembled proof inputs.
    pub fn encrypt_with_viewing_key(
        self,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        self.encrypt_with(tx_viewing_key, &Confidential)
    }

    fn encrypt_with<E: OutputEncoder>(
        self,
        tx_viewing_key: &ViewingKey,
        encoder: &E,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Require one owner tag per output slot.
        if self.owner_tags.len() != self.output_utxos.len() {
            return Err(TransactionError::OwnerTagCountMismatch {
                got: self.owner_tags.len(),
                expected: self.output_utxos.len(),
            });
        }

        // 2. Encrypt each real output and each random dummy with a fresh OS
        //    RNG salt.
        let salt = random_salt();
        let mut padding_keys = PaddingKeys::new(&self.sender, &self.output_utxos)?;
        let slots = self
            .output_utxos
            .iter()
            .zip(&self.owner_tags)
            .enumerate()
            .map(|(slot_index, (output, owner_tag))| {
                if output.is_compact() {
                    return Ok(None);
                }
                let cx = |recipient_pubkey| ConfidentialEncode {
                    tx: tx_viewing_key.clone(),
                    recipient_pubkey,
                    salt,
                    slot_index: slot_index as u32,
                };
                let Some(address) = output.owner_address else {
                    let recipient_pubkey = padding_keys.get(owner_tag.resolved);
                    return encoder
                        .encode_padding(
                            self.ring_program_id,
                            owner_tag.resolved,
                            &cx(recipient_pubkey),
                        )
                        .map(Some);
                };
                let plaintext = ConfidentialOutputPlaintext {
                    asset_id: output.asset.asset_id,
                    amount: output.amount,
                    blinding: output.blinding,
                    ring_program_id: output.ring_program_id,
                    data: output.data.clone(),
                };
                encoder
                    .encode_slot(&plaintext, owner_tag.resolved, &cx(address.viewing_pubkey))
                    .map(Some)
            })
            .collect::<Result<Vec<_>, TransactionError>>()?;

        // 3. Check owner tags and assemble commitments and ciphertexts in order.
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        for (slot_index, ((output, owner_tag), slot)) in self
            .output_utxos
            .iter()
            .zip(&self.owner_tags)
            .zip(slots)
            .enumerate()
        {
            // Compact padding is the trailing suffix SPP fills back in.
            let Some(slot) = slot else {
                continue;
            };
            if slot.view_tag != owner_tag.resolved {
                return Err(TransactionError::OwnerTagMismatch { slot_index });
            }
            transact_outputs.push(TransactOutput {
                utxo_hash: output.hash(self.output_tree_id)?,
                owner_tag: owner_tag.tag,
                data: Some(slot.data),
            });
            resolved_owner_tags.push(owner_tag.resolved);
        }

        // 4. Build external data and return the prepared input and output slots.
        let mut external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
        )
        .with_interface_transfers(self.interface_transfers)?;
        external_data.expiry_unix_ts = self.expiry_unix_ts;

        Ok(SppProofInputs {
            input_utxos: self.input_utxos,
            output_utxos: self.output_utxos,
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
            external_data,
            payer: self.payer,
            cache_accounts: Default::default(),
        })
    }
}

/// The viewing key each dummy is encrypted to, by the tag it publishes: the key
/// of the first real output under that tag, else the sender's. A real slot
/// under that tag embeds the same key. A tag naming only an input owner, whose
/// viewing key the transaction does not hold, takes one fresh key per
/// transaction.
struct PaddingKeys(Vec<([u8; 32], X25519Pubkey)>);

impl PaddingKeys {
    fn new(
        sender: &ShieldedAddress,
        outputs: &[SppProofOutputUtxo],
    ) -> Result<Self, TransactionError> {
        outputs
            .iter()
            .filter_map(|output| output.owner_address.as_ref())
            .chain([sender])
            .map(|address| Ok((address.confidential_view_tag()?, address.viewing_pubkey)))
            .collect::<Result<_, TransactionError>>()
            .map(Self)
    }

    fn get(&mut self, tag: [u8; 32]) -> X25519Pubkey {
        if let Some((_, key)) = self.0.iter().find(|(known, _)| *known == tag) {
            return *key;
        }
        let key = X25519Keypair::new().pubkey();
        self.0.push((tag, key));
        key
    }
}
