use std::{
    collections::{btree_map::Entry, BTreeMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
};

use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::SALT_LEN, random_salt, viewing_key::ViewTag, PublicKey, RingAddress,
    ShieldedAddress, ViewingKey, X25519Pubkey,
};

use super::{sender_owner_tag, ConfidentialTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    keys::{ShieldedKeys, TransactionKeyRequest},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        ring_anonymous::{
            anonymous_slot_index, ring_anonymous_padding, ring_anonymous_padding_tag,
        },
        UtxoSerialization,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    Data, SOL_ASSET_ID,
};

/// The anonymous streams one sender sealed, one salt per transaction viewing key.
#[derive(Default)]
pub struct TransactSession {
    streams: Mutex<BTreeMap<[u8; 33], SealedStream>>,
}

struct SealedStream {
    salt: [u8; SALT_LEN],
    output_hashes: Vec<[u8; 32]>,
}

impl TransactSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// A repeat of the same outputs keeps its salt, other outputs under a sealed key would
    /// key every slot stream twice.
    fn seal(
        &self,
        tx_viewing_pk: &X25519Pubkey,
        output_hashes: Vec<[u8; 32]>,
    ) -> Result<[u8; SALT_LEN], TransactionError> {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        match streams.entry(*tx_viewing_pk.as_bytes()) {
            Entry::Occupied(sealed) if sealed.get().output_hashes == output_hashes => {
                Ok(sealed.get().salt)
            }
            Entry::Occupied(_) => Err(TransactionError::AnonymousStreamReuse),
            Entry::Vacant(stream) => Ok(stream
                .insert(SealedStream {
                    salt: random_salt(),
                    output_hashes,
                })
                .salt),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    pub resolved: [u8; 32],
}

/// The tag an anonymous output publishes and the payer pseudonym its plaintext carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousOutputKeys {
    pub tag: ViewTag,
    pub pair_pk: X25519Pubkey,
}

/// The tags of a transaction's hidden outputs, one per output slot once the slot order is fixed.
#[must_use]
#[derive(Clone)]
pub struct AnonymousViewTags {
    sender: ViewingKey,
    slots: BTreeMap<usize, AnonymousSlotKeys>,
    session: Arc<TransactSession>,
}

#[derive(Clone, Copy)]
struct AnonymousSlotKeys {
    recipient: ShieldedAddress,
    keys: AnonymousOutputKeys,
}

impl AnonymousViewTags {
    pub fn new(sender: &ViewingKey) -> Self {
        Self {
            sender: sender.clone(),
            slots: BTreeMap::new(),
            session: Arc::default(),
        }
    }

    /// Shares the sender's sealed streams across transactions.
    pub fn with_session(mut self, session: Arc<TransactSession>) -> Self {
        self.session = session;
        self
    }

    /// `tag` is reserved on a stream of `address` for output slot `slot`.
    pub fn with_slot(
        mut self,
        slot: usize,
        address: &RingAddress,
        tag: ViewTag,
    ) -> Result<Self, TransactionError> {
        let keys = AnonymousOutputKeys {
            tag,
            pair_pk: self.pair_pk(&address.recipient.viewing_pubkey)?,
        };
        self.slots.insert(
            slot,
            AnonymousSlotKeys {
                recipient: address.recipient,
                keys,
            },
        );
        Ok(self)
    }

    pub fn change_keys(
        &self,
        first_nullifier: &[u8; 32],
        slot: u8,
    ) -> Result<AnonymousOutputKeys, TransactionError> {
        Ok(AnonymousOutputKeys {
            tag: self.sender.ring_change_view_tag(first_nullifier, slot)?,
            pair_pk: self.pair_pk(&self.sender.pubkey())?,
        })
    }

    pub fn blinding_seed(&self, first_nullifier: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        Ok(self.sender.ring_blinding_seed(first_nullifier)?)
    }

    /// The tag and pseudonym a hidden slot publishes, `None` for an exit or a padding slot.
    pub fn slot_keys(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        first_nullifier: &[u8; 32],
        slot_index: usize,
    ) -> Result<Option<AnonymousOutputKeys>, TransactionError> {
        Ok(
            match self.resolve(output, sender, first_nullifier, slot_index)? {
                AnonymousSlot::Hidden(keys) => Some(keys),
                AnonymousSlot::Exit | AnonymousSlot::Padding => None,
            },
        )
    }

    fn pair_pk(&self, recipient: &X25519Pubkey) -> Result<X25519Pubkey, TransactionError> {
        Ok(self.sender.pair_key(recipient)?.pubkey())
    }

    fn resolve(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        first_nullifier: &[u8; 32],
        slot_index: usize,
    ) -> Result<AnonymousSlot, TransactionError> {
        if output.is_compact() {
            return Err(TransactionError::AnonymousCompactPadding { slot_index });
        }
        let Some(owner) = output.owner_address else {
            return Ok(AnonymousSlot::Padding);
        };
        if output.ring_program_id.is_none() {
            return Ok(AnonymousSlot::Exit);
        }
        if !output.data.is_empty() {
            return Err(TransactionError::AnonymousOutputData { slot_index });
        }
        if owner.signing_pubkey == sender.signing_pubkey {
            return Ok(AnonymousSlot::Hidden(self.change_keys(
                first_nullifier,
                anonymous_slot_index(slot_index)?,
            )?));
        }
        match self.slots.get(&slot_index) {
            Some(slot) if slot.recipient == owner => Ok(AnonymousSlot::Hidden(slot.keys)),
            _ => Err(TransactionError::UnknownAnonymousRecipient { slot_index }),
        }
    }

    /// Every slot's tag in order, a padding tag drawn from `sample` until it differs from
    /// every other tag of the transaction.
    fn published_tags(
        slots: &[AnonymousSlot],
        owner_tags: &[ResolvedOwnerTag],
        mut sample: impl FnMut() -> ViewTag,
    ) -> Result<Vec<ViewTag>, TransactionError> {
        let mut taken: HashSet<ViewTag> = HashSet::new();
        let mut tags = Vec::with_capacity(slots.len());
        for (index, (slot, owner_tag)) in slots.iter().zip(owner_tags).enumerate() {
            let tag = match slot {
                AnonymousSlot::Hidden(keys) => keys.tag,
                // Exits publish owner keys, two exits to one owner share theirs.
                AnonymousSlot::Exit => {
                    taken.insert(owner_tag.resolved);
                    tags.push(owner_tag.resolved);
                    continue;
                }
                AnonymousSlot::Padding => {
                    tags.push([0; 32]);
                    continue;
                }
            };
            if !taken.insert(tag) {
                let first = tags
                    .iter()
                    .position(|earlier| *earlier == tag)
                    .unwrap_or(index);
                return Err(TransactionError::DuplicateAnonymousTag {
                    first,
                    second: index,
                });
            }
            tags.push(tag);
        }
        for (tag, slot) in tags.iter_mut().zip(slots) {
            if matches!(slot, AnonymousSlot::Padding) {
                *tag = loop {
                    let candidate = sample();
                    if taken.insert(candidate) {
                        break candidate;
                    }
                };
            }
        }
        Ok(tags)
    }
}

#[derive(Clone, Copy)]
enum AnonymousSlot {
    Hidden(AnonymousOutputKeys),
    /// A default-ring note, the circuit publishes its owner's Solana key.
    Exit,
    Padding,
}

impl ConfidentialTransaction {
    /// Obtain the sender address and transaction viewing key, then encrypt.
    ///
    /// Steps:
    /// 1. Get the sender address from `shielded_keys`.
    /// 2. Derive the transaction viewing key from the first nullifier.
    /// 3. Delegate to [`Self::encrypt_with_viewing_key`].
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Get the sender address.
        let sender = shielded_keys.address()?;
        // 2. Derive the transaction viewing key from the first nullifier.
        let tx_viewing_key = shielded_keys.transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: sender.viewing_pubkey,
            first_nullifier: self.first_nullifier,
        }])?;
        let got = tx_viewing_key.len();
        let tx_viewing_key = tx_viewing_key
            .into_iter()
            .next()
            .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;

        // 3. Encrypt using the supplied address and derived viewing key.
        self.encrypt_with_viewing_key(&sender, &tx_viewing_key)
    }

    /// Consume the transaction and encrypt with its supplied transaction viewing key.
    ///
    /// Steps:
    /// 1. If not already finalized, select a shape, convert wallet inputs and pad
    ///    the input and output slots.
    /// 2. Derive and assign output blindings using the final slot order.
    /// 3. Resolve output owner tags and public settlement transfers.
    /// 4. Encrypt each real output using a fresh salt from the OS RNG.
    /// 5. Check each encrypted slot's owner tag and assemble its commitment,
    ///    owner tag and ciphertext in output order.
    /// 6. Build the external data and return the assembled proof inputs.
    pub fn encrypt_with_viewing_key(
        self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        self.encrypt_with_viewing_key_mode(sender, tx_viewing_key, None)
    }

    /// Keeps recipient viewing keys in the auditor disclosure, not the public
    /// output body. The caller must publish that disclosure before proving SPP.
    pub fn encrypt_anonymous_with_viewing_key(
        self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
        view_tags: &AnonymousViewTags,
    ) -> Result<SppProofInputs, TransactionError> {
        self.encrypt_with_viewing_key_mode(sender, tx_viewing_key, Some(view_tags))
    }

    fn encrypt_with_viewing_key_mode(
        mut self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
        anonymous: Option<&AnonymousViewTags>,
    ) -> Result<SppProofInputs, TransactionError> {
        if let Some(view_tags) = anonymous {
            if view_tags.sender.pubkey() != sender.viewing_pubkey {
                return Err(TransactionError::AnonymousViewTagsSenderMismatch);
            }
            self.blinding_seed = view_tags.blinding_seed(&self.first_nullifier)?;
        }
        // 1. Select a shape and finalize the input and output slots if needed.
        self.pad_to_canonical_shape(sender)?;
        // 2. Derive and assign output blindings using the final slot order.
        let output_blinding_seed =
            derive_output_blinding_seed(&self.first_nullifier, &self.blinding_seed)?;
        for (index, output) in self.outputs.iter_mut().enumerate() {
            let index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            output.blinding = derive_transact_output_blinding(
                &self.first_nullifier,
                &output_blinding_seed,
                index,
            )?;
        }
        // 3. Resolve output owner tags and public settlement transfers.
        let anonymous_slots = anonymous
            .map(|view_tags| {
                self.outputs
                    .iter()
                    .enumerate()
                    .map(|(slot_index, output)| {
                        view_tags.resolve(output, sender, &self.first_nullifier, slot_index)
                    })
                    .collect::<Result<Vec<_>, TransactionError>>()
            })
            .transpose()?;
        let mut owner_tags = self.owner_tags(&sender.signing_pubkey)?;
        if let Some(slots) = &anonymous_slots {
            let tags =
                AnonymousViewTags::published_tags(slots, &owner_tags, ring_anonymous_padding_tag)?;
            for ((owner_tag, slot), tag) in owner_tags.iter_mut().zip(slots).zip(tags) {
                if !matches!(slot, AnonymousSlot::Exit) {
                    *owner_tag = ResolvedOwnerTag {
                        tag: OwnerTag::Inline(tag),
                        resolved: tag,
                    };
                }
            }
        }
        let interface_transfers = self.interface_transfers()?;

        // 4. Encrypt each real output with a fresh OS RNG salt.
        let output_hashes = self
            .outputs
            .iter()
            .map(|output| match output.is_compact() {
                true => Ok(None),
                false => output.hash(self.output_tree_id).map(Some),
            })
            .collect::<Result<Vec<_>, TransactionError>>()?;
        let salt = match anonymous {
            Some(view_tags) => view_tags.session.seal(
                &tx_viewing_key.pubkey(),
                output_hashes.iter().flatten().copied().collect(),
            )?,
            None => random_salt(),
        };
        let slot_kinds: Vec<Option<AnonymousSlot>> = match anonymous_slots {
            Some(slots) => slots.into_iter().map(Some).collect(),
            None => vec![None; self.outputs.len()],
        };
        let slots = self
            .outputs
            .iter()
            .zip(slot_kinds)
            .zip(&owner_tags)
            .enumerate()
            .map(|(slot_index, ((output, kind), owner_tag))| {
                let slot_index = slot_index as u32;
                match kind {
                    Some(AnonymousSlot::Hidden(keys)) => output
                        .seal_ring_anonymous(slot_index, tx_viewing_key, salt, keys)
                        .map(Some),
                    Some(AnonymousSlot::Padding) => {
                        ring_anonymous_padding(owner_tag.resolved).map(Some)
                    }
                    Some(AnonymousSlot::Exit) | None => output
                        .owner_address
                        .map(|_| output.seal(slot_index, tx_viewing_key, salt))
                        .transpose(),
                }
            })
            .collect::<Result<Vec<_>, TransactionError>>()?;
        let dummy_len = if anonymous.is_none()
            && self
                .outputs
                .iter()
                .any(|output| output.is_dummy() && !output.is_compact())
        {
            DummyTemplate::new(self.ring_program_id, salt).confidential_len()?
        } else {
            0
        };

        // 5. Check owner tags and assemble commitments and ciphertexts in order.
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        for (slot_index, ((utxo_hash, owner_tag), slot)) in output_hashes
            .into_iter()
            .zip(owner_tags)
            .zip(slots)
            .enumerate()
        {
            // Compact padding is the trailing suffix SPP fills back in.
            let Some(utxo_hash) = utxo_hash else {
                continue;
            };
            let data = match slot {
                Some(slot) if slot.view_tag != owner_tag.resolved => {
                    return Err(TransactionError::OwnerTagMismatch { slot_index });
                }
                Some(slot) => slot.data,
                None => std::iter::repeat_with(random_salt)
                    .flatten()
                    .take(dummy_len)
                    .collect(),
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: owner_tag.tag,
                data: Some(data),
            });
            resolved_owner_tags.push(owner_tag.resolved);
        }

        // 6. Build external data and return the prepared input and output slots.
        let external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
        )
        .with_interface_transfers(interface_transfers)?;

        Ok(SppProofInputs {
            input_utxos: self.padded_inputs.ok_or(TransactionError::NoInputs)?,
            output_utxos: self.outputs,
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
            external_data,
            payer: self.payer,
            cache_accounts: Default::default(),
        })
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

/// A zero output sealed to a throwaway key, the published length of a dummy slot.
struct DummyTemplate {
    output: ConfidentialOutputPlaintext,
    cx: ConfidentialEncode,
}

impl DummyTemplate {
    fn new(ring_program_id: Option<Address>, salt: [u8; SALT_LEN]) -> Self {
        let throwaway = ViewingKey::new();
        Self {
            output: ConfidentialOutputPlaintext {
                asset_id: SOL_ASSET_ID,
                amount: 0,
                blinding: [0u8; 32],
                ring_program_id,
                data: Data::default(),
            },
            cx: ConfidentialEncode {
                recipient_pubkey: throwaway.pubkey(),
                tx: throwaway,
                salt,
                slot_index: 0,
            },
        }
    }

    fn confidential_len(&self) -> Result<usize, TransactionError> {
        Ok(
            Confidential::encode_plaintext(&self.output, [0u8; 32], &self.cx)?
                .data
                .len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(tag: ViewTag) -> ResolvedOwnerTag {
        ResolvedOwnerTag {
            tag: OwnerTag::Inline(tag),
            resolved: tag,
        }
    }

    fn hidden(tag: ViewTag) -> AnonymousSlot {
        AnonymousSlot::Hidden(AnonymousOutputKeys {
            tag,
            pair_pk: ViewingKey::new().pubkey(),
        })
    }

    /// A padding tag equal to a hidden, exit or earlier padding tag is drawn again.
    #[test]
    fn padding_tags_are_resampled_on_collision() {
        let real = [1; 32];
        let exit = [2; 32];
        let slots = [
            hidden(real),
            AnonymousSlot::Exit,
            AnonymousSlot::Padding,
            AnonymousSlot::Padding,
        ];
        let owner_tags = [
            resolved([0; 32]),
            resolved(exit),
            resolved([0; 32]),
            resolved([0; 32]),
        ];
        let mut draws = [real, exit, [3; 32], [3; 32], [4; 32]].into_iter();
        let tags = AnonymousViewTags::published_tags(&slots, &owner_tags, || {
            draws.next().expect("a draw per attempt")
        })
        .unwrap();
        assert_eq!(tags, [real, exit, [3; 32], [4; 32]]);
        assert!(draws.next().is_none());
    }

    #[test]
    fn two_hidden_slots_never_share_a_tag() {
        let slots = [hidden([1; 32]), hidden([1; 32])];
        let owner_tags = [resolved([0; 32]); 2];
        assert!(matches!(
            AnonymousViewTags::published_tags(&slots, &owner_tags, ring_anonymous_padding_tag),
            Err(TransactionError::DuplicateAnonymousTag {
                first: 0,
                second: 1
            })
        ));
    }
}
