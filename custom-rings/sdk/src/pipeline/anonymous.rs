//! The hidden owner's rail of an anonymous ring. The owner signs inside the
//! AnonymousRingEddsa proof and the auditor disclosure names every hidden party.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use custom_ring_interface::{
    anonymous_output_body, anonymous_output_body_hash, RingMode, ANONYMOUS_OUTPUT_PLAINTEXT_LEN,
    ANONYMOUS_RING_SHAPES,
};
use solana_address::Address;
use zolana_client::{AsyncRpc, Shape, TagReservations, TagStream};
use zolana_hasher::primitives::{hash_bytes, SOLANA_OWNER_TAG};
use zolana_interface::instruction::instruction_data::transact::ring_anonymous_encrypted_output_body;
use zolana_keypair::{
    viewing_key::ViewTag, Curve, InboxSecret, KeypairError, PublicKey, RingAddress,
    ShieldedAddress, SigningKey, ViewingKey, X25519Pubkey,
};
use zolana_ring_client::{AnonymousDisclosure, AnonymousOutputOpening, AuditInputOpening};
use zolana_transaction::instructions::transact::{
    AnonymousViewTags, ConfidentialTransaction, SppProofInputs, TransactSession,
};

use super::{sealed, Owner, Rail, RailKind, RingTransfer, Staged};
use crate::{
    request::{AnonymousDelivery, DeliveryOutput},
    CustomRing, CustomRingConfig, RingError,
};

/// The hidden owner's Ed25519 key, the signature lives inside the proof so the key may live elsewhere.
#[async_trait]
pub trait AnonymousSpendSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    /// Signs the ring spend message with RFC 8032 Ed25519.
    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], RingError>;
}

#[async_trait]
impl AnonymousSpendSigner for SigningKey {
    fn public_key(&self) -> PublicKey {
        self.pubkey()
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], RingError> {
        Ok(self.sign_message(message)?)
    }
}

#[async_trait]
impl AnonymousSpendSigner for ed25519_dalek::SigningKey {
    fn public_key(&self) -> PublicKey {
        PublicKey::from_ed25519(self.verifying_key().as_bytes())
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], RingError> {
        Ok(ed25519_dalek::Signer::sign(self, message).to_bytes())
    }
}

/// The owner's spends on an anonymous ring, no transaction signer names the owner.
pub struct Anonymous<'a> {
    pub(super) owner: Owner<'a>,
    pub(super) signer: &'a dyn AnonymousSpendSigner,
    viewing_key: &'a ViewingKey,
    recipients: Vec<AnonymousRecipient>,
    session: Arc<TransactSession>,
}

/// Where a payment to an address is tagged, the address itself is always carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnonymousRecipient {
    /// A first payment, on the inbox stream of the shared address.
    Address(RingAddress),
    /// A recipient paid or received from before, on the pair stream toward its viewing key.
    Paired(RingAddress),
}

impl AnonymousRecipient {
    pub fn address(&self) -> &RingAddress {
        match self {
            Self::Address(address) | Self::Paired(address) => address,
        }
    }
}

pub type AnonymousTransfer<'a> = RingTransfer<Anonymous<'a>>;

impl sealed::Sealed for Anonymous<'_> {}

impl Rail for Anonymous<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Anonymous(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    /// The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key.
    pub fn with_anonymous_signer(
        self,
        signer: &'a dyn AnonymousSpendSigner,
        viewing_key: &'a ViewingKey,
    ) -> RingTransfer<Anonymous<'a>> {
        RingTransfer {
            ring: self.ring,
            rail: Anonymous {
                owner: self.rail,
                signer,
                viewing_key,
                recipients: Vec::new(),
                session: Arc::default(),
            },
            cosigner: self.cosigner,
        }
    }
}

impl RingTransfer<Anonymous<'_>> {
    /// Every output owner other than the sender needs one.
    #[must_use = "use the updated transfer"]
    pub fn with_recipient(mut self, recipient: AnonymousRecipient) -> Self {
        self.rail.recipients.push(recipient);
        self
    }

    /// The wallet's sealed streams, a transfer without one seals under its own.
    #[must_use = "use the updated transfer"]
    pub fn with_session(mut self, session: Arc<TransactSession>) -> Self {
        self.rail.session = session;
        self
    }
}

/// A tag stream of one transaction, two addresses on one viewing key share the pair stream.
#[derive(Clone, PartialEq, Eq, Hash)]
enum StreamKey {
    Inbox([u8; 32]),
    Pair(X25519Pubkey),
}

/// The stream a recipient slot takes its tag from.
enum Stream<'a> {
    Inbox(&'a InboxSecret),
    Pair {
        sender: &'a ViewingKey,
        recipient: X25519Pubkey,
    },
}

impl Stream<'_> {
    fn key(&self) -> StreamKey {
        match self {
            Self::Inbox(inbox) => StreamKey::Inbox(*inbox.as_bytes()),
            Self::Pair { recipient, .. } => StreamKey::Pair(*recipient),
        }
    }

    fn tag_at(&self, index: u64) -> Result<ViewTag, KeypairError> {
        match self {
            Self::Inbox(inbox) => inbox.view_tag(index),
            Self::Pair { sender, recipient } => sender.pair_send_view_tag(recipient, index),
        }
    }
}

impl Anonymous<'_> {
    pub(super) async fn stage(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
        config: &CustomRingConfig,
        cosigner: Option<Address>,
    ) -> Result<Box<Staged>, RingError> {
        if config.mode != RingMode::Anonymous {
            return Err(RingError::NotAnonymousRing);
        }
        let sender = self.owner.sender.address()?;
        if self.signer.public_key() != sender.signing_pubkey {
            return Err(RingError::AnonymousSignerMismatch);
        }
        // A public signature by the owner would undo the hiding.
        let owner = Address::new_from_array(sender.signing_pubkey.as_ed25519()?);
        if owner == self.owner.transaction.payer() || cosigner == Some(owner) {
            return Err(RingError::AnonymousPublicSignerLinksOwner);
        }
        // Tags bind slots, the slot order is fixed before any stream is read.
        let mut transaction = self.owner.transaction.clone();
        transaction.pad_to_canonical_shape(&sender)?;
        let view_tags = self.view_tags(ring, client, &sender, &transaction).await?;
        self.owner
            .stage_with(ring, client, config, transaction, Some(&view_tags))
            .await
    }

    /// One window read per stream, every slot takes the lowest index free in history and
    /// not reserved by an earlier slot of the same transaction.
    async fn view_tags(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
        sender: &ShieldedAddress,
        transaction: &ConfidentialTransaction,
    ) -> Result<AnonymousViewTags, RingError> {
        if let Some(foreign) = self
            .recipients
            .iter()
            .map(|recipient| recipient.address().ring_program_id)
            .find(|program| *program != ring.program_id())
        {
            return Err(RingError::ForeignRing(foreign));
        }
        let stream = TagStream::new(client);
        let mut reservations: HashMap<StreamKey, TagReservations> = HashMap::new();
        let mut view_tags =
            AnonymousViewTags::new(self.viewing_key).with_session(Arc::clone(&self.session));
        for (slot, output) in transaction.outputs().iter().enumerate() {
            let Some(owner) = output.owner_address else {
                continue;
            };
            if output.ring_program_id.is_none() || owner.signing_pubkey == sender.signing_pubkey {
                continue;
            }
            let Some(recipient) = self
                .recipients
                .iter()
                .find(|recipient| recipient.address().recipient == owner)
            else {
                continue;
            };
            let address = recipient.address();
            let tags = match recipient {
                AnonymousRecipient::Address(address) => Stream::Inbox(&address.inbox_secret),
                AnonymousRecipient::Paired(address) => Stream::Pair {
                    sender: self.viewing_key,
                    recipient: address.recipient.viewing_pubkey,
                },
            };
            let index = stream
                .reserve_index(reservations.entry(tags.key()).or_default(), |index| {
                    tags.tag_at(index)
                })
                .await?;
            view_tags = view_tags.with_slot(slot, address, tags.tag_at(index)?)?;
        }
        Ok(view_tags)
    }
}

/// AnonymousRingEddsa keeps its owners hidden, a note leaves only to the default ring.
pub(super) fn check_anonymous_slots(
    shape: Shape,
    inputs: &SppProofInputs,
) -> Result<(), RingError> {
    if !ANONYMOUS_RING_SHAPES.contains(&shape) {
        return Err(RingError::AnonymousShapeUnsupported);
    }
    let input_open = inputs
        .input_utxos
        .iter()
        .any(|input| input.cache_slot.is_some() || input.is_compact());
    let output_open = inputs.output_utxos.iter().any(|output| {
        output.cache_slot.is_some()
            || output.is_compact()
            || (!output.is_dummy()
                && output.owner_address.is_none_or(|address| {
                    address.signing_pubkey.curve().ok() != Some(Curve::Ed25519)
                }))
    });
    if input_open || output_open {
        return Err(RingError::InvalidAnonymousSlot);
    }
    // The recipient recomputes an anonymous commitment with zero data hashes.
    if inputs.output_utxos.iter().any(|output| {
        output.data_hash.is_some_and(|hash| hash != [0; 32])
            || output.ring_data_hash.is_some_and(|hash| hash != [0; 32])
            || !output.data.is_empty()
    }) {
        return Err(RingError::AnonymousOutputData);
    }
    Ok(())
}

/// Each published slot's recipient, the proof checks it against its commitment.
pub(crate) fn anonymous_disclosure(
    sender: &ShieldedAddress,
    proof: &SppProofInputs,
) -> Result<AnonymousDisclosure, RingError> {
    let inputs = proof
        .input_utxos
        .iter()
        .filter(|input| !input.is_compact())
        .map(|input| match input.is_dummy() {
            true => Ok(AuditInputOpening::default()),
            false => Ok(AuditInputOpening {
                tree_id: input.tree_id,
                amount: input.utxo.amount,
                asset: hash_bytes(input.utxo.asset.asset.as_array())?,
                blinding: input.utxo.blinding,
            }),
        })
        .collect::<Result<_, RingError>>()?;
    let outputs = proof
        .output_utxos
        .iter()
        .map(|output| {
            let Some(owner) = output.owner_address else {
                return Ok(AnonymousOutputOpening::default());
            };
            Ok(AnonymousOutputOpening {
                identity_tag: SOLANA_OWNER_TAG,
                identity_key: owner.signing_pubkey.confidential_view_tag()?,
                viewing_pk: *owner.viewing_pubkey.as_bytes(),
                nullifier_pk: owner.nullifier_pubkey,
            })
        })
        .collect::<Result<_, RingError>>()?;
    Ok(AnonymousDisclosure {
        sender: sender.signing_pubkey.as_ed25519()?,
        inputs,
        outputs,
    })
}

/// The sealed bodies the base circuit proves, read back from the published slots.
pub(crate) fn anonymous_delivery(
    ring: Address,
    sender: &ShieldedAddress,
    first_nullifier: &[u8; 32],
    view_tags: &AnonymousViewTags,
    proof: &SppProofInputs,
) -> Result<AnonymousDelivery, RingError> {
    let outputs = proof
        .output_utxos
        .iter()
        .zip(&proof.external_data.outputs)
        .enumerate()
        .map(|(slot, (output, published))| {
            let body = published
                .data
                .as_deref()
                .and_then(ring_anonymous_encrypted_output_body);
            let Some(body) = body else {
                return Ok(None);
            };
            let ciphertext: [u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN] = body
                .try_into()
                .map_err(|_| RingError::InvalidAnonymousBody)?;
            let keys = view_tags.slot_keys(output, sender, first_nullifier, slot)?;
            Ok(Some(match keys {
                Some(keys) => DeliveryOutput {
                    asset_address: *output.asset.asset.as_array(),
                    pair_u: keys.pair_pk.u(),
                    ciphertext,
                },
                None => DeliveryOutput {
                    ciphertext,
                    ..DeliveryOutput::ZERO
                },
            }))
        })
        .collect::<Result<Vec<_>, RingError>>()?;
    Ok(AnonymousDelivery {
        ring_program_id: ring,
        outputs,
    })
}

impl AnonymousDelivery {
    /// The body hash per slot in slot order, zero for an exit slot.
    pub(crate) fn output_body_hashes(&self) -> Result<Vec<[u8; 32]>, RingError> {
        self.outputs
            .iter()
            .map(|output| match output {
                Some(output) => Ok(anonymous_output_body_hash(&anonymous_output_body(
                    &output.ciphertext,
                ))?),
                None => Ok([0; 32]),
            })
            .collect()
    }
}

/// The hidden owner signs inside the proof. SPP excludes the fee payer from
/// the signer vector on owner-signed rails, so every public slot is zero.
pub(super) fn anonymous_signers(width: usize) -> Vec<[u8; 32]> {
    vec![[0; 32]; width]
}
