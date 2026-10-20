//! The hidden owner's rail of an anonymous ring. The owner signs inside the
//! AnonymousRingEddsa proof and the auditor disclosure names every hidden party.

use custom_ring_interface::{RingMode, ANONYMOUS_RING_SHAPES};
use solana_address::Address;
use zolana_client::{AsyncRpc, Shape, TagStream};
use zolana_hasher::primitives::{hash_bytes, SOLANA_OWNER_TAG};
use zolana_keypair::{Curve, RingAddress, ShieldedAddress, SigningKey, ViewingKey, X25519Pubkey};
use zolana_ring_client::{AnonymousDisclosure, AnonymousOutputOpening, AuditInputOpening};
use zolana_transaction::instructions::transact::{AnonymousViewTags, SppProofInputs};

use super::{sealed, Owner, Rail, RailKind, RingTransfer, Staged};
use crate::{CustomRing, CustomRingConfig, RingError};

/// The owner's spends on an anonymous ring, no transaction signer names the owner.
pub struct Anonymous<'a> {
    pub(super) owner: Owner<'a>,
    pub(super) signer: &'a SigningKey,
    viewing_key: &'a ViewingKey,
    recipients: Vec<AnonymousRecipient>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnonymousRecipient {
    /// A first payment, on the inbox stream of the shared address.
    Address(RingAddress),
    /// A recipient paid or received from before, on the pair stream toward it.
    Paired(X25519Pubkey),
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
        signer: &'a SigningKey,
        viewing_key: &'a ViewingKey,
    ) -> RingTransfer<Anonymous<'a>> {
        RingTransfer {
            ring: self.ring,
            rail: Anonymous {
                owner: self.rail,
                signer,
                viewing_key,
                recipients: Vec::new(),
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
        if self.signer.pubkey() != sender.signing_pubkey {
            return Err(RingError::AnonymousSignerMismatch);
        }
        // A public signature by the owner would undo the hiding.
        let owner = Address::new_from_array(sender.signing_pubkey.as_ed25519()?);
        if owner == self.owner.transaction.payer() || cosigner == Some(owner) {
            return Err(RingError::AnonymousPublicSignerLinksOwner);
        }
        let view_tags = self.view_tags(ring, client).await?;
        self.owner
            .stage_with(ring, client, config, Some(&view_tags))
            .await
    }

    async fn view_tags(
        &self,
        ring: CustomRing,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<AnonymousViewTags, RingError> {
        let stream = TagStream::new(client);
        let mut view_tags = AnonymousViewTags::new(self.viewing_key);
        for recipient in &self.recipients {
            view_tags = match recipient {
                AnonymousRecipient::Address(address) => {
                    if address.ring_program_id != ring.program_id() {
                        return Err(RingError::ForeignRing(address.ring_program_id));
                    }
                    let j = stream
                        .first_free_index(0, |j| address.inbox_secret.view_tag(j))
                        .await?;
                    view_tags.with_inbox_recipient(address, j)?
                }
                AnonymousRecipient::Paired(recipient) => {
                    let k = stream
                        .first_free_index(0, |k| self.viewing_key.pair_send_view_tag(recipient, k))
                        .await?;
                    view_tags.with_paired_recipient(*recipient, k)?
                }
            };
        }
        Ok(view_tags)
    }
}

/// AnonymousRingEddsa keeps its owners hidden, a note leaves only to the default ring. Only outputs may use compact padding.
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
            || output.data.utxo_data().is_some()
            || output.data.ring_data().is_some()
    }) {
        return Err(RingError::AnonymousOutputData);
    }
    Ok(())
}

/// Each published slot's opening, the proof checks it against its commitment.
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
        .filter(|output| !output.is_compact())
        .map(|output| {
            let Some(owner) = output.owner_address else {
                return Ok(AnonymousOutputOpening::default());
            };
            let identity_tag = SOLANA_OWNER_TAG;
            Ok(AnonymousOutputOpening {
                identity_tag,
                identity_key: owner.signing_pubkey.confidential_view_tag()?,
                viewing_pk: *owner.viewing_pubkey.as_bytes(),
                nullifier_pk: owner.nullifier_pubkey,
                amount: output.amount,
                asset: hash_bytes(output.asset.asset.as_array())?,
                blinding: output.blinding,
                data_hash: output.data_hash.unwrap_or_default(),
                ring_data_hash: output.ring_data_hash.unwrap_or_default(),
                ring_note: u8::from(output.ring_program_id.is_some()),
            })
        })
        .collect::<Result<_, RingError>>()?;
    Ok(AnonymousDisclosure {
        sender: sender.signing_pubkey.as_ed25519()?,
        inputs,
        outputs,
    })
}

/// The hidden owner signs inside the proof. SPP excludes the fee payer from
/// the signer vector on owner-signed rails, so every public slot is zero.
pub(super) fn anonymous_signers(width: usize) -> Vec<[u8; 32]> {
    vec![[0; 32]; width]
}
