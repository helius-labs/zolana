//! The hidden owner's rail of an anonymous ring. The owner signs inside the
//! RingEd25519 proof and the auditor disclosure names every hidden party.

use custom_ring_interface::RingMode;
use solana_address::Address;
use zolana_client::{AsyncRpc, Shape};
use zolana_hasher::primitives::{hash_bytes, solana_owner_identity, SOLANA_OWNER_TAG};
use zolana_keypair::{Curve, ShieldedAddress, SigningKey};
use zolana_ring_client::{AnonymousDisclosure, AnonymousOutputOpening, AuditInputOpening};
use zolana_transaction::instructions::transact::SppProofInputs;

use super::{sealed, Owner, Rail, RailKind, RingTransfer, Staged};
use crate::{CustomRing, CustomRingConfig, RingError};

/// The owner's spends on an anonymous ring, no transaction signer names the owner.
pub struct Anonymous<'a> {
    pub(super) owner: Owner<'a>,
    pub(super) signer: &'a SigningKey,
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
    pub fn with_anonymous_signer(self, signer: &'a SigningKey) -> RingTransfer<Anonymous<'a>> {
        RingTransfer {
            ring: self.ring,
            rail: Anonymous {
                owner: self.rail,
                signer,
            },
            cosigner: self.cosigner,
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
        if self.signer.pubkey() != sender.signing_pubkey {
            return Err(RingError::AnonymousSignerMismatch);
        }
        // A public signature by the owner would undo the hiding.
        let owner = Address::new_from_array(sender.signing_pubkey.as_ed25519()?);
        if owner == self.owner.transaction.payer() || cosigner == Some(owner) {
            return Err(RingError::AnonymousPublicSignerLinksOwner);
        }
        self.owner.stage_with(ring, client, config, true).await
    }
}

/// RingEd25519 keeps its notes in this ring and its owners hidden. Only outputs may use compact padding.
pub(super) fn check_anonymous_slots(
    program: Address,
    shape: Shape,
    inputs: &SppProofInputs,
) -> Result<(), RingError> {
    if !shape.is_anonymous_ring_ed25519() {
        return Err(RingError::AnonymousShapeUnsupported);
    }
    let input_open = inputs
        .input_utxos
        .iter()
        .any(|input| input.cache_slot.is_some() || input.is_compact());
    let output_open = inputs.output_utxos.iter().any(|output| {
        output.cache_slot.is_some()
            || (!output.is_dummy()
                && (output.ring_program_id != Some(program)
                    || output.owner_address.is_none_or(|address| {
                        address.signing_pubkey.curve().ok() != Some(Curve::Ed25519)
                    })))
    });
    match input_open || output_open {
        true => Err(RingError::InvalidAnonymousSlot),
        false => Ok(()),
    }
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

/// Only the payer signs in public, the hidden owner signs inside the proof.
pub(super) fn anonymous_signers(payer: Address, width: usize) -> Result<Vec<[u8; 32]>, RingError> {
    let mut signers = vec![[0; 32]; width];
    *signers
        .first_mut()
        .ok_or(RingError::PolicyShapeUnsupported)? = solana_owner_identity(payer.as_array())?;
    Ok(signers)
}
