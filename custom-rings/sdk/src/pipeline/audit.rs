//! The audit half of a ring transfer, its disclosure sealed to the auditor.

use custom_ring_interface::{
    key_catalog::RingCircuit, AnonymousAuditKey, AuditLayout, AuditorMessage, DisclosureLayout,
    RingOutput, RING_DELIVERED_BODY_LEN,
};
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient};
use zolana_event::MessageData;
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::{ShieldedAddress, X25519Pubkey};
use zolana_ring_client::{
    AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
    AuditDisclosure, AuditEnvelope, DeliveredOutputOpening, DisclosurePad, PackedOutputOpening,
};
use zolana_ring_transaction::{AnonymousSlot, PublishedSlot, RingOutputRail, StreamPosition};
use zolana_transaction::{
    derive_output_blinding_seed, instructions::transact::SppProofInputs, SppProofOutputUtxo,
    TransactionError,
};

use crate::{
    prover::{to_instruction_proof, RingRequest},
    request::{
        owner_key, Anchor, AnonymousAudit, AnonymousOutput, AuditParams, DeliveredAudit,
        DeliveredOutput, Opening, PackedAudit, Stream,
    },
    RingError,
};

pub(crate) struct SealedAudit {
    pub layout: DisclosureLayout,
    /// The statement's flags, the frame's data-free bit included.
    pub flags: AuditLayout,
    pub eph_u: [u8; 32],
    pub sealed: [u8; 32],
    eph_sk: Zeroizing<[u8; 32]>,
    /// The published fields.
    pub fields: Vec<[u8; 32]>,
    seed_out: [u8; 32],
}

pub(super) struct AuditSeal<'a> {
    pub rail: &'a RingOutputRail,
    pub layout: DisclosureLayout,
    pub flags: AuditLayout,
    pub published: &'a [PublishedSlot<'a>],
    pub inputs: &'a SppProofInputs,
    pub sender: &'a ShieldedAddress,
    pub auditor: &'a X25519Pubkey,
}

impl AuditSeal<'_> {
    pub fn seal(self) -> Result<SealedAudit, RingError> {
        let first_nullifier = self
            .inputs
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier();
        let seed_out = derive_output_blinding_seed(&first_nullifier, &self.inputs.blinding_seed)?;
        let disclosure = self.disclosure(seed_out)?;
        let envelope = AuditEnvelope::seal(self.rail.tx_viewing_key(), self.auditor)?;
        let pad = DisclosurePad::new(self.rail.tx_viewing_key(), &self.rail.salt())?;
        Ok(SealedAudit {
            layout: self.layout,
            flags: self.flags,
            eph_u: envelope.envelope.eph_u,
            sealed: envelope.envelope.sealed,
            eph_sk: envelope.ephemeral_sk,
            fields: pad.encrypt(&disclosure.fields()?)?,
            seed_out,
        })
    }

    fn disclosure(&self, seed_out: [u8; 32]) -> Result<AuditDisclosure, RingError> {
        Ok(match self.layout {
            DisclosureLayout::Packed(layout) => AuditDisclosure::Packed {
                layout,
                seed_out: layout.exits.then_some(seed_out),
                outputs: self
                    .published
                    .iter()
                    .map(|slot| packed_opening(slot.output, layout.key_escrow))
                    .collect::<Result<_, _>>()?,
            },
            DisclosureLayout::Delivered(layout) => AuditDisclosure::Delivered {
                layout,
                seed_out: layout.exits.then_some(seed_out),
                outputs: self
                    .published
                    .iter()
                    .map(|slot| delivered_opening(slot, layout.key_escrow))
                    .collect::<Result<_, _>>()?,
            },
            DisclosureLayout::Anonymous(layout) => {
                AuditDisclosure::Anonymous(AnonymousDisclosure {
                    layout,
                    seed_out: layout.exits.then_some(seed_out),
                    outputs: self
                        .published
                        .iter()
                        .enumerate()
                        .map(|(index, slot)| anonymous_opening(slot, index))
                        .collect::<Result<_, _>>()?,
                    inputs: self.spent(layout.key)?,
                })
            }
        })
    }

    fn spent(&self, key: AnonymousAuditKey) -> Result<AnonymousInputs, RingError> {
        let published = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact());
        Ok(match key {
            AnonymousAuditKey::Commitment { .. } => AnonymousInputs::commitments(
                &published
                    .map(|input| (!input.is_dummy()).then(|| input.private_tx_input_hash()))
                    .collect::<Vec<_>>(),
            )?,
            AnonymousAuditKey::Entry => AnonymousInputs::Openings {
                sender_key: owner_key(&self.sender.signing_pubkey)?,
                sender_nullifier_pk: self.sender.nullifier_pubkey,
                inputs: published
                    .map(|input| match input.is_dummy() {
                        true => Ok(None),
                        false => Ok(Some(AnonymousInputOpening {
                            asset: hash_bytes(input.utxo.asset.asset.as_array())?,
                            amount: input.utxo.amount,
                            blinding: input.utxo.blinding,
                        })),
                    })
                    .collect::<Result<_, RingError>>()?,
            },
        })
    }
}

impl SealedAudit {
    /// The message the program expands under the auditor's view tag.
    pub fn message(&self, auditor: &X25519Pubkey) -> MessageData {
        MessageData {
            view_tag: auditor.u(),
            data: AuditorMessage::data(&self.eph_u, &self.sealed, &self.fields),
        }
    }
}

pub(crate) struct AuditProving<'a> {
    pub rail: &'a RingOutputRail,
    pub sealed: &'a SealedAudit,
    pub published: Vec<PublishedSlot<'a>>,
    pub inputs: &'a SppProofInputs,
    pub n_out: u8,
    pub sender: &'a ShieldedAddress,
    pub auditor: &'a X25519Pubkey,
    pub ring_id: [u8; 32],
    pub public_input_hash: [u8; 32],
    /// `None` outside the anonymous rail.
    pub anonymous: Option<&'a AnonymousStatement>,
}

pub(crate) struct AuditRequest {
    pub circuit: RingCircuit,
    pub body: AuditBody,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum AuditBody {
    Packed(PackedAudit),
    Delivered(DeliveredAudit),
    Anonymous(Box<AnonymousAudit>),
}

pub(crate) struct AnonymousStatement {
    pub private_tx_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub sender_commitment: [u8; 32],
    pub epoch: u64,
    pub first_contact_root: [u8; 32],
    pub anchor: Option<Anchor>,
}

impl AuditProving<'_> {
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<custom_ring_interface::CustomRingProof, RingError> {
        let request = self.request()?;
        let proof = RingRequest::new(request.circuit, &request.body)?
            .prove(client, self.public_input_hash)
            .await?;
        to_instruction_proof(proof)
    }

    /// The circuit the sealed layout selects and the body it proves.
    pub fn request(&self) -> Result<AuditRequest, RingError> {
        let inputs = self.inputs;
        let n_out = self.n_out;
        let circuit = RingCircuit::audit(self.sealed.layout, n_out);
        let first_nullifier = inputs
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier();
        let audit = AuditParams {
            first_nullifier,
            ring_id: self.ring_id,
            tx_viewing_sk: self.rail.tx_viewing_key().secret_bytes(),
            eph_sk: self.sealed.eph_sk.clone(),
            auditor_pk: *self.auditor,
            salt: self.rail.salt(),
            seed_out: self.sealed.seed_out,
            layout: self.sealed.flags.value(),
        };
        let tree = inputs.output_tree_id;
        let body = match (self.sealed.layout, self.anonymous) {
            (DisclosureLayout::Packed(layout), _) => {
                let mut openings = vec![Opening::default(); usize::from(n_out)];
                let mut owner_keys = vec![[0; 32]; usize::from(n_out)];
                for (index, slot) in self.published.iter().enumerate() {
                    openings[index] = Opening::output(slot.output, tree)?;
                    owner_keys[index] = slot_owner_key(slot.output)?;
                }
                AuditBody::Packed(PackedAudit {
                    public_input_hash: self.public_input_hash,
                    audit,
                    n_out: u8::try_from(layout.outputs)
                        .map_err(|_| TransactionError::TooManyOutputs)?,
                    outputs: openings,
                    owner_keys,
                })
            }
            (DisclosureLayout::Delivered(_), _) => AuditBody::Delivered(DeliveredAudit {
                public_input_hash: self.public_input_hash,
                audit,
                outputs: self
                    .published
                    .iter()
                    .map(|slot| delivered_output(slot, tree))
                    .collect::<Result<_, _>>()?,
            }),
            (DisclosureLayout::Anonymous(layout), Some(statement)) => {
                let (class, count) = (layout.key.class(), layout.inputs);
                let mut openings = inputs
                    .input_utxos
                    .iter()
                    .filter(|input| !input.is_compact())
                    .map(Opening::input)
                    .collect::<Result<Vec<_>, _>>()?;
                openings.resize(class, Opening::default());
                AuditBody::Anonymous(Box::new(AnonymousAudit {
                    public_input_hash: self.public_input_hash,
                    audit,
                    outputs: self
                        .published
                        .iter()
                        .map(|slot| anonymous_output(slot, tree))
                        .collect::<Result<_, _>>()?,
                    private_tx_hash: statement.private_tx_hash,
                    private_tx_blinding: statement.private_tx_blinding,
                    sender_key: (layout.key == AnonymousAuditKey::Entry)
                        .then(|| owner_key(&self.sender.signing_pubkey))
                        .transpose()?,
                    input_count: u8::try_from(count).map_err(|_| {
                        TransactionError::TooManyInputs {
                            got: count,
                            max: usize::from(u8::MAX),
                        }
                    })?,
                    inputs: openings,
                    sender_commitment: statement.sender_commitment,
                    epoch: statement.epoch,
                    first_contact_root: statement.first_contact_root,
                    anchor: statement.anchor.clone(),
                }))
            }
            (DisclosureLayout::Anonymous(_), None) => {
                return Err(RingError::MissingAnonymousSigner)
            }
        };
        Ok(AuditRequest { circuit, body })
    }
}

fn slot_owner_key(output: &SppProofOutputUtxo) -> Result<[u8; 32], RingError> {
    output
        .owner_address
        .map(|owner| owner_key(&owner.signing_pubkey))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn disclosed_key(owner: &ShieldedAddress, key_escrow: bool) -> Option<[u8; 32]> {
    (!key_escrow).then_some(owner.nullifier_pubkey)
}

fn packed_opening(
    output: &SppProofOutputUtxo,
    key_escrow: bool,
) -> Result<Option<PackedOutputOpening>, RingError> {
    let Some(owner) = output.owner_address else {
        return Ok(None);
    };
    Ok(Some(PackedOutputOpening {
        owner_key: owner_key(&owner.signing_pubkey)?,
        nullifier_pk: disclosed_key(&owner, key_escrow),
        asset: hash_bytes(output.asset.asset.as_array())?,
        amount: output.amount,
        data_hash: output.data_hash.unwrap_or_default(),
        ring_data_hash: output.ring_data_hash.unwrap_or_default(),
    }))
}

fn delivered_opening(
    slot: &PublishedSlot<'_>,
    key_escrow: bool,
) -> Result<DeliveredOutputOpening, RingError> {
    let output = slot.output;
    let Some(owner) = output.owner_address else {
        return Ok(DeliveredOutputOpening::Dummy);
    };
    Ok(match slot.wire.is_exit() {
        true => DeliveredOutputOpening::Exit {
            nullifier_pk: disclosed_key(&owner, key_escrow),
            asset: hash_bytes(output.asset.asset.as_array())?,
            amount: output.amount,
        },
        false => DeliveredOutputOpening::Ring {
            owner_key: owner_key(&owner.signing_pubkey)?,
            nullifier_pk: disclosed_key(&owner, key_escrow),
        },
    })
}

fn anonymous_opening(
    slot: &PublishedSlot<'_>,
    index: usize,
) -> Result<AnonymousOutputOpening, RingError> {
    let output = slot.output;
    let Some(owner) = output.owner_address else {
        return Ok(AnonymousOutputOpening::Dummy);
    };
    Ok(match (slot.wire.is_exit(), slot.recipient) {
        (true, _) => AnonymousOutputOpening::Exit {
            nullifier_pk: owner.nullifier_pubkey,
            asset: hash_bytes(output.asset.asset.as_array())?,
            amount: output.amount,
        },
        (false, Some(recipient)) => AnonymousOutputOpening::Ring {
            owner_key: owner_key(&owner.signing_pubkey)?,
            nullifier_pk: owner.nullifier_pubkey,
            recipient_u: recipient.u(),
        },
        (false, None) => return Err(RingError::UndeliveredRingOutput { slot: index }),
    })
}

/// A ring output opens its body for its recipient, padding binds its published key and body.
fn delivered_output(slot: &PublishedSlot<'_>, tree: u16) -> Result<DeliveredOutput, RingError> {
    let output = slot.output;
    let (recipient_key, body) = match slot.wire {
        RingOutput::Delivered { u, body, .. } => (*u, *body),
        RingOutput::Anonymous { body, .. } => {
            (slot.recipient.map(|key| key.u()).unwrap_or_default(), *body)
        }
        RingOutput::Exit { .. } | RingOutput::Packed { .. } => {
            ([0; 32], [0; RING_DELIVERED_BODY_LEN])
        }
    };
    let ring = !output.is_dummy() && !slot.wire.is_exit();
    Ok(DeliveredOutput {
        output: Opening::output(output, tree)?,
        asset_address: *output.asset.asset.as_array(),
        recipient_key,
        owner_key: match ring {
            true => slot_owner_key(output)?,
            false => [0; 32],
        },
        body,
    })
}

fn anonymous_output(slot: &PublishedSlot<'_>, tree: u16) -> Result<AnonymousOutput, RingError> {
    let stream = match slot.anonymous {
        Some(AnonymousSlot::Payment(payment)) => {
            let (inbox, index) = match payment.position {
                StreamPosition::Inbox(index) => (true, index),
                StreamPosition::Pair(index) => (false, index),
            };
            Stream {
                tag: payment.tag.field(),
                inbox,
                pair: !inbox,
                change: false,
                index: index.get(),
            }
        }
        Some(AnonymousSlot::Change { tag }) => Stream {
            tag: tag.field(),
            change: true,
            ..Stream::default()
        },
        Some(AnonymousSlot::Dummy { tag }) => Stream {
            tag: tag.field(),
            ..Stream::default()
        },
        Some(AnonymousSlot::Exit) | None => Stream::default(),
    };
    Ok(AnonymousOutput {
        delivered: delivered_output(slot, tree)?,
        stream,
    })
}
