//! Opens a ring transfer for its auditor from the disclosure and the blindings its keys derive.

use std::collections::HashMap;

use custom_ring_interface::{
    stream::{DeliveredSlot, PackedSlot, RingTag, SlotSecret},
    AuditorMessage, DisclosureLayout, RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_event::{
    confidential_encrypted_output_body, ring_anonymous_encrypted_output_body,
    ring_confidential_delivered_output_body,
};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::tree_slot::tree_id_field;
use zolana_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use zolana_transaction::{
    serialization::{RingDeliveredBody, RingDeliverySlot},
    utxo::{derive_transact_output_blinding, DUMMY_DOMAIN},
    AssetRegistry, OutputSlot, ShieldedTransaction,
};

use crate::{
    disclosure::{
        AnonymousDisclosure, AnonymousInputs, AnonymousOutputOpening, AuditDisclosure,
        AuditEnvelope, DeliveredOutputOpening, DisclosurePad, PackedOutputOpening,
        PublishedOutputs,
    },
    encryption::auditor_view_tag,
    types::{
        AuditedInput, AuditedInputOpening, AuditedNote, AuditedOutput, AuditedSender,
        AuditedTransaction, InputRing, KnownNote, OutputOpening, OutputPayloadError,
        OutputPayloadErrorKind,
    },
    AuditError,
};

/// Takes the transaction as given, [`crate::RingScan::audit`] binds it to its confirmed event.
#[must_use = "run the audit explicitly"]
pub struct TransactionAudit<'a> {
    transaction: &'a ShieldedTransaction,
    layout: DisclosureLayout,
    input_trees: Option<&'a [Option<u16>]>,
    known_notes: Option<&'a dyn KnownNotes>,
    escrowed_keys: Option<&'a dyn EscrowedKeys>,
}

/// Notes the auditor opened before.
pub trait KnownNotes {
    fn note(&self, commitment: &[u8; 32]) -> Option<KnownNote>;
}

impl KnownNotes for HashMap<[u8; 32], KnownNote> {
    fn note(&self, commitment: &[u8; 32]) -> Option<KnownNote> {
        self.get(commitment).copied()
    }
}

/// The nullifier key each registered owner escrows, keyed by its raw Solana key.
pub trait EscrowedKeys {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]>;
}

impl EscrowedKeys for HashMap<[u8; 32], [u8; 32]> {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.get(owner_key).copied()
    }
}

impl<'a> TransactionAudit<'a> {
    /// `layout` comes from [`crate::RingOrigin::disclosure_layout`].
    pub fn new(transaction: &'a ShieldedTransaction, layout: DisclosureLayout) -> Self {
        Self {
            transaction,
            layout,
            input_trees: None,
            known_notes: None,
            escrowed_keys: None,
        }
    }

    /// One tree per published nullifier, else [`AuditError::InputTreeCount`].
    pub fn with_input_trees(mut self, trees: &'a [Option<u16>]) -> Result<Self, AuditError> {
        let inputs = self.transaction.nullifiers.len();
        if trees.len() != inputs {
            return Err(AuditError::InputTreeCount {
                trees: trees.len(),
                inputs,
            });
        }
        self.input_trees = Some(trees);
        Ok(self)
    }

    /// Opens a commitment-layout input and resolves an entry input's ring.
    pub fn with_known_notes(mut self, known: &'a dyn KnownNotes) -> Self {
        self.known_notes = Some(known);
        self
    }

    /// The output nullifier keys a key-escrow ring leaves out of its disclosure.
    pub fn with_escrowed_keys(mut self, keys: &'a dyn EscrowedKeys) -> Self {
        self.escrowed_keys = Some(keys);
        self
    }

    pub fn run(
        self,
        auditor: &X25519Keypair,
        assets: &AssetRegistry,
    ) -> Result<AuditedTransaction, AuditError> {
        let tx = self.transaction;
        let tx_viewing_pk = tx.tx_viewing_pk.ok_or(AuditError::MissingTxViewingPk)?;
        let salt = tx.salt.ok_or(AuditError::MissingSalt)?;
        let ring = tx.ring_program_id.ok_or(AuditError::MissingRingProgram)?;
        let first_nullifier = *tx.nullifiers.first().ok_or(AuditError::MissingNullifier)?;
        let data = auditor_message(tx, &auditor.pubkey())?;
        let exits: Vec<bool> = tx.output_slots.iter().map(is_exit).collect();
        let layout = self.layout;
        check_published(layout, tx, &exits)?;
        let message = AuditorMessage::parse(data, layout)
            .ok_or(AuditError::AuditorMessageLength(data.len()))?;
        let tx_key = AuditEnvelope {
            eph_u: X25519Pubkey::from_bytes(*message.eph_pk)?.u(),
            sealed: *message.sealed,
        }
        .open(auditor)?;
        // The audit proof binds the envelope to the published key.
        if tx_key.pubkey() != tx_viewing_pk {
            return Err(AuditError::TxViewingKeyMismatch);
        }
        let plaintext =
            Zeroizing::new(DisclosurePad::new(&tx_key, &salt)?.decrypt(message.disclosure)?);
        let disclosure = AuditDisclosure::decode(
            PublishedOutputs {
                layout,
                exits: &exits,
            },
            &plaintext,
        )?;
        let mut audited = AuditedTransaction {
            tx_signature: tx.tx_signature,
            slot: tx.slot,
            tx_viewing_pk,
            outputs: Vec::new(),
            payload_errors: Vec::new(),
            sender: None,
            inputs: Vec::new(),
        };
        let transfer = |seed_out| Transfer {
            ring,
            tx_key: &tx_key,
            tx_viewing_pk,
            salt,
            first_nullifier,
            seed_out,
            assets,
            escrowed: self.escrowed_keys,
        };
        let slots = (0u32..)
            .zip(&tx.output_slots)
            .map(|(index, output)| Slot { index, output });
        match disclosure {
            AuditDisclosure::Packed {
                seed_out, outputs, ..
            } => {
                let transfer = transfer(seed_out);
                for (slot, opening) in slots.zip(outputs) {
                    audited.record(slot, transfer.packed(slot, opening)?);
                }
            }
            AuditDisclosure::Delivered {
                seed_out, outputs, ..
            } => {
                let transfer = transfer(seed_out);
                for (slot, opening) in slots.zip(outputs) {
                    audited.record(slot, transfer.delivered(slot, opening)?);
                }
            }
            AuditDisclosure::Anonymous(disclosure) => {
                let transfer = transfer(disclosure.seed_out);
                for (slot, opening) in slots.zip(&disclosure.outputs) {
                    audited.record(slot, transfer.anonymous(slot, *opening)?);
                }
                let spent = transfer.inputs(SpentInputs {
                    disclosure: &disclosure,
                    nullifiers: &tx.nullifiers,
                    trees: self.input_trees,
                    known: self.known_notes,
                })?;
                audited.sender = Some(AuditedSender {
                    owner_key: disclosure.sender_key,
                    nullifier_pk: spent.sender_nullifier_pk,
                });
                audited.inputs = spent.inputs;
            }
        }
        Ok(audited)
    }
}

fn check_published(
    layout: DisclosureLayout,
    tx: &ShieldedTransaction,
    exits: &[bool],
) -> Result<(), AuditError> {
    let (outputs, inputs, flagged) = match layout {
        DisclosureLayout::Packed(packed) => (packed.outputs, None, packed.exits),
        DisclosureLayout::Delivered(delivered) => (delivered.outputs, None, delivered.exits),
        DisclosureLayout::Anonymous(anonymous) => {
            (anonymous.outputs, Some(anonymous.inputs), anonymous.exits)
        }
    };
    let consistent = outputs == tx.output_slots.len()
        && inputs.is_none_or(|inputs| inputs == tx.nullifiers.len())
        && flagged == exits.contains(&true);
    match consistent {
        true => Ok(()),
        false => Err(AuditError::DisclosureLayout),
    }
}

fn auditor_message<'a>(
    tx: &'a ShieldedTransaction,
    auditor_pk: &X25519Pubkey,
) -> Result<&'a [u8], AuditError> {
    let view_tag = auditor_view_tag(auditor_pk);
    let mut tagged = tx
        .messages
        .iter()
        .enumerate()
        .filter(|(_, message)| message.view_tag == view_tag);
    let (index, message) = tagged.next().ok_or(AuditError::MissingAuditorMessage)?;
    if tagged.next().is_some() {
        return Err(AuditError::DuplicateAuditorMessage);
    }
    let count = tx.messages.len();
    if index + 1 != count {
        return Err(AuditError::AuditorMessageNotLast { index, count });
    }
    Ok(&message.data)
}

/// The ring program encodes every exit under scheme 3, every other slot under its layout's scheme.
fn is_exit(slot: &OutputSlot) -> bool {
    confidential_encrypted_output_body(&slot.payload).is_some()
}

#[derive(Clone, Copy)]
struct Slot<'a> {
    index: u32,
    output: &'a OutputSlot,
}

impl<'a> Slot<'a> {
    fn owner_tag(self) -> [u8; 32] {
        self.output.view_tag
    }

    fn tag(self) -> Option<RingTag> {
        RingTag::from_owner_tag(&self.output.view_tag)
    }

    fn body(self, anonymous: bool) -> Option<&'a [u8; RING_DELIVERED_BODY_LEN]> {
        let payload = &self.output.payload;
        match anonymous {
            true => ring_anonymous_encrypted_output_body(payload)?
                .try_into()
                .ok(),
            false => ring_confidential_delivered_output_body(payload),
        }
    }

    fn tree_id(self) -> u16 {
        self.output.output_context.tree_id
    }
}

type SlotOpening = Result<OutputOpening, OutputPayloadErrorKind>;

struct Transfer<'a> {
    ring: Address,
    tx_key: &'a ViewingKey,
    tx_viewing_pk: X25519Pubkey,
    salt: [u8; 16],
    first_nullifier: [u8; 32],
    seed_out: Option<[u8; 32]>,
    assets: &'a AssetRegistry,
    escrowed: Option<&'a dyn EscrowedKeys>,
}

struct Spent {
    sender_nullifier_pk: Option<[u8; 32]>,
    inputs: Vec<AuditedInput>,
}

struct Delivery<'a> {
    slot: Slot<'a>,
    owner_key: [u8; 32],
    nullifier_pk: Option<[u8; 32]>,
    recipient_u: [u8; 32],
    tag: Option<RingTag>,
}

struct DeliveredExit {
    nullifier_pk: Option<[u8; 32]>,
    asset: [u8; 32],
    amount: u64,
}

struct SpentInputs<'a> {
    disclosure: &'a AnonymousDisclosure,
    nullifiers: &'a [[u8; 32]],
    trees: Option<&'a [Option<u16>]>,
    known: Option<&'a dyn KnownNotes>,
}

impl Transfer<'_> {
    fn packed(
        &self,
        slot: Slot<'_>,
        opening: Option<PackedOutputOpening>,
    ) -> Result<SlotOpening, AuditError> {
        let Some(opening) = opening else {
            return self.verify(slot, OutputOpening::Dummy);
        };
        let Some(nullifier_pk) = self.nullifier_pk(&opening.owner_key, opening.nullifier_pk) else {
            return Ok(Err(OutputPayloadErrorKind::EscrowUnknown));
        };
        let exit = is_exit(slot.output);
        let blinding = match exit {
            true => self.exit_blinding(slot)?,
            false => {
                let secret = PackedSlot {
                    tx_viewing_secret: &self.tx_key.secret_bytes(),
                    salt: &self.salt,
                    output_index: slot.index,
                    first_nullifier: &self.first_nullifier,
                }
                .secret()?;
                self.ring_blinding(slot, &secret, None)?
            }
        };
        let note = AuditedNote {
            owner_key: opening.owner_key,
            nullifier_pk,
            asset: opening.asset,
            mint: self.mint(&opening.asset)?,
            amount: opening.amount,
            blinding,
            data_hash: opening.data_hash,
            ring_data_hash: opening.ring_data_hash,
        };
        self.verify(
            slot,
            match exit {
                true => OutputOpening::Exit(note),
                false => OutputOpening::Ring {
                    note,
                    recipient_u: slot.owner_tag(),
                    tag: None,
                },
            },
        )
    }

    fn delivered(
        &self,
        slot: Slot<'_>,
        opening: DeliveredOutputOpening,
    ) -> Result<SlotOpening, AuditError> {
        match opening {
            DeliveredOutputOpening::Ring {
                owner_key,
                nullifier_pk,
            } => self.deliver(Delivery {
                slot,
                owner_key,
                nullifier_pk,
                recipient_u: slot.owner_tag(),
                tag: None,
            }),
            DeliveredOutputOpening::Exit {
                nullifier_pk,
                asset,
                amount,
            } => self.exit(
                slot,
                DeliveredExit {
                    nullifier_pk,
                    asset,
                    amount,
                },
            ),
            DeliveredOutputOpening::Dummy => self.verify(slot, OutputOpening::Dummy),
        }
    }

    fn anonymous(
        &self,
        slot: Slot<'_>,
        opening: AnonymousOutputOpening,
    ) -> Result<SlotOpening, AuditError> {
        match opening {
            AnonymousOutputOpening::Ring {
                owner_key,
                nullifier_pk,
                recipient_u,
            } => {
                let Some(tag) = slot.tag() else {
                    return Ok(Err(OutputPayloadErrorKind::Frame));
                };
                self.deliver(Delivery {
                    slot,
                    owner_key,
                    nullifier_pk: Some(nullifier_pk),
                    recipient_u,
                    tag: Some(tag),
                })
            }
            AnonymousOutputOpening::Exit {
                nullifier_pk,
                asset,
                amount,
            } => self.exit(
                slot,
                DeliveredExit {
                    nullifier_pk: Some(nullifier_pk),
                    asset,
                    amount,
                },
            ),
            AnonymousOutputOpening::Dummy => self.verify(slot, OutputOpening::Dummy),
        }
    }

    fn deliver(&self, delivery: Delivery<'_>) -> Result<SlotOpening, AuditError> {
        let Delivery {
            slot,
            owner_key,
            nullifier_pk,
            recipient_u,
            tag,
        } = delivery;
        let Some(nullifier_pk) = self.nullifier_pk(&owner_key, nullifier_pk) else {
            return Ok(Err(OutputPayloadErrorKind::EscrowUnknown));
        };
        let Some(body) = slot.body(tag.is_some()) else {
            return Ok(Err(OutputPayloadErrorKind::Frame));
        };
        let Some(secret) = self.delivered_secret(slot, recipient_u)? else {
            return Ok(Err(OutputPayloadErrorKind::RecipientKey));
        };
        let body = RingDeliveredBody::open(body, &secret)?;
        let note = AuditedNote {
            owner_key,
            nullifier_pk,
            asset: hash_bytes(body.asset_address.as_array())?,
            mint: Some(body.asset_address),
            amount: body.amount,
            blinding: self.ring_blinding(slot, &secret, tag)?,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        };
        self.verify(
            slot,
            OutputOpening::Ring {
                note,
                recipient_u,
                tag,
            },
        )
    }

    fn exit(&self, slot: Slot<'_>, exit: DeliveredExit) -> Result<SlotOpening, AuditError> {
        let owner_key = slot.owner_tag();
        let Some(nullifier_pk) = self.nullifier_pk(&owner_key, exit.nullifier_pk) else {
            return Ok(Err(OutputPayloadErrorKind::EscrowUnknown));
        };
        let note = AuditedNote {
            owner_key,
            nullifier_pk,
            asset: exit.asset,
            mint: self.mint(&exit.asset)?,
            amount: exit.amount,
            blinding: self.exit_blinding(slot)?,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        };
        self.verify(slot, OutputOpening::Exit(note))
    }

    fn verify(&self, slot: Slot<'_>, opening: OutputOpening) -> Result<SlotOpening, AuditError> {
        let tree_id = slot.tree_id();
        let commitment = match &opening {
            OutputOpening::Ring { note, .. } => note.commitment(tree_id, Some(self.ring))?,
            OutputOpening::Exit(note) => note.commitment(tree_id, None)?,
            // Without SeedOut the audit proof alone binds a dummy.
            OutputOpening::Dummy if self.seed_out.is_none() => return Ok(Ok(opening)),
            OutputOpening::Dummy => ProofInputUtxo {
                domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
                tree_id: tree_id_field(tree_id),
                blinding: self.exit_blinding(slot)?,
                ..ProofInputUtxo::default()
            }
            .hash()?,
        };
        Ok(match commitment == slot.output.output_context.hash {
            true => Ok(opening),
            false => Err(OutputPayloadErrorKind::Commitment),
        })
    }

    fn delivered_secret(
        &self,
        slot: Slot<'_>,
        recipient_u: [u8; 32],
    ) -> Result<Option<SlotSecret>, AuditError> {
        let Ok(recipient) = X25519Pubkey::from_u(recipient_u) else {
            return Ok(None);
        };
        let Ok(agreement) = self.tx_key.ecdh(&recipient) else {
            return Ok(None);
        };
        let agreement = Zeroizing::new(agreement);
        Ok(Some(
            DeliveredSlot {
                agreement: &agreement,
                tx_viewing_pk: self.tx_viewing_pk.as_bytes(),
                recipient_viewing_pk: recipient.as_bytes(),
                salt: &self.salt,
                output_index: slot.index,
                first_nullifier: &self.first_nullifier,
            }
            .secret()?,
        ))
    }

    fn ring_blinding(
        &self,
        slot: Slot<'_>,
        secret: &SlotSecret,
        tag: Option<RingTag>,
    ) -> Result<[u8; 32], AuditError> {
        Ok(RingDeliverySlot {
            ring: self.ring,
            first_nullifier: self.first_nullifier,
            output_index: slot.index,
            tag,
        }
        .blinding(secret)?)
    }

    /// SPP's TXOB blinding of an exit or a dummy.
    fn exit_blinding(&self, slot: Slot<'_>) -> Result<[u8; 32], AuditError> {
        let seed_out = self.seed_out.ok_or(AuditError::DisclosureLayout)?;
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &seed_out,
            slot.index,
        )?)
    }

    fn nullifier_pk(&self, owner_key: &[u8; 32], disclosed: Option<[u8; 32]>) -> Option<[u8; 32]> {
        disclosed.or_else(|| self.escrowed?.nullifier_pk(owner_key))
    }

    fn mint(&self, asset: &[u8; 32]) -> Result<Option<Address>, AuditError> {
        Ok(self.assets.address_for_field(asset)?)
    }

    fn inputs(&self, spent: SpentInputs<'_>) -> Result<Spent, AuditError> {
        let SpentInputs {
            disclosure,
            nullifiers,
            trees,
            known,
        } = spent;
        match &disclosure.inputs {
            AnonymousInputs::Commitments(hashes) => {
                let notes = hashes
                    .iter()
                    .map(|hash| {
                        hash.map(|commitment| {
                            known
                                .and_then(|known| known.note(&commitment))
                                .map(|note| (commitment, note))
                                .ok_or(AuditError::UnseenInput { commitment })
                        })
                        .transpose()
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // The circuit proves spent UTXO 0 real.
                let (_, first) = notes
                    .first()
                    .copied()
                    .flatten()
                    .ok_or(AuditError::DisclosureLayout)?;
                Ok(Spent {
                    sender_nullifier_pk: first.nullifier_pk,
                    inputs: nullifiers
                        .iter()
                        .zip(notes)
                        .map(|(nullifier, note)| AuditedInput {
                            nullifier: *nullifier,
                            opening: note.map(|(commitment, note)| AuditedInputOpening {
                                asset: note.asset,
                                mint: note.mint,
                                amount: note.amount,
                                blinding: note.blinding,
                                ring: Some(InputRing::Ring { commitment }),
                            }),
                        })
                        .collect(),
                })
            }
            AnonymousInputs::Openings {
                sender_nullifier_pk,
                inputs: openings,
            } => {
                let inputs = nullifiers
                    .iter()
                    .zip(openings)
                    .enumerate()
                    .map(|(index, (nullifier, opening))| {
                        let opening = opening
                            .map(|opening| {
                                let note = AuditedNote {
                                    owner_key: disclosure.sender_key,
                                    nullifier_pk: *sender_nullifier_pk,
                                    asset: opening.asset,
                                    mint: self.mint(&opening.asset)?,
                                    amount: opening.amount,
                                    blinding: opening.blinding,
                                    data_hash: [0; 32],
                                    ring_data_hash: [0; 32],
                                };
                                let tree =
                                    trees.and_then(|trees| trees.get(index).copied().flatten());
                                Ok::<_, AuditError>(AuditedInputOpening {
                                    asset: note.asset,
                                    mint: note.mint,
                                    amount: note.amount,
                                    blinding: note.blinding,
                                    ring: tree
                                        .map(|tree| self.input_ring(&note, tree, known))
                                        .transpose()?,
                                })
                            })
                            .transpose()?;
                        Ok(AuditedInput {
                            nullifier: *nullifier,
                            opening,
                        })
                    })
                    .collect::<Result<_, AuditError>>()?;
                Ok(Spent {
                    sender_nullifier_pk: Some(*sender_nullifier_pk),
                    inputs,
                })
            }
        }
    }

    fn input_ring(
        &self,
        note: &AuditedNote,
        tree_id: u16,
        known: Option<&dyn KnownNotes>,
    ) -> Result<InputRing, AuditError> {
        let ring = note.commitment(tree_id, Some(self.ring))?;
        let default = note.commitment(tree_id, None)?;
        let found = |commitment| known.is_some_and(|known| known.note(commitment).is_some());
        Ok(match (found(&ring), found(&default)) {
            (true, false) => InputRing::Ring { commitment: ring },
            (false, true) => InputRing::Default {
                commitment: default,
            },
            _ => InputRing::Unresolved { ring, default },
        })
    }
}

impl AuditedTransaction {
    fn record(&mut self, slot: Slot<'_>, opened: SlotOpening) {
        match opened {
            Ok(opening) => self.outputs.push(AuditedOutput {
                slot_index: slot.index,
                context: slot.output.output_context.clone(),
                opening,
            }),
            Err(kind) => self.payload_errors.push(OutputPayloadError {
                slot_index: slot.index,
                kind,
            }),
        }
    }
}
