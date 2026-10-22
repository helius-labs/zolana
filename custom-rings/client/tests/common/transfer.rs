//! Ring transfers as the ring program publishes them, under the keys of the Go `ringaudit` fixture.

use custom_ring_interface::{
    stream::{DeliveredSlot, PackedSlot, RingSecret, RingTag, SlotSecret, TAG_LEN},
    tag as ring_tag, tagged_x25519, AnonymousAuditKey, AnonymousLayout, AnonymousProofData,
    AnonymousSpend, AuditorMessage, CustomRingProof, DeliveredLayout, DisclosureLayout, InputTrees,
    PackedLayout, PlainGroth16Proof, RingOutput, RingRail, RingTransactData,
    PACKED_AUDIT_CAPACITIES, RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::ProofInputUtxo;
use zolana_event::{
    MessageData, RingPackedBody, CONFIDENTIAL_DATA_FREE_BODY_LEN, RECIPIENT_KEY_LEN,
    RING_PACKED_DATA_FREE_BODY_LEN,
};
use zolana_hasher::{
    primitives::{hash_bytes, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            confidential_encrypted_output_body, ring_anonymous_encrypted_output_body,
            ring_confidential_delivered_output_body, ring_confidential_packed_output_body,
            TreeContext,
        },
        OwnerTag,
    },
    shape::SPP_SUPPORTED_SHAPES,
    tree_slot::tree_id_field,
};
use zolana_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use zolana_ring_client::{
    AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
    AuditDisclosure, AuditEnvelope, AuditedUtxo, DeliveredOutputOpening, DisclosurePad, KnownUtxo,
    OutputOpening, PackedOutputOpening, UtxoOwner,
};
use zolana_transaction::{
    derive_output_blinding_seed,
    serialization::{RingDeliveredBody, RingDeliverySlot},
    utxo::{derive_transact_output_blinding, DUMMY_DOMAIN, UTXO_DOMAIN},
    OutputContext, OutputSlot, ShieldedTransaction,
};

/// Byte `i` is `seed ^ i` under a `0x01` lead byte, the Go `ringaudit.Scalar`.
pub fn scalar(seed: u8) -> [u8; 32] {
    let mut out = core::array::from_fn(|i| seed ^ i as u8);
    out[0] = 0x01;
    out
}

/// `byte` repeated behind a zero lead byte, a canonical field.
pub fn field(byte: u8) -> [u8; 32] {
    let mut out = [byte; 32];
    out[0] = 0;
    out
}

pub fn x25519_u(seed: u8) -> [u8; 32] {
    X25519Keypair::from_bytes(&scalar(seed)).pubkey().u()
}

/// The auditor of the Go fixture.
pub fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&scalar(0x33))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UtxoFields {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub asset_address: Address,
    pub amount: u64,
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct Placement {
    pub blinding: [u8; 32],
    pub ring: Option<Address>,
    pub tree_id: u16,
}

impl UtxoFields {
    pub fn asset(&self) -> [u8; 32] {
        hash_bytes(self.asset_address.as_array()).unwrap()
    }

    pub fn owner_hash(&self) -> [u8; 32] {
        Poseidon::hashv(&[
            &solana_owner_identity(&self.owner_key).unwrap(),
            &self.nullifier_pk,
        ])
        .unwrap()
    }

    pub fn commitment(&self, placement: Placement) -> [u8; 32] {
        let ring = placement
            .ring
            .map(|ring| hash_bytes(ring.as_array()).unwrap());
        ProofInputUtxo {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(placement.tree_id),
            owner_hash: self.owner_hash(),
            asset: self.asset(),
            amount: right_align(&self.amount.to_be_bytes()),
            blinding: placement.blinding,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            ring_program_id: ring.unwrap_or_default(),
        }
        .hash()
        .unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Output {
    /// `tag` is the published tag on an anonymous ring.
    Ring {
        utxo: UtxoFields,
        recipient_u: [u8; 32],
        tag: Option<RingTag>,
    },
    Exit(UtxoFields),
    Dummy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rail {
    Packed,
    Delivered,
    Anonymous,
}

pub struct Slot {
    pub output: OutputSlot,
    pub slot_secret: Option<[u8; 32]>,
    pub ring_secret: Option<[u8; 32]>,
    pub blinding: [u8; 32],
    pub body: Option<[u8; RING_DELIVERED_BODY_LEN]>,
}

pub struct Transfer {
    pub tx_key: ViewingKey,
    pub ring: Address,
    pub first_nullifier: [u8; 32],
    pub salt: [u8; 16],
    pub blinding_seed: [u8; 32],
    pub seed_out: [u8; 32],
    pub tree_id: u16,
    pub nullifiers: Vec<[u8; 32]>,
}

pub struct Publish<'a> {
    pub slots: Vec<OutputSlot>,
    pub disclosure: &'a AuditDisclosure,
    pub auditor: &'a X25519Pubkey,
}

pub struct Frame<'a> {
    pub tx: &'a ShieldedTransaction,
    pub layout: DisclosureLayout,
    pub data_free: bool,
}

impl Transfer {
    /// The values of Go `ringaudit.newTransfer`.
    pub fn fixture() -> Self {
        let first_nullifier = right_align(&[0x1f, 0x1f]);
        let blinding_seed = right_align(&[0x5e, 0xed]);
        Self {
            tx_key: ViewingKey::from_bytes(&scalar(0x11)),
            ring: Address::new_from_array([0x90; 32]),
            first_nullifier,
            salt: core::array::from_fn(|i| 0xa0 + i as u8),
            blinding_seed,
            seed_out: derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap(),
            tree_id: 9,
            nullifiers: vec![first_nullifier],
        }
    }

    pub fn ring_id(&self) -> [u8; 32] {
        hash_bytes(self.ring.as_array()).unwrap()
    }

    pub fn exit_blinding(&self, index: u32) -> [u8; 32] {
        derive_transact_output_blinding(&self.first_nullifier, &self.seed_out, index).unwrap()
    }

    pub fn delivered_secret(&self, recipient_u: &[u8; 32], index: u32) -> SlotSecret {
        let recipient = X25519Pubkey::from_u(*recipient_u).unwrap();
        DeliveredSlot {
            agreement: &self.tx_key.ecdh(&recipient).unwrap(),
            tx_viewing_pk: self.tx_key.pubkey().as_bytes(),
            recipient_viewing_pk: &tagged_x25519(recipient_u),
            salt: &self.salt,
            output_index: index,
            first_nullifier: &self.first_nullifier,
        }
        .secret()
        .unwrap()
    }

    pub fn slot(&self, rail: Rail, index: u32, output: &Output) -> Slot {
        let leaf_index = u64::from(index);
        match *output {
            Output::Ring {
                utxo,
                recipient_u,
                tag,
            } => {
                let secret = match rail {
                    Rail::Packed => PackedSlot {
                        tx_viewing_secret: &self.tx_key.secret_bytes(),
                        salt: &self.salt,
                        output_index: index,
                        first_nullifier: &self.first_nullifier,
                    }
                    .secret()
                    .unwrap(),
                    Rail::Delivered | Rail::Anonymous => self.delivered_secret(&recipient_u, index),
                };
                let ring_secret = match &tag {
                    Some(tag) => RingSecret::anonymous(&secret, tag),
                    None => RingSecret::confidential(&secret),
                }
                .unwrap();
                let blinding = RingDeliverySlot {
                    ring: self.ring,
                    first_nullifier: self.first_nullifier,
                    output_index: index,
                    tag,
                }
                .blinding(&secret)
                .unwrap();
                let hash = utxo.commitment(Placement {
                    blinding,
                    ring: Some(self.ring),
                    tree_id: self.tree_id,
                });
                let body = RingDeliveredBody {
                    asset_address: utxo.asset_address,
                    amount: utxo.amount,
                }
                .seal(&secret)
                .unwrap();
                let published = match (rail, tag) {
                    (Rail::Packed, _) => RingOutput::Packed {
                        hash: &hash,
                        u: &recipient_u,
                        ciphertext: &[0xc0; RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN],
                    },
                    (Rail::Delivered, _) => RingOutput::Delivered {
                        hash: &hash,
                        u: &recipient_u,
                        body: &body,
                    },
                    (Rail::Anonymous, tag) => RingOutput::Anonymous {
                        hash: &hash,
                        tag: tag.unwrap(),
                        body: &body,
                    },
                };
                Slot {
                    output: indexed(published, self.tree_id, leaf_index),
                    slot_secret: Some(*secret.as_bytes()),
                    ring_secret: Some(*ring_secret.as_bytes()),
                    blinding,
                    body: (rail != Rail::Packed).then_some(body),
                }
            }
            Output::Exit(utxo) => {
                let blinding = self.exit_blinding(index);
                let hash = utxo.commitment(Placement {
                    blinding,
                    ring: None,
                    tree_id: self.tree_id,
                });
                let published = RingOutput::Exit {
                    hash: &hash,
                    owner_tag: &utxo.owner_key,
                    payload: &[0xe0; CONFIDENTIAL_DATA_FREE_BODY_LEN],
                };
                Slot {
                    output: indexed(published, self.tree_id, leaf_index),
                    slot_secret: None,
                    ring_secret: None,
                    blinding,
                    body: None,
                }
            }
            Output::Dummy => {
                let blinding = self.exit_blinding(index);
                let hash = ProofInputUtxo {
                    domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
                    tree_id: tree_id_field(self.tree_id),
                    blinding,
                    ..ProofInputUtxo::default()
                }
                .hash()
                .unwrap();
                // A dummy publishes random bytes in its rail's encoding.
                let u = [0xd1 + index as u8; 32];
                let body = core::array::from_fn(|j| 0xd0 + j as u8);
                let published = match rail {
                    Rail::Packed => RingOutput::Packed {
                        hash: &hash,
                        u: &u,
                        ciphertext: &[0xc1; RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN],
                    },
                    Rail::Delivered => RingOutput::Delivered {
                        hash: &hash,
                        u: &u,
                        body: &body,
                    },
                    Rail::Anonymous => RingOutput::Anonymous {
                        hash: &hash,
                        tag: RingTag::from_bytes([0xd1 + index as u8; TAG_LEN]),
                        body: &body,
                    },
                };
                Slot {
                    output: indexed(published, self.tree_id, leaf_index),
                    slot_secret: None,
                    ring_secret: None,
                    blinding,
                    body: (rail != Rail::Packed).then_some(body),
                }
            }
        }
    }

    pub fn slots(&self, rail: Rail, outputs: &[Output]) -> Vec<Slot> {
        (0u32..)
            .zip(outputs)
            .map(|(index, output)| self.slot(rail, index, output))
            .collect()
    }

    /// The indexed transaction, the disclosure masked under a fresh envelope to the auditor.
    pub fn publish(&self, publish: Publish<'_>) -> ShieldedTransaction {
        let plaintext = publish.disclosure.fields().unwrap();
        let disclosure = DisclosurePad::new(&self.tx_key, &self.salt)
            .unwrap()
            .encrypt(&plaintext)
            .unwrap();
        let envelope = AuditEnvelope::seal(&self.tx_key, publish.auditor)
            .unwrap()
            .envelope;
        ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(self.tx_key.pubkey()),
            salt: Some(self.salt),
            output_slots: publish.slots,
            messages: vec![MessageData {
                view_tag: publish.auditor.u(),
                data: AuditorMessage::data(&envelope.eph_u, &envelope.sealed, &disclosure),
            }],
            nullifiers: self.nullifiers.clone(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(self.ring),
        }
    }
}

impl Transfer {
    fn published_seed_out(&self, outputs: &[Output]) -> Option<[u8; 32]> {
        outputs
            .iter()
            .any(|output| matches!(output, Output::Exit(_)))
            .then_some(self.seed_out)
    }

    pub fn disclosure(&self, rail: Rail, outputs: &[Output], key_escrow: bool) -> AuditDisclosure {
        let seed_out = self.published_seed_out(outputs);
        let exits = seed_out.is_some();
        let escrowed = |nullifier_pk: Option<[u8; 32]>| nullifier_pk.filter(|_| !key_escrow);
        match rail {
            Rail::Packed => AuditDisclosure::Packed {
                layout: PackedLayout {
                    outputs: outputs.len(),
                    exits,
                    key_escrow,
                    data_free: data_free(outputs),
                },
                seed_out,
                outputs: outputs
                    .iter()
                    .map(|output| {
                        packed_opening(output).map(|opening| PackedOutputOpening {
                            nullifier_pk: escrowed(opening.nullifier_pk),
                            ..opening
                        })
                    })
                    .collect(),
            },
            Rail::Delivered => AuditDisclosure::Delivered {
                layout: DeliveredLayout {
                    outputs: outputs.len(),
                    exits,
                    key_escrow,
                },
                seed_out,
                outputs: outputs
                    .iter()
                    .map(|output| match delivered_opening(output) {
                        DeliveredOutputOpening::Ring {
                            owner_key,
                            nullifier_pk,
                        } => DeliveredOutputOpening::Ring {
                            owner_key,
                            nullifier_pk: escrowed(nullifier_pk),
                        },
                        DeliveredOutputOpening::Exit {
                            nullifier_pk,
                            asset,
                            amount,
                        } => DeliveredOutputOpening::Exit {
                            nullifier_pk: escrowed(nullifier_pk),
                            asset,
                            amount,
                        },
                        DeliveredOutputOpening::Dummy => DeliveredOutputOpening::Dummy,
                    })
                    .collect(),
            },
            Rail::Anonymous => panic!("an anonymous disclosure names its spent notes"),
        }
    }

    /// The anonymous disclosure, the entry key when `inputs` open in full.
    pub fn anonymous_disclosure(
        &self,
        outputs: &[Output],
        inputs: AnonymousInputs,
    ) -> AuditDisclosure {
        let (count, spends_default_ring) = match &inputs {
            AnonymousInputs::Commitments { prefixes, .. } => (prefixes.len() + 1, false),
            AnonymousInputs::Openings { inputs, .. } => (inputs.len(), true),
        };
        let seed_out = self.published_seed_out(outputs);
        AuditDisclosure::Anonymous(AnonymousDisclosure {
            layout: AnonymousLayout {
                key: AnonymousSpend {
                    inputs: count,
                    outputs: outputs.len(),
                    spends_default_ring,
                }
                .audit_key()
                .expect("an anonymous audit key serves the spend"),
                inputs: count,
                outputs: outputs.len(),
                exits: seed_out.is_some(),
            },
            seed_out,
            outputs: outputs.iter().map(anonymous_opening).collect(),
            inputs,
        })
    }
}

impl Transfer {
    /// `tag || RingTransactData` the ring program received for `frame.tx`, every proof zero.
    pub fn frame(&self, frame: Frame<'_>) -> Vec<u8> {
        let Frame {
            tx,
            layout,
            data_free,
        } = frame;
        let (rail, n_out, key_escrow, full_openings) = match layout {
            DisclosureLayout::Packed(packed) => (
                RingRail::Confidential,
                PACKED_AUDIT_CAPACITIES
                    .into_iter()
                    .find(|capacity| *capacity >= packed.outputs)
                    .unwrap(),
                packed.key_escrow,
                false,
            ),
            DisclosureLayout::Delivered(delivered) => (
                RingRail::Confidential,
                delivered.outputs,
                delivered.key_escrow,
                false,
            ),
            DisclosureLayout::Anonymous(anonymous) => (
                RingRail::Anonymous,
                anonymous.outputs,
                false,
                anonymous.key == AnonymousAuditKey::Entry,
            ),
        };
        let shape = SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() >= tx.nullifiers.len() && shape.n_outputs() == n_out)
            .unwrap();
        let message = AuditorMessage::parse(&tx.messages.last().unwrap().data, layout).unwrap();
        let eph_u = X25519Pubkey::from_bytes(*message.eph_pk).unwrap().u();
        let tx_viewing_u = self.tx_key.pubkey().u();
        let zero = [0; 32];
        let groth16 = PlainGroth16Proof {
            proof_a: zero,
            proof_b: [0; 64],
            proof_c: zero,
        };
        let audit_proof = CustomRingProof {
            groth16,
            commitment: zero,
            commitment_pok: zero,
        };
        let data = RingTransactData {
            rail,
            n_in: shape.n_inputs() as u8,
            n_out: shape.n_outputs() as u8,
            audit_proof: &audit_proof,
            policy: None,
            approval_required: false,
            previous_epoch: false,
            anchor: None,
            expiry_unix_ts: 0,
            tx_viewing_u: &tx_viewing_u,
            salt: &self.salt,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            data_free,
            key_escrow,
            full_openings,
            outputs: tx.output_slots.iter().map(wire).collect(),
            eph_u: &eph_u,
            sealed: message.sealed,
            disclosure: message.disclosure,
            private_tx_hash: &zero,
            anonymous: (rail == RingRail::Anonymous).then_some(AnonymousProofData {
                commitment: &zero,
                commitment_pok: &zero,
                default_owner_tag: None,
            }),
            spp_proof: &groth16,
            nullifiers: &tx.nullifiers,
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
            }),
        };
        [vec![ring_tag::TRANSACT], data.encode().unwrap()].concat()
    }
}

pub fn data_free(outputs: &[Output]) -> bool {
    outputs.iter().all(|output| match output {
        Output::Ring { utxo, .. } | Output::Exit(utxo) => {
            utxo.data_hash == [0; 32] && utxo.ring_data_hash == [0; 32]
        }
        Output::Dummy => true,
    })
}

/// The inverse of `RingOutput::transact_output`.
fn wire(slot: &OutputSlot) -> RingOutput<'_> {
    let hash = &slot.output_context.hash;
    let payload = &slot.payload;
    if let Some(payload) = confidential_encrypted_output_body(payload) {
        return RingOutput::Exit {
            hash,
            owner_tag: &slot.view_tag,
            payload,
        };
    }
    if let Some(RingPackedBody { ciphertext, .. }) = ring_confidential_packed_output_body(payload) {
        return RingOutput::Packed {
            hash,
            u: &slot.view_tag,
            ciphertext,
        };
    }
    if let Some(body) = ring_confidential_delivered_output_body(payload) {
        return RingOutput::Delivered {
            hash,
            u: &slot.view_tag,
            body,
        };
    }
    RingOutput::Anonymous {
        hash,
        tag: RingTag::from_owner_tag(&slot.view_tag).unwrap(),
        body: ring_anonymous_encrypted_output_body(payload)
            .and_then(|body| body.try_into().ok())
            .unwrap(),
    }
}

pub fn packed_opening(output: &Output) -> Option<PackedOutputOpening> {
    let (Output::Ring { utxo, .. } | Output::Exit(utxo)) = output else {
        return None;
    };
    Some(PackedOutputOpening {
        owner_key: utxo.owner_key,
        nullifier_pk: Some(utxo.nullifier_pk),
        asset: utxo.asset(),
        amount: utxo.amount,
        data_hash: utxo.data_hash,
        ring_data_hash: utxo.ring_data_hash,
    })
}

pub fn delivered_opening(output: &Output) -> DeliveredOutputOpening {
    match output {
        Output::Ring { utxo, .. } => DeliveredOutputOpening::Ring {
            owner_key: utxo.owner_key,
            nullifier_pk: Some(utxo.nullifier_pk),
        },
        Output::Exit(utxo) => DeliveredOutputOpening::Exit {
            nullifier_pk: Some(utxo.nullifier_pk),
            asset: utxo.asset(),
            amount: utxo.amount,
        },
        Output::Dummy => DeliveredOutputOpening::Dummy,
    }
}

pub fn anonymous_opening(output: &Output) -> AnonymousOutputOpening {
    match output {
        Output::Ring {
            utxo, recipient_u, ..
        } => AnonymousOutputOpening::Ring {
            owner_key: utxo.owner_key,
            nullifier_pk: utxo.nullifier_pk,
            recipient_u: *recipient_u,
        },
        Output::Exit(utxo) => AnonymousOutputOpening::Exit {
            nullifier_pk: utxo.nullifier_pk,
            asset: utxo.asset(),
            amount: utxo.amount,
        },
        Output::Dummy => AnonymousOutputOpening::Dummy,
    }
}

pub fn audited_opening(output: &Output, slot: &Slot) -> OutputOpening {
    let audited = |utxo: &UtxoFields| AuditedUtxo {
        owner_key: utxo.owner_key,
        nullifier_pk: utxo.nullifier_pk,
        asset: utxo.asset(),
        mint: Some(utxo.asset_address),
        amount: utxo.amount,
        blinding: slot.blinding,
        data_hash: utxo.data_hash,
        ring_data_hash: utxo.ring_data_hash,
    };
    match output {
        Output::Ring {
            utxo,
            recipient_u,
            tag,
        } => OutputOpening::Ring {
            utxo: audited(utxo),
            recipient_u: *recipient_u,
            tag: *tag,
        },
        Output::Exit(utxo) => OutputOpening::Exit(audited(utxo)),
        Output::Dummy => OutputOpening::Dummy,
    }
}

/// `note` at `placement` as an earlier audit opened it.
pub fn known_utxo(utxo: &UtxoFields, placement: Placement) -> KnownUtxo {
    KnownUtxo {
        owner_key: utxo.owner_key,
        owner: UtxoOwner::Keyed {
            nullifier_pk: utxo.nullifier_pk,
        },
        asset: utxo.asset(),
        mint: Some(utxo.asset_address),
        amount: utxo.amount,
        blinding: placement.blinding,
        data_hash: utxo.data_hash,
        ring_data_hash: utxo.ring_data_hash,
        tree_id: placement.tree_id,
    }
}

pub fn input_opening(utxo: &UtxoFields, blinding: [u8; 32]) -> AnonymousInputOpening {
    AnonymousInputOpening {
        asset: utxo.asset(),
        amount: utxo.amount,
        blinding,
    }
}

/// The slot the indexer returns for `output`, its owner tag rebuilt by the program.
fn indexed(output: RingOutput<'_>, tree_id: u16, leaf_index: u64) -> OutputSlot {
    let output = output.transact_output();
    let OwnerTag::Inline(view_tag) = output.owner_tag else {
        panic!("ring outputs publish inline owner tags");
    };
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash: output.utxo_hash,
            tree_id,
            leaf_index,
        },
        payload: output.data.unwrap(),
    }
}
