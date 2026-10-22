//! The `HashChain4` public input of the audit, policy, apply and register key proofs.

use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, pack_be, right_align},
    HasherError,
};
use zolana_interface::N_PUBLIC_SLOTS;

use crate::{
    disclosure::AuditLayout, domain, tagged_x25519, transact::RingOutput, AUDIT_CIPHERTEXT_LEN,
    TAGGED_X25519_KEY_LEN,
};

/// `[CRAU, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout]`.
pub const AUDIT_HEAD_ELEMENTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditHead<'a> {
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub tx_viewing_u: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: &'a [u8; 32],
    pub sealed: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub salt: &'a [u8; 16],
    pub layout: AuditLayout,
}

impl AuditHead<'_> {
    fn elements(&self) -> Result<[[u8; 32]; AUDIT_HEAD_ELEMENTS], HasherError> {
        let [tx0, tx1] = pack_be(&tagged_x25519(self.tx_viewing_u));
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        let [eph0, eph1] = pack_be(&tagged_x25519(self.eph_u));
        Ok([
            domain::field(domain::AUDIT_STATEMENT),
            *self.first_nullifier,
            *self.ring_id,
            tx0,
            tx1,
            aud0,
            aud1,
            eph0,
            eph1,
            hash_bytes(self.sealed)?,
            right_align(self.salt),
            right_align(&[self.layout.value()]),
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousAudit<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub epoch: u64,
    /// Zero without a pair-anchored slot.
    pub first_contact_root: &'a [u8; 32],
    /// Zero outside a policy ring.
    pub sender_commitment: &'a [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind<'a> {
    Packed,
    Delivered,
    Anonymous(AnonymousAudit<'a>),
}

/// Every ring transfer's audit proof, mirror `prover/server/custom_rings/circuits/base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditStatement<'a> {
    pub head: AuditHead<'a>,
    /// Published output order.
    pub outputs: &'a [RingOutput<'a>],
    /// Exactly the published disclosure fields.
    pub disclosure: &'a [[u8; 32]],
    pub kind: AuditKind<'a>,
}

impl AuditStatement<'_> {
    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        let mut elements = self.head.elements()?.to_vec();
        let hashes: Vec<[u8; 32]> = self.outputs.iter().map(|output| *output.hash()).collect();
        let output_chain = create_hash_chain_4_from_slice(&hashes)?;
        let disclosure_chain = create_hash_chain_4_from_slice(self.disclosure)?;
        match self.kind {
            AuditKind::Packed => elements.extend([output_chain, disclosure_chain]),
            AuditKind::Delivered => {
                let keys: Vec<[u8; 32]> = self
                    .outputs
                    .iter()
                    .flat_map(RingOutput::recipient_key_fields)
                    .collect();
                elements.extend([
                    output_chain,
                    self.body_chain()?,
                    disclosure_chain,
                    create_hash_chain_4_from_slice(&keys)?,
                ]);
            }
            AuditKind::Anonymous(anonymous) => {
                let tags: Vec<[u8; 32]> = self.outputs.iter().map(RingOutput::tag_field).collect();
                elements.extend([
                    output_chain,
                    self.body_chain()?,
                    disclosure_chain,
                    *anonymous.private_tx_hash,
                    create_hash_chain_4_from_slice(&tags)?,
                    right_align(&anonymous.epoch.to_be_bytes()),
                    *anonymous.first_contact_root,
                    *anonymous.sender_commitment,
                ]);
            }
        }
        Ok(elements)
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }

    fn body_chain(&self) -> Result<[u8; 32], HasherError> {
        let bodies = self
            .outputs
            .iter()
            .map(RingOutput::body_hash)
            .collect::<Result<Vec<_>, _>>()?;
        create_hash_chain_4_from_slice(&bodies)
    }
}

/// The member key reads the sender by the ring mode, the delegate key proves every input the sender's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKey {
    Member { anonymous: bool },
    Delegate,
}

/// A policy ring transfer's policy proof, mirror `prover/server/custom_rings/circuits/policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyStatement<'a> {
    pub key: PolicyKey,
    pub private_tx_hash: &'a [u8; 32],
    pub policy_hash: &'a [u8; 32],
    pub ring_id: &'a [u8; 32],
    pub approval_required: bool,
    pub key_escrow: bool,
    pub own_root: &'a [u8; 32],
    /// Zero without a curator source.
    pub curator_root: &'a [u8; 32],
    /// The owner signer's identity, the sender commitment on an anonymous ring, zero on the delegate rail.
    pub sender: &'a [u8; 32],
    /// SPP's public asset fields, zero past the used slots.
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// SPP's public amount fields, a withdrawal is `q - |amount|`.
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PolicyStatement<'_> {
    pub fn elements(&self) -> Vec<[u8; 32]> {
        let mut elements = vec![
            domain::field(domain::POLICY_STATEMENT),
            *self.private_tx_hash,
            *self.policy_hash,
            *self.ring_id,
        ];
        if let PolicyKey::Member { anonymous } = self.key {
            elements.push(bit(anonymous));
        }
        elements.extend([
            bit(self.approval_required),
            bit(self.key_escrow),
            *self.own_root,
            *self.curator_root,
            *self.sender,
        ]);
        for (asset, amount) in self.public_assets.iter().zip(self.public_amounts) {
            elements.extend([*asset, *amount]);
        }
        elements
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// An application of `count` queued writes, mirror `prover/server/custom_rings/circuits/registry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyRecordsStatement {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    /// `chain(head - 1)`.
    pub chain_start: [u8; 32],
    /// `chain(tail - 1)`.
    pub chain_end: [u8; 32],
    pub count: u64,
}

impl ApplyRecordsStatement {
    /// `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`.
    pub fn elements(&self) -> [[u8; 32]; 8] {
        [
            domain::field(domain::APPLY_RECORDS),
            self.old_root,
            self.new_root,
            right_align(&self.old_next_index.to_be_bytes()),
            right_align(&self.new_next_index.to_be_bytes()),
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
        ]
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// The auditor envelope of a registered nullifier key, mirror
/// `prover/server/custom_rings/circuits/policy/register_key.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterKeyStatement<'a> {
    /// The owner identity of the signing member.
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: &'a [u8; 32],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

impl RegisterKeyStatement<'_> {
    /// `[CRRG, member, nullifier_pk, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`.
    pub fn elements(&self) -> Result<[[u8; 32]; 8], HasherError> {
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        let [eph0, eph1] = pack_be(&tagged_x25519(self.eph_u));
        Ok([
            domain::field(domain::REGISTER_KEY),
            *self.member,
            *self.nullifier_pk,
            aud0,
            aud1,
            eph0,
            eph1,
            hash_bytes(self.ciphertext)?,
        ])
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }
}

fn bit(value: bool) -> [u8; 32] {
    right_align(&[u8::from(value)])
}
