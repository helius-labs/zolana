//! The auditor message joins `messages` before the SPP proof. That proof fixes
//! the `private_tx_hash` the audit proof binds, so the two are separate steps.

use custom_ring_interface::{
    CustomRingBasePublicInput, CustomRingPolicyPublicInput, AUDIT_INPUT_SLOTS,
    TAGGED_X25519_KEY_LEN,
};
use zeroize::Zeroizing;
use zolana_client::{prover::indexed::IndexedPolicyData, ProofInputUtxo};
use zolana_hasher::primitives::{is_canonical_bn254_scalar_be, SOLANA_OWNER_TAG};
use zolana_keypair::{ViewingKey, X25519Pubkey};
use zolana_ring_client::{AnonymousDisclosure, AuditorEncryption, AuditorMessage};
use zolana_ring_policy::POLICY_OUTPUT_SLOTS;
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    prover::RingCircuit,
    request::{
        AnonymousBase, AnonymousFlag, AnonymousIdentities, AuditSecrets, BaseBody, PolicyBody,
        IDENTITY_LEN,
    },
    witness::{input_opening, output_opening, CustomRingWitness},
    RingError,
};

#[must_use]
pub struct CustomRingProofParams {
    /// The AES plaintext.
    pub tx_viewing_key: ViewingKey,
    pub auditor_pk: X25519Pubkey,
    pub salt: [u8; 16],
    pub outputs: Vec<ProofInputUtxo>,
}

#[must_use]
pub struct EncryptedAudit {
    pub pending: PendingCustomRingProof,
    pub message: AuditorMessage,
}

/// An encryption waiting for the `private_tx_hash` it will be bound to.
#[must_use]
pub struct PendingCustomRingProof {
    tx_viewing_key: ViewingKey,
    tx_viewing_pk: X25519Pubkey,
    auditor_pk: X25519Pubkey,
    ephemeral_sk: Zeroizing<[u8; 32]>,
    message: AuditorMessage,
    salt: [u8; 16],
    outputs: Vec<ProofInputUtxo>,
    /// The hidden sender and slot openings of an anonymous ring.
    anonymous: Option<AnonymousDisclosure>,
}

/// The policy body and, on the indexed route, what the prover resolves for it.
pub(crate) struct PolicyProof {
    pub body: PolicyBody,
    pub indexed: Option<IndexedPolicyData>,
}

impl CustomRingProofParams {
    /// Each call mints its ephemeral key, a reused one would publish the XOR of two viewing keys.
    pub fn encrypt(self) -> Result<EncryptedAudit, RingError> {
        self.encrypt_with(None)
    }

    /// Seals the hidden sender and the slot openings under the capsule of the viewing key.
    pub fn encrypt_anonymous(
        self,
        disclosure: AnonymousDisclosure,
    ) -> Result<EncryptedAudit, RingError> {
        self.encrypt_with(Some(disclosure))
    }

    fn encrypt_with(
        self,
        anonymous: Option<AnonymousDisclosure>,
    ) -> Result<EncryptedAudit, RingError> {
        let AuditorEncryption {
            ephemeral_sk,
            message,
        } = match &anonymous {
            Some(disclosure) => AuditorEncryption::new_with_anonymous(
                &self.tx_viewing_key,
                &self.auditor_pk,
                self.salt,
                disclosure,
            )?,
            None => AuditorEncryption::new_with_outputs(
                &self.tx_viewing_key,
                &self.auditor_pk,
                self.salt,
                &self.outputs,
            )?,
        };
        Ok(EncryptedAudit {
            pending: PendingCustomRingProof {
                tx_viewing_pk: self.tx_viewing_key.pubkey(),
                tx_viewing_key: self.tx_viewing_key,
                auditor_pk: self.auditor_pk,
                ephemeral_sk,
                message: message.clone(),
                salt: self.salt,
                outputs: self.outputs,
                anonymous,
            },
            message,
        })
    }
}

impl PendingCustomRingProof {
    pub(crate) fn is_anonymous(&self) -> bool {
        self.anonymous.is_some()
    }

    pub(crate) fn finish_base(self, private_tx_hash: [u8; 32]) -> Result<BaseBody, RingError> {
        self.base(private_tx_hash, None)
    }

    /// The anonymous statement also opens every SPP slot the disclosure names.
    pub(crate) fn finish_anonymous_base(
        self,
        private_tx_hash: [u8; 32],
        slots: &SppProofInputs,
    ) -> Result<BaseBody, RingError> {
        self.base(private_tx_hash, Some(slots))
    }

    fn base(
        self,
        private_tx_hash: [u8; 32],
        slots: Option<&SppProofInputs>,
    ) -> Result<BaseBody, RingError> {
        let audit = self.secrets(private_tx_hash)?;
        let output_hashes = self.output_hashes()?;
        let public_input_hash = self.statement(&private_tx_hash, &output_hashes).hash()?;
        let anonymous = match (self.anonymous.is_some(), slots) {
            (false, None) => None,
            (true, Some(slots)) => Some(self.anonymous_base(slots)?),
            _ => return Err(RingError::AnonymousDisclosureShape),
        };
        Ok(BaseBody {
            circuit_type: if anonymous.is_some() || self.outputs.len() != 2 {
                RingCircuit::Base
            } else {
                RingCircuit::BaseConfidential
            },
            public_input_hash,
            n_out: self.outputs.len() as u8,
            outputs: self.outputs,
            audit,
            anonymous,
        })
    }

    fn anonymous_base(&self, slots: &SppProofInputs) -> Result<AnonymousBase, RingError> {
        let (inputs, outputs) = (&slots.input_utxos, &slots.output_utxos);
        if inputs.len() > AUDIT_INPUT_SLOTS || outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(RingError::AnonymousDisclosureShape);
        }
        let mut base = AnonymousBase {
            identities: self
                .identities(inputs.len())?
                .ok_or(RingError::AnonymousDisclosureShape)?,
            n_in: inputs.len() as u8,
            inputs: Default::default(),
            anonymous_outputs: Default::default(),
            private_tx_blinding: slots.private_tx_blinding()?,
        };
        for (slot, input) in base.inputs.iter_mut().zip(inputs) {
            *slot = input_opening(input)?;
        }
        for (slot, output) in base.anonymous_outputs.iter_mut().zip(outputs) {
            *slot = output_opening(output, slots.output_tree_id)?;
        }
        Ok(base)
    }

    /// The program recomputes this public input from the payload and the config account.
    pub(crate) fn finish(
        self,
        private_tx_hash: [u8; 32],
        mut witness: Box<CustomRingWitness>,
        policy_hash: &[u8; 32],
    ) -> Result<PolicyProof, RingError> {
        let audit = self.secrets(private_tx_hash)?;
        let output_hashes = self.output_hashes()?;
        let anonymous = self.identities(usize::from(witness.n_in))?;
        let tree_slots = witness.tree_slots();
        let statement = CustomRingPolicyPublicInput {
            audit: self.statement(&private_tx_hash, &output_hashes),
            policy_hash,
            tree_slots: &tree_slots,
            address_tree_id: witness.address_tree_id,
            ring_id: &witness.limits.ring_id,
            namespace_owner_hash: &witness.limits.namespace_owner_hash,
            approval_required: witness.limits.approval_required,
            key_escrow: witness.key_escrow,
            member_registry_root: &witness.member_registry_root,
            foreign_root: &witness.foreign_root,
        };
        let public_input_hash = statement.hash()?;
        let indexed = match witness.indexed.take() {
            Some(registries) => Some(IndexedPolicyData {
                registry: registries.registry,
                foreign_registry: registries.foreign,
                public_inputs: statement.indexed_inputs()?.to_vec(),
                trees: witness.trees.iter().map(|tree| tree.resolved()).collect(),
            }),
            None => None,
        };
        Ok(PolicyProof {
            body: PolicyBody {
                circuit_type: RingCircuit::Policy,
                public_input_hash,
                audit,
                anonymous,
                witness,
            },
            indexed,
        })
    }

    /// The tagged hidden identities, checked against the slot counts the statement opens.
    fn identities(&self, n_in: usize) -> Result<Option<AnonymousIdentities>, RingError> {
        let Some(disclosure) = &self.anonymous else {
            return Ok(None);
        };
        if disclosure.inputs.len() != n_in || disclosure.outputs.len() != self.outputs.len() {
            return Err(RingError::AnonymousDisclosureShape);
        }
        let mut sender = [SOLANA_OWNER_TAG; IDENTITY_LEN];
        sender[1..].copy_from_slice(&disclosure.sender);
        let mut identities = AnonymousIdentities {
            flag: AnonymousFlag,
            sender,
            recipients: [[0; IDENTITY_LEN]; POLICY_OUTPUT_SLOTS],
            recipient_viewing_keys: [[0; TAGGED_X25519_KEY_LEN]; POLICY_OUTPUT_SLOTS],
        };
        for ((identity, viewing_key), output) in identities
            .recipients
            .iter_mut()
            .zip(&mut identities.recipient_viewing_keys)
            .zip(&disclosure.outputs)
        {
            identity[0] = output.identity_tag;
            identity[1..].copy_from_slice(&output.identity_key);
            *viewing_key = output.viewing_pk;
        }
        Ok(Some(identities))
    }

    fn output_hashes(&self) -> Result<Vec<[u8; 32]>, RingError> {
        if self.outputs.is_empty() || self.outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(RingError::PolicyShapeUnsupported);
        }
        Ok(self
            .outputs
            .iter()
            .map(ProofInputUtxo::hash)
            .collect::<Result<_, _>>()?)
    }

    fn statement<'a>(
        &'a self,
        private_tx_hash: &'a [u8; 32],
        output_hashes: &'a [[u8; 32]],
    ) -> CustomRingBasePublicInput<'a> {
        CustomRingBasePublicInput {
            private_tx_hash,
            tx_viewing_pk: self.tx_viewing_pk.as_bytes(),
            auditor_pk: self.auditor_pk.as_bytes(),
            eph_pk: self.message.ephemeral_pubkey_bytes(),
            ciphertext: self.message.ciphertext(),
            output_hashes,
            salt: &self.salt,
            disclosure: self.message.disclosure(),
            anonymous: self.anonymous.is_some(),
        }
    }

    /// The audit statement binds the `private_tx_hash` that SPP settles.
    fn secrets(&self, private_tx_hash: [u8; 32]) -> Result<AuditSecrets, RingError> {
        if !is_canonical_bn254_scalar_be(&private_tx_hash) {
            return Err(RingError::NonCanonicalHash);
        }
        Ok(AuditSecrets {
            private_tx_hash,
            tx_viewing_key: self.tx_viewing_key.clone(),
            ephemeral_sk: self.ephemeral_sk.clone(),
            auditor_key: self.auditor_pk,
            salt: self.salt,
        })
    }
}
