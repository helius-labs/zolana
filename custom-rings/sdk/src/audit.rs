//! The auditor message joins `messages` before the SPP proof. That proof fixes
//! the `private_tx_hash` the audit proof binds, so the two are separate steps.

use custom_ring_interface::{CustomRingBasePublicInput, CustomRingPolicyPublicInput};
use zeroize::Zeroizing;
use zolana_client::{prover::indexed::IndexedPolicyData, ProofInputUtxo};
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_ring_client::{AuditorEncryption, AuditorMessage};
use zolana_ring_policy::POLICY_OUTPUT_SLOTS;

use crate::{
    prover::RingCircuit,
    request::{AuditSecrets, BaseBody, PolicyBody},
    witness::CustomRingWitness,
    RingError,
};

#[must_use]
pub struct CustomRingProofParams {
    /// The AES plaintext.
    pub tx_viewing_key: ViewingKey,
    pub auditor_pk: P256Pubkey,
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
    tx_viewing_pk: P256Pubkey,
    auditor_pk: P256Pubkey,
    ephemeral_sk: Zeroizing<[u8; 32]>,
    message: AuditorMessage,
    salt: [u8; 16],
    outputs: Vec<ProofInputUtxo>,
}

/// The policy body and, on the indexed route, what the prover resolves for it.
pub(crate) struct PolicyProof {
    pub body: PolicyBody,
    pub indexed: Option<IndexedPolicyData>,
}

impl CustomRingProofParams {
    /// Each call mints its ephemeral key, a reused one would publish the XOR of two viewing keys.
    pub fn encrypt(self) -> Result<EncryptedAudit, RingError> {
        let AuditorEncryption {
            ephemeral_sk,
            message,
        } = AuditorEncryption::new_with_outputs(
            &self.tx_viewing_key,
            &self.auditor_pk,
            self.salt,
            &self.outputs,
        )?;
        Ok(EncryptedAudit {
            pending: PendingCustomRingProof {
                tx_viewing_pk: self.tx_viewing_key.pubkey(),
                tx_viewing_key: self.tx_viewing_key,
                auditor_pk: self.auditor_pk,
                ephemeral_sk,
                message,
                salt: self.salt,
                outputs: self.outputs,
            },
            message,
        })
    }
}

impl PendingCustomRingProof {
    pub(crate) fn finish_base(self, private_tx_hash: [u8; 32]) -> Result<BaseBody, RingError> {
        let output_hashes = self.output_hashes()?;
        let public_input_hash = self.statement(&private_tx_hash, &output_hashes).hash()?;
        let audit = self.secrets(private_tx_hash)?;
        Ok(BaseBody {
            circuit_type: RingCircuit::Base,
            public_input_hash,
            n_out: self.outputs.len() as u8,
            outputs: self.outputs,
            audit,
        })
    }

    /// The program recomputes this public input from the payload and the config account.
    pub(crate) fn finish(
        self,
        private_tx_hash: [u8; 32],
        mut witness: CustomRingWitness,
        policy_hash: &[u8; 32],
    ) -> Result<PolicyProof, RingError> {
        let output_hashes = self.output_hashes()?;
        let tree_slots = witness.tree_slots();
        let key_registry_root = witness.escrow.0.map(|registry| registry.root);
        let statement = CustomRingPolicyPublicInput {
            audit: self.statement(&private_tx_hash, &output_hashes),
            policy_hash,
            tree_slots: &tree_slots,
            address_tree_id: witness.address_tree_id,
            ring_id: &witness.velocity.ring_id,
            namespace_owner_hash: &witness.velocity.namespace_owner_hash,
            window_index: witness.velocity.window_index,
            approval_required: witness.velocity.approval_required,
            key_registry_root: key_registry_root.as_ref(),
            revocation_tree_indexes: &witness.revocation_tree_indexes,
            revocation_targets: &witness.revocation_targets,
        };
        let public_input_hash = statement.hash()?;
        let indexed = match witness.indexed.take() {
            Some(inputs) => Some(IndexedPolicyData {
                inputs,
                registry: witness.indexed_registry.take(),
                public_inputs: statement.indexed_inputs()?.to_vec(),
                trees: witness.trees.iter().map(|tree| tree.resolved()).collect(),
            }),
            None => None,
        };
        Ok(PolicyProof {
            body: PolicyBody {
                circuit_type: RingCircuit::Policy,
                public_input_hash,
                audit: self.secrets(private_tx_hash)?,
                witness,
            },
            indexed,
        })
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
        }
    }

    /// The circuit recomputes `private_tx_hash`, so only the one the SPP witness fixed proves.
    fn secrets(&self, private_tx_hash: [u8; 32]) -> Result<AuditSecrets, RingError> {
        if !is_canonical_bn254_scalar_be(&private_tx_hash) {
            return Err(RingError::NonCanonicalHash);
        }
        Ok(AuditSecrets {
            private_tx_hash,
            tx_viewing_key: self.tx_viewing_key.clone(),
            ephemeral_key: ViewingKey::from_bytes(&self.ephemeral_sk)?,
            auditor_key: self.auditor_pk,
            salt: self.salt,
        })
    }
}
