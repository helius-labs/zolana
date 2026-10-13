//! Custom-ring transfer proof builder whose shared owner authorizes its
//! inputs with an Ed25519 signature the proof verifies (`CircuitId::RingP256`,
//! `transfer-p256-ring`).

use num_bigint::BigUint;
use solana_address::Address;
use zolana_hasher::primitives::{hash_bytes, solana_owner_identity};
use zolana_interface::instruction::instruction_data::transact::TreeContext;
use zolana_keypair::PublicKey;
use zolana_transaction::{
    instructions::transact::{transact_message_hash, PublicTransfers},
    utxo::program_id_proof_input_hash,
    Ed25519Authorization, ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        cache::CacheSelection,
        field::be,
        transact::assembly::{
            assemble_transaction, confidential_marked_output_owner_pk_hashes, validate_shape,
            AssembledTransaction, OwnerMode, PublicInputs, TransferInputUtxo,
        },
        Shape, TransferP256Inputs, TreeSlotFields,
    },
};

pub struct RingTransferP256Prover {
    pub inputs: Vec<TransferInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`TransferProver::blinding_seed`](crate::prover::TransferProver).
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    /// The payer first, then the runtime owner signers without the
    /// authorization key, as `SppProofInputs::runtime_signer_pk_hashes`
    /// builds them.
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    pub authorization: Ed25519Authorization,
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

#[derive(Debug, Clone)]
pub struct RingTransferP256ProofResult {
    pub inputs: TransferP256Inputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    /// One root-index pair per input tree, in the order the tree accounts are
    /// passed. An input selects its pair with its `tree_index`.
    pub tree_contexts: Vec<TreeContext>,
    /// Each input's index into `tree_contexts`, parallel to `nullifiers`.
    pub input_tree_indexes: Vec<u8>,
    /// The shared owner's Ed25519 public key, carried in `CircuitId::RingP256`
    /// when it spends a default-ring UTXO. Address slots never set it.
    pub default_owner_tag: Option<[u8; 32]>,
}

impl RingTransferP256Prover {
    pub fn build(self) -> Result<RingTransferP256ProofResult, ClientError> {
        let shape = self.shape;
        validate_shape(shape, self.inputs.len(), self.outputs.len())?;
        if self.signer_pk_hashes.len() != shape.signer_width() {
            return Err(ClientError::WitnessInputCountMismatch {
                got: self.signer_pk_hashes.len(),
                expected: shape.signer_width(),
            });
        }

        let cache = CacheSelection::derive(
            &self.inputs,
            &self.outputs,
            Default::default(),
            &self.external_data,
        )?;
        let AssembledTransaction {
            inputs: assembled_inputs,
            outputs: assembled_outputs,
            external_data_hash,
            private_tx_hash: private_tx,
            input_flags,
        } = assemble_transaction(
            &self.inputs,
            &self.outputs,
            &self.blinding_seed,
            self.output_tree_id,
            &cache.external_data_hash,
            &OwnerMode::RingP256 {
                shared_owner: PublicKey::from_ed25519(&self.authorization.pubkey),
            },
            self.allow_dummy_inputs,
        )?;
        let published_output_owner_pk_hashes =
            confidential_marked_output_owner_pk_hashes(&self.external_data, self.outputs.len())?;
        let PreparedEd25519Authorization {
            message_digest,
            default_owner_tag,
            default_owner_pk_hash,
        } = Ed25519AuthorizationPreparation {
            inputs: &self.inputs,
            authorization: &self.authorization,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            published_owners: &published_output_owner_pk_hashes,
            signer_pk_hashes: &self.signer_pk_hashes,
        }
        .prepare()?;

        let ring_program_id = program_id_proof_input_hash(&self.ring_program_id)?;
        let message_proof_input_hash = hash_bytes(&message_digest)?;
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id: self.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &self.public_transfers,
            ring_program_id: &ring_program_id,
            input_flags: &input_flags,
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: Some(&published_output_owner_pk_hashes),
            cached_inputs: cache.public_fields,
        }
        .hash_with_after_private_tx(&[message_proof_input_hash, default_owner_pk_hash])?;

        let inputs = TransferP256Inputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: BigUint::from(self.output_tree_id),
            blinding_seed: be(&self.blinding_seed),
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            ed25519_public_key: self.authorization.pubkey,
            ed25519_signature: self.authorization.signature,
            ed25519_message_hash_low: BigUint::from_bytes_be(message_digest_low(&message_digest)),
            ed25519_message_hash_high: BigUint::from_bytes_be(message_digest_high(&message_digest)),
            default_ed25519_owner_pk_hash: be(&default_owner_pk_hash),
            public_assets: self.public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: self.public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: be(&ring_program_id),
            signer_pk_hashes: self.signer_pk_hashes.iter().map(be).collect(),
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: published_output_owner_pk_hashes
                .iter()
                .map(be)
                .collect(),
            cache: cache.proof_inputs,
            public_input_hash: be(&public_input),
        };

        Ok(RingTransferP256ProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            tree_contexts: assembled_inputs.tree_contexts,
            input_tree_indexes: assembled_inputs.input_tree_indexes,
            default_owner_tag,
        })
    }
}

pub(crate) struct Ed25519AuthorizationPreparation<'a> {
    pub inputs: &'a [TransferInputUtxo],
    pub authorization: &'a Ed25519Authorization,
    pub private_tx: &'a [u8; 32],
    pub external_data_hash: &'a [u8; 32],
    pub published_owners: &'a [[u8; 32]],
    pub signer_pk_hashes: &'a [[u8; 32]],
}

pub(crate) struct PreparedEd25519Authorization {
    pub message_digest: [u8; 32],
    pub default_owner_tag: Option<[u8; 32]>,
    pub default_owner_pk_hash: [u8; 32],
}

impl Ed25519AuthorizationPreparation<'_> {
    /// Mirrors the circuit: inputs owned by the authorization key take the
    /// zero owner sentinel and are authorized by the signature, every other
    /// real input needs a runtime signer. The shared identity is the Solana
    /// tag of the key, the value SPP publishes for a runtime signer of that
    /// key, so a ring-bound spend keeps it out of the published output owners
    /// and the signer vector, payer included, and may not coexist with a
    /// default-ring spend that would publish it.
    pub fn prepare(self) -> Result<PreparedEd25519Authorization, ClientError> {
        let message_digest = transact_message_hash(self.private_tx, self.external_data_hash);
        let shared_owner = PublicKey::from_ed25519(&self.authorization.pubkey);
        let rings = authorized_spend_rings(self.inputs, &shared_owner, self.signer_pk_hashes)?;
        verify_authorization(self.authorization, &message_digest)?;

        let shared_identity = solana_owner_identity(&self.authorization.pubkey)?;
        if rings.default_ring && rings.bound_ring {
            return Err(ClientError::RingEd25519MixedDefaultAndRingSpend);
        }
        if rings.bound_ring {
            if let Some(index) = self
                .published_owners
                .iter()
                .position(|published| *published == shared_identity)
            {
                return Err(ClientError::RingEd25519PublishedOwnerLeaksIdentity { index });
            }
            if let Some(index) = self
                .signer_pk_hashes
                .iter()
                .position(|signer| *signer == shared_identity)
            {
                return Err(ClientError::RingEd25519SignerLeaksIdentity { index });
            }
        }
        let default_owner_tag = rings.default_ring.then_some(self.authorization.pubkey);
        let default_owner_pk_hash = match default_owner_tag {
            Some(_) => shared_identity,
            None => [0u8; 32],
        };

        Ok(PreparedEd25519Authorization {
            message_digest,
            default_owner_tag,
            default_owner_pk_hash,
        })
    }
}

/// The first 16 digest bytes, the high 128-bit limb of the signing digest.
pub(crate) fn message_digest_high(digest: &[u8; 32]) -> &[u8] {
    digest.split_at(16).0
}

/// The final 16 digest bytes, the low 128-bit limb of the signing digest.
pub(crate) fn message_digest_low(digest: &[u8; 32]) -> &[u8] {
    digest.split_at(16).1
}

/// Which rings the proof's spent UTXOs of the authorization key belong to.
struct AuthorizedSpendRings {
    default_ring: bool,
    bound_ring: bool,
}

fn authorized_spend_rings(
    inputs: &[TransferInputUtxo],
    shared_owner: &PublicKey,
    signer_pk_hashes: &[[u8; 32]],
) -> Result<AuthorizedSpendRings, ClientError> {
    let mut rings = AuthorizedSpendRings {
        default_ring: false,
        bound_ring: false,
    };
    let mut found = false;
    for (index, input_utxo) in inputs.iter().enumerate() {
        if input_utxo.utxo.is_dummy() {
            continue;
        }
        let owner = &input_utxo.utxo.utxo.owner;
        if owner != shared_owner {
            if !signer_pk_hashes.contains(&owner.owner_proof_input_hash()?) {
                return Err(ClientError::RingEd25519InputNotAuthorized { index });
            }
            continue;
        }
        found = true;
        if input_utxo.utxo.utxo.ring_program_id.is_some() {
            rings.bound_ring = true;
        } else {
            rings.default_ring = true;
        }
    }
    if !found {
        return Err(ClientError::Ed25519ProofWithoutAuthorizedInput);
    }
    Ok(rings)
}

/// Strict RFC 8032 verification, the rule the circuit enforces: canonical `S`,
/// no small-order key, cofactorless equation.
fn verify_authorization(
    authorization: &Ed25519Authorization,
    message_digest: &[u8; 32],
) -> Result<(), ClientError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&authorization.pubkey)
        .map_err(|e| ClientError::InvalidEd25519Authorization(e.to_string()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&authorization.signature);
    verifying_key
        .verify_strict(message_digest, &signature)
        .map_err(|e| ClientError::InvalidEd25519Authorization(e.to_string()))
}
