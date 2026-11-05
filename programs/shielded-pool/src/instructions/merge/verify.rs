use arrayvec::ArrayVec;
use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, ProgramResult};
use spr_hasher::hash_chain::create_hash_chain_4_from_slice;
use spr_hasher::zero_suffix_hash_chain::create_padded_right_hash_chain_4;
use spr_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::merge_transact::{
            merge_circuit_width, MergeOutputEncryption, MergeTransactIxDataRef,
            MAX_MERGE_OUTPUT_ENCRYPTION_PUBLIC_INPUTS,
        },
        tag::{MERGE_TRANSACT, RING_MERGE_TRANSACT},
    },
    tree_slot::{populated_tree_slots_hash_chain, TreeSlot},
    verifying_keys::{merge_24_1, merge_52_1, merge_8_1},
};

use crate::instructions::verifier;

/// The owner-binding tail of the merge public-input hash, which differs by
/// variant. Modeling it as an enum keeps the two shapes mutually exclusive: the
/// default merge cannot carry a ring id, and the policy-ring merge cannot carry
/// the registry's signing identity. The variant also selects the verifying key.
pub enum MergeOwnerBinding {
    /// Default merge (`merge_transact`): owner identity bound from the user
    /// registry record -- both the signing identity and nullifier public key --
    /// and the output ciphertext under the owner's registered scheme. The
    /// scheme and the input count select the verifying key.
    Default {
        signing_pk_field: [u8; 32],
        nullifier_pk: [u8; 32],
        output_encryption: MergeOutputEncryption,
    },
    /// Policy-ring merge (`merge_ring`): `pk_field(ring_program_id)` from the
    /// calling `ring_config`, plus the output `ring_data_hash` the ring program
    /// selected; the proof asserts it against the output's
    /// `Output.Utxo.RingDataHash`.
    Ring {
        ring_program_id: [u8; 32],
        output_ring_data_hash: [u8; 32],
        /// The signer's hashed key, zero with no signer.
        published_owner: [u8; 32],
        output_encryption: MergeOutputEncryption,
    },
}

impl MergeOwnerBinding {
    /// The instruction each binding belongs to, which domain-separates the
    /// external data hash exactly as the binding selects the verifying key.
    pub fn instruction_tag(&self) -> u8 {
        match self {
            MergeOwnerBinding::Default { .. } => MERGE_TRANSACT,
            MergeOwnerBinding::Ring { .. } => RING_MERGE_TRANSACT,
        }
    }
}

/// Derived public inputs the program resolves from the trees (and, for the
/// default merge, the registry), folded into the merge public-input hash
/// alongside the instruction fields.
pub struct MergeProofInputs {
    /// Tree slot 0: `input_tree`'s id and the roots every input references.
    /// The circuit's remaining `INPUT_TREES - 1` slots stay all zero.
    pub tree_slot: TreeSlot,
    /// `tree_id_field` of the tree the merged output is appended to.
    pub output_tree_id: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
    pub owner_binding: MergeOwnerBinding,
}

pub struct MergeProof<'a> {
    ix: &'a MergeTransactIxDataRef<'a>,
    derived: MergeProofInputs,
}

impl<'a> MergeProof<'a> {
    pub fn new(ix: &'a MergeTransactIxDataRef<'a>, derived: MergeProofInputs) -> Self {
        Self { ix, derived }
    }

    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let p = &self.ix.proof;
        let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
        let proof = verifier::Groth16Proof {
            a: p.a,
            b: p.b,
            c: p.c,
            commitment: None,
        };
        let vk = self.verifying_key()?;
        verifier::verify_groth16(
            proof,
            public_input_hash,
            vk,
            encoding_err,
            ShieldedPoolError::TransactProofVerificationFailed,
        )
    }

    /// The circuit width the sent nullifiers select; slots past them are
    /// compact padding.
    fn circuit_width(&self) -> Result<usize, ProgramError> {
        merge_circuit_width(self.ix.nullifiers.len())
            .ok_or(ShieldedPoolError::InvalidMergeShape.into())
    }

    fn verifying_key(&self) -> Result<&'static Groth16Verifyingkey<'static>, ProgramError> {
        let vk = match (&self.derived.owner_binding, self.circuit_width()?) {
            (
                MergeOwnerBinding::Default {
                    output_encryption, ..
                },
                width,
            ) => match output_encryption {
                MergeOutputEncryption::PoseidonCtrV1 { .. } => match width {
                    8 => &merge_8_1::VERIFYINGKEY,
                    24 => &merge_24_1::VERIFYINGKEY,
                    52 => &merge_52_1::VERIFYINGKEY,
                    _ => return Err(ShieldedPoolError::InvalidMergeShape.into()),
                },
            },
            // No ring merge keys are pinned.
            (MergeOwnerBinding::Ring { .. }, _) => {
                return Err(ShieldedPoolError::CircuitFeatureDisabled.into())
            }
        };
        Ok(vk)
    }

    /// The 4-input Poseidon hash chain the circuit folds into its single public
    /// input (`prover/server/circuits/spp_merge/{default,ring}.go`, prefix from
    /// `spp_merge/shared/transaction.go` `CommonPublicInputs.Prefix`).
    ///
    /// Both variants share the same 7 leading elements (nullifier chain, output
    /// hash, tree slot chain, output tree id, private tx hash, external data
    /// hash, dummy-input policy). The default merge then appends the owner's
    /// signing identity and nullifier public key (from the registry) and its
    /// scheme's ciphertext elements (PoseidonCtrV1: the salt and the three
    /// ciphertext elements). The policy-ring merge omits that identity (no
    /// registry to bind it against) and appends the output `ring_data_hash`,
    /// `ring_program_id`, the published owner and the ciphertext elements. The
    /// 7-element prefix is 1 + 3 + 3, so it ends on a complete HashChain4 group
    /// without padding. Continuing
    /// from its hash with the tail is therefore equivalent to folding all
    /// elements together.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        // The circuit's `TreeSlotsHashChain` over `[slot0, 0, 0, 0, 0]`: one
        // slot hash folded onto the precomputed four-slot zero suffix.
        let prefix_hash = create_hash_chain_4_from_slice(&[
            create_padded_right_hash_chain_4(&self.ix.nullifiers, self.circuit_width()?)?,
            *self.ix.output_utxo_hash,
            populated_tree_slots_hash_chain(core::slice::from_ref(&self.derived.tree_slot))?,
            self.derived.output_tree_id,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
            self.derived.allow_dummy_inputs,
        ])?;
        let mut inputs =
            ArrayVec::<[u8; 32], { 4 + MAX_MERGE_OUTPUT_ENCRYPTION_PUBLIC_INPUTS }>::new();
        inputs.push(prefix_hash);
        let output_encryption = match &self.derived.owner_binding {
            MergeOwnerBinding::Default {
                signing_pk_field,
                nullifier_pk,
                output_encryption,
            } => {
                inputs.extend([*signing_pk_field, *nullifier_pk]);
                output_encryption
            }
            MergeOwnerBinding::Ring {
                ring_program_id,
                output_ring_data_hash,
                published_owner,
                output_encryption,
            } => {
                inputs.extend([*output_ring_data_hash, *ring_program_id, *published_owner]);
                output_encryption
            }
        };
        // Sized for every scheme's tail, so this cannot overflow.
        output_encryption
            .append_public_inputs(&mut inputs)
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        create_hash_chain_4_from_slice(&inputs).map_err(Into::into)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::Value;
    use spr_interface::{
        instruction::instruction_data::merge_transact::{
            MergeProof as MergeProofData, MergeTransactIxData,
        },
        tree_slot::tree_id_field,
    };

    use super::*;

    pub(crate) fn field(value: &Value) -> [u8; 32] {
        let hex = value.as_str().expect("hex string");
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex byte")
        })
    }

    pub(crate) fn output_encryption(salt: &Value, ciphertext: &Value) -> MergeOutputEncryption {
        let salt = salt.as_str().expect("salt");
        MergeOutputEncryption::PoseidonCtrV1 {
            salt: core::array::from_fn(|index| {
                u8::from_str_radix(&salt[index * 2..index * 2 + 2], 16).expect("hex byte")
            }),
            ciphertext: core::array::from_fn(|index| field(&ciphertext[index])),
        }
    }

    /// Compact padding stays off the wire.
    pub(crate) fn ix_data(
        nullifiers: &[[u8; 32]],
        output_hash: [u8; 32],
        private_tx_hash: [u8; 32],
        output_encryption: MergeOutputEncryption,
    ) -> Vec<u8> {
        MergeTransactIxData {
            cache_slot: None,
            expiry_unix_ts: 0,
            proof: MergeProofData::zeroed(),
            output_utxo_hash: output_hash,
            output_encryption,
            private_tx_hash,
            nullifiers: nullifiers
                .iter()
                .copied()
                .filter(|nullifier| *nullifier != [0; 32])
                .collect(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }
        .serialize()
        .expect("serialize")
    }

    pub(crate) fn derived(
        tree_slot: TreeSlot,
        output_tree_id: u16,
        external_data_hash: [u8; 32],
        owner_binding: MergeOwnerBinding,
    ) -> MergeProofInputs {
        let mut allow_dummy_inputs = [0u8; 32];
        allow_dummy_inputs[31] = 1;
        MergeProofInputs {
            tree_slot,
            output_tree_id: tree_id_field(output_tree_id),
            external_data_hash,
            allow_dummy_inputs,
            owner_binding,
        }
    }

    /// Pins both rails' statements to the cross-language vectors whose sent
    /// nullifiers select the vector's width.
    #[test]
    fn statements_match_the_shared_vectors() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../../test-vectors/public_input_hash.json"
        ))
        .expect("vectors");
        let mut checked = [0usize; 2];
        for (rail, key) in ["merges", "ring_merges"].into_iter().enumerate() {
            for vector in vectors[key].as_array().expect("vectors") {
                let nullifiers: Vec<[u8; 32]> = vector["nullifiers"]
                    .as_array()
                    .expect("nullifiers")
                    .iter()
                    .map(field)
                    .collect();
                let sent = nullifiers.iter().filter(|n| **n != [0; 32]).count();
                if merge_circuit_width(sent) != Some(nullifiers.len()) {
                    continue;
                }
                let encryption = output_encryption(
                    &vector["output_ciphertext_salt"],
                    &vector["output_ciphertext"],
                );
                let data = ix_data(
                    &nullifiers,
                    field(&vector["output_hash"]),
                    field(&vector["private_tx_hash"]),
                    encryption,
                );
                let ix = MergeTransactIxDataRef::from_bytes(&data).expect("parse");
                let slot = &vector["tree_slots"][0];
                let owner_binding = if rail == 0 {
                    MergeOwnerBinding::Default {
                        signing_pk_field: field(&vector["owner_pk_hash"]),
                        nullifier_pk: field(&vector["nullifier_pk"]),
                        output_encryption: encryption,
                    }
                } else {
                    MergeOwnerBinding::Ring {
                        ring_program_id: field(&vector["ring_program_id"]),
                        output_ring_data_hash: field(&vector["output_ring_data_hash"]),
                        published_owner: field(&vector["published_owner"]),
                        output_encryption: encryption,
                    }
                };
                let proof = MergeProof::new(
                    &ix,
                    derived(
                        TreeSlot {
                            id: tree_id_field(slot["id"].as_u64().expect("id") as u16),
                            utxo_root: field(&slot["utxo_root"]),
                            nullifier_root: field(&slot["nullifier_root"]),
                        },
                        vector["output_tree_id"].as_u64().expect("tree id") as u16,
                        field(&vector["external_data_hash"]),
                        owner_binding,
                    ),
                );
                assert_eq!(
                    proof.public_input_hash().expect("hash"),
                    field(&vector["public_input_hash"]),
                    "{}",
                    vector["name"]
                );
                checked[rail] += 1;
            }
        }
        assert_eq!(checked, [2, 2]);
    }

    /// Refused ahead of any pairing.
    #[test]
    fn ring_is_refused_until_its_keys_are_pinned() {
        let encryption = MergeOutputEncryption::PoseidonCtrV1 {
            salt: [0; 16],
            ciphertext: [[0; 32]; 3],
        };
        let data = ix_data(&[[3; 32]], [1; 32], [2; 32], encryption);
        let ix = MergeTransactIxDataRef::from_bytes(&data).expect("parse");
        for published_owner in [[0; 32], [4; 32]] {
            let proof = MergeProof::new(
                &ix,
                derived(
                    TreeSlot::ZERO,
                    0,
                    [0; 32],
                    MergeOwnerBinding::Ring {
                        ring_program_id: [0; 32],
                        output_ring_data_hash: [0; 32],
                        published_owner,
                        output_encryption: encryption,
                    },
                ),
            );
            assert_eq!(
                proof.verify(),
                Err(ShieldedPoolError::CircuitFeatureDisabled.into())
            );
        }
    }
}
