use crate::ClientError;
use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice, primitives::right_align,
    zero_suffix_hash_chain::create_padded_right_hash_chain_4,
};
use zolana_interface::{
    instruction::instruction_data::MergeOutputEncryption, tree_slot::tree_id_field,
};

/// The rail-specific part of the merge statement, before the output ciphertext.
pub enum MergePublicInputBinding {
    Owner {
        signing_key_hash: [u8; 32],
        nullifier_public_key: [u8; 32],
    },
    Ring {
        output_data_hash: [u8; 32],
        program_id_hash: [u8; 32],
        /// `None` until the ring registration is bound.
        member_registry_root: Option<[u8; 32]>,
    },
}

/// One ordering for local proofs, indexed requests and cross-language vectors.
pub struct MergePublicInputs<'a> {
    pub nullifiers: &'a [[u8; 32]],
    pub output_hash: [u8; 32],
    pub output_tree_id: u16,
    pub private_tx_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: bool,
    pub binding: MergePublicInputBinding,
    pub output_encryption: MergeOutputEncryption,
}

impl MergePublicInputs<'_> {
    /// Indexed requests omit the tree hash until the indexer resolves it.
    pub fn elements(
        &self,
        tree_slots_hash: Option<[u8; 32]>,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        let mut elements = vec![
            create_padded_right_hash_chain_4(self.nullifiers, self.nullifiers.len())?,
            self.output_hash,
        ];
        elements.extend(tree_slots_hash);
        elements.extend([
            tree_id_field(self.output_tree_id),
            self.private_tx_hash,
            self.external_data_hash,
            right_align(&[u8::from(self.allow_dummy_inputs)]),
        ]);
        match &self.binding {
            MergePublicInputBinding::Ring {
                output_data_hash,
                program_id_hash,
                member_registry_root,
            } => {
                elements.extend([*output_data_hash, *program_id_hash]);
                elements.extend(*member_registry_root);
            }
            MergePublicInputBinding::Owner {
                signing_key_hash,
                nullifier_public_key,
            } => {
                elements.extend([*signing_key_hash, *nullifier_public_key]);
            }
        }
        match &self.output_encryption {
            MergeOutputEncryption::PoseidonCtrV1 { salt, ciphertext } => {
                elements.push(right_align(salt));
                elements.extend(ciphertext);
            }
        }
        Ok(elements)
    }

    pub fn hash(&self, tree_slots_hash: [u8; 32]) -> Result<[u8; 32], ClientError> {
        Ok(create_hash_chain_4_from_slice(
            &self.elements(Some(tree_slots_hash))?,
        )?)
    }
}
