use anyhow::{anyhow, Result};
use compression_example_program::instructions::read::ReadPublicInput;
use compression_example_prover::ReadProofInputs;
use zolana_client::{MerkleProof, NonInclusionProof};
use zolana_interface::instruction::instruction_data::transact::TreeContext;
use zolana_program::compression::CompressedAccountMeta;
use zolana_transaction::WalletUtxo;

use crate::{err, state::decode_state};

pub struct ReadProofInputParams {
    pub current: WalletUtxo,
    /// Inclusion of `current` in the state tree, under any root in its history.
    pub merkle_proof: MerkleProof,
    /// Non-inclusion of `current`'s nullifier in the nullifier tree, under any
    /// root in its history.
    pub non_inclusion: NonInclusionProof,
}

pub struct ReadCompressedAccount {
    pub proof_inputs: ReadProofInputs,
    pub value: u64,
    pub version: u64,
    pub meta: CompressedAccountMeta,
    pub nullifier: [u8; 32],
}

impl ReadProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<ReadCompressedAccount> {
        let state = decode_state(
            self.current
                .utxo
                .data
                .utxo_data()
                .ok_or_else(|| anyhow!("current UTXO has no state data"))?,
        )?;
        if self.current.utxo.blinding != state.blinding {
            return Err(anyhow!("current UTXO blinding does not match its state"));
        }
        if self.merkle_proof.leaf != self.current.utxo_hash {
            return Err(anyhow!("merkle proof is not for the current UTXO"));
        }
        if self.non_inclusion.leaf != self.current.nullifier {
            return Err(anyhow!(
                "non-inclusion proof is not for the current nullifier"
            ));
        }
        let public_input_hash = ReadPublicInput {
            utxo_hash: &self.current.utxo_hash,
            utxo_root: &self.merkle_proof.root,
            nullifier: &self.current.nullifier,
            nullifier_root: &self.non_inclusion.root,
        }
        .hash()
        .map_err(err)?;
        Ok(ReadCompressedAccount {
            proof_inputs: ReadProofInputs {
                public_input_hash,
                merkle_proof: self.merkle_proof.clone(),
                non_inclusion: self.non_inclusion.clone(),
            },
            value: state.value,
            version: state.version,
            meta: CompressedAccountMeta {
                address: state.address,
                blinding: state.blinding,
                tree_context: TreeContext {
                    utxo_tree_root_index: self.merkle_proof.root_index,
                    nullifier_tree_root_index: self.non_inclusion.root_index,
                },
            },
            nullifier: self.current.nullifier,
        })
    }
}
