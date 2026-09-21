use crate::{ClientError, MerkleProof, NonInclusionProof, SpendProof};
use solana_address::Address;
use zolana_transaction::instructions::types::InputUtxoContext;

pub struct InputProofs<'a> {
    pub tree: Address,
    pub commitments: &'a [InputUtxoContext],
    pub state_proofs: Vec<MerkleProof>,
    pub nullifier_proofs: Vec<NonInclusionProof>,
}

impl InputProofs<'_> {
    pub fn validate(self) -> Result<Vec<SpendProof>, ClientError> {
        let Self {
            tree,
            commitments,
            state_proofs,
            nullifier_proofs,
        } = self;
        if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
            return Err(ClientError::IncompleteInputProofs {
                expected: commitments.len(),
                state: state_proofs.len(),
                nullifier: nullifier_proofs.len(),
            });
        }

        state_proofs
            .into_iter()
            .zip(nullifier_proofs)
            .zip(commitments)
            .enumerate()
            .map(|(index, ((state, nullifier), commitment))| {
                if state.leaf != commitment.utxo_hash {
                    return Err(ClientError::StateProofLeafMismatch { index });
                }
                if state.merkle_context.tree != tree {
                    return Err(ClientError::StateProofTreeMismatch { index });
                }
                if nullifier.leaf != commitment.nullifier {
                    return Err(ClientError::NullifierProofLeafMismatch { index });
                }
                if nullifier.merkle_context.tree != tree {
                    return Err(ClientError::NullifierProofTreeMismatch { index });
                }
                Ok(SpendProof { state, nullifier })
            })
            .collect()
    }
}
