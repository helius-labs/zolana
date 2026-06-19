use zolana_interface::instruction::instruction_data::transact::{InputUtxo, TransactIxData};
use zolana_keypair::hash::sha256;
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::{ExternalData, OutputUtxo};

use crate::error::ClientError;
use crate::private_transaction::transaction::{
    inputs_require_p256, CircuitType, InputCommitment, SpendProof, SpendUtxo,
};
use crate::prover::shape::Shape;
use crate::prover::transfer::TransferProver;
use crate::prover::transfer_p256::{
    P256Owner, PublicAmounts, TransferP256Prover, TransferSpendInput,
};

pub struct SignedTransaction {
    pub(crate) inputs: Vec<SpendUtxo>,
    pub(crate) outputs: Vec<OutputUtxo>,
    pub(crate) public_amounts: PublicAmounts,
    pub(crate) external_data: ExternalData,
    pub(crate) payer_pubkey_hash: [u8; 32],
    pub(crate) shape: Shape,
    pub(crate) p256_owner: Option<P256Owner>,
}

/// Tree placement for one spent input, resolved against the indexer/on-chain tree
/// state: the root indices the proof was built against plus the eddsa signer slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputTreeIndices {
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
    pub tree_index: u8,
    pub eddsa_signer_index: u8,
}

impl SignedTransaction {
    pub fn input_commitments(&self) -> Result<Vec<InputCommitment>, ClientError> {
        self.inputs
            .iter()
            .enumerate()
            .map(|(index, spend)| {
                let utxo_hash =
                    spend
                        .utxo
                        .hash(&spend.nullifier_key.pubkey()?, &[0u8; 32], &[0u8; 32])?;
                let nullifier = spend
                    .nullifier_key
                    .nullifier(&utxo_hash, &spend.utxo.blinding)?;
                Ok(InputCommitment {
                    index,
                    utxo_hash,
                    nullifier,
                })
            })
            .collect()
    }

    pub fn into_prover(
        self,
        input_merkle_proofs: &[SpendProof],
    ) -> Result<CircuitType, ClientError> {
        let requires_p256 = inputs_require_p256(&self.inputs)?;
        let SignedTransaction {
            inputs,
            outputs,
            public_amounts,
            external_data,
            payer_pubkey_hash,
            shape,
            p256_owner,
        } = self;

        let mut spends = Vec::with_capacity(inputs.len());
        for (index, spend) in inputs.into_iter().enumerate() {
            let SpendUtxo {
                utxo,
                nullifier_key,
                ..
            } = spend;
            let proof = input_merkle_proofs
                .get(index)
                .ok_or(ClientError::MissingInputMerkleProof { index })?;
            spends.push(TransferSpendInput {
                utxo,
                nullifier_key,
                state_proof: proof.state.clone(),
                nullifier_proof: proof.nullifier.clone(),
            });
        }

        if requires_p256 {
            let p256_owner = p256_owner.ok_or(ClientError::MissingP256Signature)?;
            Ok(CircuitType::P256(TransferP256Prover {
                inputs: spends,
                outputs,
                external_data,
                public_amounts,
                payer_pubkey_hash,
                p256_owner,
                shape: Some(shape),
            }))
        } else {
            Ok(CircuitType::Eddsa(TransferProver {
                inputs: spends,
                outputs,
                external_data,
                public_amounts,
                payer_pubkey_hash,
                shape: Some(shape),
            }))
        }
    }

    /// Assemble the on-chain `Transact` instruction data from this signed
    /// transaction, the proof bytes, and the per-input tree placement. The output
    /// ciphertext slots and `external_data_hash` come from [`ExternalData`], so the
    /// instruction and the proof commit to the same values.
    pub fn into_transact_ix_data(
        self,
        proof: [u8; 192],
        input_tree_indices: &[InputTreeIndices],
    ) -> Result<TransactIxData, ClientError> {
        let commitments = self.input_commitments()?;
        if input_tree_indices.len() != commitments.len() {
            return Err(ClientError::InputTreeIndexCountMismatch {
                expected: commitments.len(),
                actual: input_tree_indices.len(),
            });
        }
        let inputs = commitments
            .iter()
            .zip(input_tree_indices)
            .map(|(commitment, placement)| InputUtxo {
                nullifier_hash: commitment.nullifier,
                nullifier_tree_root_index: placement.nullifier_tree_root_index,
                utxo_tree_root_index: placement.utxo_tree_root_index,
                tree_index: placement.tree_index,
                eddsa_signer_index: placement.eddsa_signer_index,
            })
            .collect();

        let external_data_hash = self.external_data.hash()?;
        let mut input_hashes: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
        input_hashes.resize(self.shape.n_inputs, [0u8; 32]);
        let output_hashes: Vec<[u8; 32]> = self
            .external_data
            .output_slots
            .iter()
            .map(|slot| slot.utxo_hash)
            .collect();
        let private_tx = private_tx_hash(&input_hashes, &output_hashes, &external_data_hash)?;

        let (sender_utxo_data, recipient_utxo_data) = self
            .external_data
            .output_slots
            .split_first()
            .ok_or(ClientError::MissingOutput)?;

        Ok(TransactIxData {
            proof,
            expiry_unix_ts: self.external_data.expiry_unix_ts,
            relayer_fee: self.external_data.relayer_fee,
            private_tx_hash: private_tx,
            inputs,
            public_sol_amount: self.external_data.public_sol_amount,
            public_spl_amount: self.external_data.public_spl_amount,
            cpi_signer: self.external_data.cpi_signer,
            tx_viewing_pk: self.external_data.tx_viewing_pk,
            salt: self.external_data.salt,
            sender_utxo_data: sender_utxo_data.clone(),
            recipient_utxo_data: recipient_utxo_data.to_vec(),
        })
    }

    pub(crate) fn message_hash(&self) -> Result<[u8; 32], ClientError> {
        let mut input_hashes = Vec::with_capacity(self.shape.n_inputs);
        for spend in &self.inputs {
            input_hashes.push(spend.utxo.hash(
                &spend.nullifier_key.pubkey()?,
                &[0u8; 32],
                &[0u8; 32],
            )?);
        }
        input_hashes.resize(self.shape.n_inputs, [0u8; 32]);

        let mut output_hashes = Vec::with_capacity(self.shape.n_outputs);
        for output in &self.outputs {
            output_hashes.push(output.hash()?);
        }
        output_hashes.resize(self.shape.n_outputs, [0u8; 32]);

        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(&input_hashes, &output_hashes, &external_data_hash)?;
        Ok(sha256(&private_tx))
    }
}
