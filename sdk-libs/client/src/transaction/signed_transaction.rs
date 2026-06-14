use zolana_keypair::hash::sha256_be;
use zolana_transaction::ExternalData;

use crate::error::ClientError;
use crate::prover::shape::Shape;
use crate::prover::transfer::TransferProver;
use crate::prover::transfer_p256::{
    input_utxo_hash, output_utxo_hash, private_tx_hash, P256Owner, PublicAmounts,
    TransferNewOutput, TransferP256Prover, TransferSpendInput,
};
use crate::transaction::transaction::{
    inputs_require_p256, InputCommitment, ProofResolver, SpendUtxo, TransferRail,
};

pub struct SignedTransaction {
    pub(crate) inputs: Vec<SpendUtxo>,
    pub(crate) outputs: Vec<TransferNewOutput>,
    pub(crate) public_amounts: PublicAmounts,
    pub(crate) external_data: ExternalData,
    pub(crate) payer_pubkey_hash: [u8; 32],
    pub(crate) shape: Shape,
    pub(crate) p256_owner: Option<P256Owner>,
}

impl SignedTransaction {
    pub fn input_commitments(&self) -> Result<Vec<InputCommitment>, ClientError> {
        self.inputs
            .iter()
            .enumerate()
            .map(|(index, spend)| {
                let utxo_hash = input_utxo_hash(&spend.utxo, &spend.nullifier_key)?;
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
        resolver: &mut impl ProofResolver,
    ) -> Result<TransferRail, ClientError> {
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
            } = spend;
            let utxo_hash = input_utxo_hash(&utxo, &nullifier_key)?;
            let nullifier = nullifier_key.nullifier(&utxo_hash, &utxo.blinding)?;
            let commitment = InputCommitment {
                index,
                utxo_hash,
                nullifier,
            };
            let proof = resolver.resolve(&commitment)?;
            spends.push(TransferSpendInput {
                utxo,
                nullifier_key,
                state_proof: proof.state,
                nullifier_proof: proof.nullifier,
            });
        }

        if requires_p256 {
            let p256_owner = p256_owner.ok_or(ClientError::MissingP256Signature)?;
            Ok(TransferRail::P256(TransferP256Prover {
                inputs: spends,
                outputs,
                external_data,
                public_amounts,
                payer_pubkey_hash,
                p256_owner,
                shape: Some(shape),
            }))
        } else {
            Ok(TransferRail::Eddsa(TransferProver {
                inputs: spends,
                outputs,
                external_data,
                public_amounts,
                payer_pubkey_hash,
                shape: Some(shape),
            }))
        }
    }

    pub(crate) fn message_hash(&self) -> Result<[u8; 32], ClientError> {
        let mut input_hashes = Vec::with_capacity(self.shape.n_inputs);
        for spend in &self.inputs {
            input_hashes.push(input_utxo_hash(&spend.utxo, &spend.nullifier_key)?);
        }
        input_hashes.resize(self.shape.n_inputs, [0u8; 32]);

        let mut output_hashes = Vec::with_capacity(self.shape.n_outputs);
        for output in &self.outputs {
            output_hashes.push(output_utxo_hash(output)?);
        }
        output_hashes.resize(self.shape.n_outputs, [0u8; 32]);

        let external_data_hash = self.external_data.hash();
        let private_tx = private_tx_hash(&input_hashes, &output_hashes, &external_data_hash)?;
        Ok(sha256_be(&private_tx))
    }
}
