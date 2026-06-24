use zolana_interface::instruction::instruction_data::transact::{InputUtxo, TransactIxData};
use zolana_keypair::hash::sha256;
use zolana_keypair::SignatureType;
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
use crate::prover::{TransferInputs, TransferP256Inputs};

#[derive(Clone)]
pub struct SignedTransaction {
    /// Inputs padded to `shape.n_inputs`; dummies have a zero owner
    /// ([`SpendUtxo::is_dummy`]) and sit at the tail.
    pub(crate) inputs: Vec<SpendUtxo>,
    /// Outputs padded to `shape.n_outputs`; dummies have `owner_hash == 0`
    /// ([`OutputUtxo::is_dummy`]): both empty change and tail padding.
    pub(crate) outputs: Vec<OutputUtxo>,
    pub(crate) public_amounts: PublicAmounts,
    pub(crate) external_data: ExternalData,
    pub(crate) payer_pubkey_hash: [u8; 32],
    pub(crate) shape: Shape,
    pub(crate) p256_owner: Option<P256Owner>,
}

/// Sentinel `eddsa_signer_index` marking a P256-owned input; the program uses it
/// to select the P256 verifying key and skip the eddsa signer check. Mirrors
/// `P256_OWNED_SIGNER` in the shielded-pool program.
const P256_OWNED_SIGNER: u8 = 255;

/// Default output-tree slot every input is placed at (`tree_index` 0).
const DEFAULT_TREE_INDEX: u8 = 0;

/// Default eddsa signer account index for a Solana-owned input.
const DEFAULT_EDDSA_SIGNER_INDEX: u8 = 0;

/// Witness for one of the two proving rails, ready to hand to the prover client.
pub enum ProverInputs {
    P256(TransferP256Inputs),
    Eddsa(TransferInputs),
}

/// A transaction assembled exactly once: the prover witness, the public input it
/// commits to, and the `Transact` instruction data minus the proof bytes. The
/// per-input nullifiers, hash chains, dummy padding, and `private_tx_hash` are
/// computed a single time and shared by the witness and the instruction, so they
/// are identical by construction. Call [`AssembledTransfer::with_proof`] once the
/// proof is produced from [`AssembledTransfer::prover_inputs`].
pub struct AssembledTransfer {
    pub prover_inputs: ProverInputs,
    pub public_input_hash: [u8; 32],
    ix: TransactIxData,
}

impl AssembledTransfer {
    pub fn with_proof(mut self, proof: [u8; 192]) -> TransactIxData {
        self.ix.proof = proof;
        self.ix
    }
}

impl SignedTransaction {
    /// Commitments for the real inputs only. Dummy padding has a zero owner that has
    /// no `owner_hash`, so it has no meaningful commitment to look up.
    pub fn input_commitments(&self) -> Result<Vec<InputCommitment>, ClientError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                let nullifier_pubkey = spend.nullifier_key.pubkey()?;
                let utxo_hash = spend.utxo.hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])?;
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
        let mut real_index = 0;
        for spend in inputs {
            let SpendUtxo {
                utxo,
                nullifier_key,
                program_data_hash,
                zone_data_hash,
            } = spend;
            // Real inputs have their own proof; a dummy (zero owner) is proofless and
            // mirrors the first real input's roots downstream.
            let proof = if utxo.owner.is_zero() {
                None
            } else {
                let proof = input_merkle_proofs
                    .get(real_index)
                    .ok_or(ClientError::MissingInputMerkleProof { index: real_index })?
                    .clone();
                real_index += 1;
                Some(proof)
            };
            spends.push(TransferSpendInput {
                utxo,
                nullifier_key,
                program_data_hash,
                zone_data_hash,
                proof,
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

    /// Assemble the prover witness and the `Transact` instruction data in a single
    /// pass over the already-padded transaction. The witness and the instruction
    /// commit to identical values by construction: the nullifiers and
    /// `private_tx_hash` come from the one prover build, and `external_data`
    /// (including every dummy output hash) was finalized at signing time. Each padded
    /// dummy input mirrors the first real input's signer; root indices come from each
    /// real `SpendProof`.
    pub fn assemble(self, input_proofs: &[SpendProof]) -> Result<AssembledTransfer, ClientError> {
        let shape = self.shape;

        // Signer indices for the real inputs only; dummies (zero owner) inherit the
        // first real input's signer below. A zero owner reads as P256, so it must
        // never reach `signature_type`.
        let mut real_signer_indices = Vec::new();
        for spend in self.inputs.iter().filter(|spend| !spend.is_dummy()) {
            let signer = if spend.utxo.owner.signature_type()? == SignatureType::P256 {
                P256_OWNED_SIGNER
            } else {
                DEFAULT_EDDSA_SIGNER_INDEX
            };
            real_signer_indices.push(signer);
        }

        let ExternalData {
            expiry_unix_ts,
            relayer_fee,
            public_sol_amount,
            public_spl_amount,
            cpi_signer,
            tx_viewing_pk,
            salt,
            output_utxo_hashes,
            output_ciphertexts,
            ..
        } = self.external_data.clone();

        let (prover_inputs, public_input_hash, nullifiers, private_tx, root_indices) =
            match self.into_prover(input_proofs)? {
                CircuitType::P256(prover) => {
                    let result = prover.build()?;
                    (
                        ProverInputs::P256(result.inputs),
                        result.public_input_hash,
                        result.nullifiers,
                        result.private_tx_hash,
                        result.input_root_indices,
                    )
                }
                CircuitType::Eddsa(prover) => {
                    let result = prover.build()?;
                    (
                        ProverInputs::Eddsa(result.inputs),
                        result.public_input_hash,
                        result.nullifiers,
                        result.private_tx_hash,
                        result.input_root_indices,
                    )
                }
            };

        if nullifiers.len() != shape.n_inputs || root_indices.len() != shape.n_inputs {
            return Err(ClientError::WitnessInputCountMismatch {
                got: nullifiers.len(),
                expected: shape.n_inputs,
            });
        }

        let dummy_signer = real_signer_indices
            .first()
            .copied()
            .unwrap_or(DEFAULT_EDDSA_SIGNER_INDEX);
        let mut inputs = Vec::with_capacity(shape.n_inputs);
        for i in 0..shape.n_inputs {
            let nullifier_hash =
                *nullifiers
                    .get(i)
                    .ok_or(ClientError::WitnessInputCountMismatch {
                        got: nullifiers.len(),
                        expected: shape.n_inputs,
                    })?;
            let &(utxo_tree_root_index, nullifier_tree_root_index) =
                root_indices
                    .get(i)
                    .ok_or(ClientError::WitnessInputCountMismatch {
                        got: root_indices.len(),
                        expected: shape.n_inputs,
                    })?;
            let eddsa_signer_index = match real_signer_indices.get(i) {
                Some(&signer) => signer,
                None => dummy_signer,
            };
            inputs.push(InputUtxo {
                nullifier_hash,
                nullifier_tree_root_index,
                utxo_tree_root_index,
                tree_index: DEFAULT_TREE_INDEX,
                eddsa_signer_index,
            });
        }

        let ix = TransactIxData {
            proof: [0u8; 192],
            expiry_unix_ts,
            relayer_fee,
            private_tx_hash: private_tx,
            inputs,
            public_sol_amount,
            public_spl_amount,
            cpi_signer,
            tx_viewing_pk,
            salt,
            output_utxo_hashes,
            output_ciphertexts,
        };

        Ok(AssembledTransfer {
            prover_inputs,
            public_input_hash,
            ix,
        })
    }

    pub(crate) fn message_hash(&self) -> Result<[u8; 32], ClientError> {
        // Dummies contribute zero to match circuit private_tx hashing.
        let mut input_hashes = Vec::with_capacity(self.shape.n_inputs);
        for spend in &self.inputs {
            if spend.is_dummy() {
                input_hashes.push([0u8; 32]);
            } else {
                let nullifier_pubkey = spend.nullifier_key.pubkey()?;
                input_hashes.push(spend.utxo.hash(
                    &nullifier_pubkey,
                    &spend.program_data_hash.unwrap_or([0u8; 32]),
                    &spend.zone_data_hash.unwrap_or([0u8; 32]),
                )?);
            }
        }

        let mut output_hashes = Vec::with_capacity(self.shape.n_outputs);
        for output in &self.outputs {
            if output.is_dummy() {
                output_hashes.push([0u8; 32]);
            } else {
                output_hashes.push(output.hash()?);
            }
        }

        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(&input_hashes, &output_hashes, &external_data_hash)?;
        Ok(sha256(&private_tx))
    }
}
