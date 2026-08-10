use zolana_interface::{
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, TransactIxData, TransactProof,
    },
    N_PUBLIC_SLOTS,
};
use zolana_transaction::instructions::{
    transact::{inputs_require_p256, SppProofInputs},
    types::SppProofInputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        transact::{assembly::TransferSpendInput, eddsa::TransferProver},
        ProofCompressed, ProverClient, TransferInputs,
    },
    rpc::{MerkleProof, NonInclusionProof},
};

/// State-inclusion and nullifier-non-inclusion proofs for one real input UTXO.
#[derive(Clone)]
pub struct SpendProof {
    pub state: MerkleProof,
    pub nullifier: NonInclusionProof,
}

/// Attach the fetched Merkle proofs to the proof inputs positionally: each real
/// input (non-zero owner) consumes the next spend proof, each dummy slot consumes
/// the next dummy non-inclusion proof (the transact circuit checks non-inclusion
/// for every slot). Shared by every witness builder (transact, merge,
/// merge-ring, ring-authority).
pub(crate) fn attach_input_proofs(
    inputs: Vec<SppProofInputUtxo>,
    proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<Vec<TransferSpendInput>, ClientError> {
    let mut spends = Vec::with_capacity(inputs.len());
    let mut real_index = 0;
    let mut dummy_index = 0;
    for spend in inputs {
        let (proof, nullifier_proof) = if spend.utxo.owner.is_zero() {
            let nullifier_proof = dummy_nullifier_proofs.get(dummy_index).cloned();
            dummy_index += 1;
            (None, nullifier_proof)
        } else {
            let proof = proofs
                .get(real_index)
                .ok_or(ClientError::MissingInputMerkleProof { index: real_index })?
                .clone();
            real_index += 1;
            (Some(proof), None)
        };
        spends.push(TransferSpendInput {
            utxo: spend.utxo,
            nullifier_key: spend.nullifier_key,
            data_hash: spend.data_hash,
            ring_data_hash: spend.ring_data_hash,
            proof,
            nullifier_proof,
        });
    }
    Ok(spends)
}

pub enum ProverVariant {
    Eddsa(TransferProver),
}

/// A built circuit ready to hand to the prover client.
pub struct BuiltCircuit {
    pub circuit: ProverVariant,
}

/// Witness for a supported transaction circuit, ready for the prover client.
pub enum ProverInputs {
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
    pub fn with_proof(mut self, proof: TransactProof) -> TransactIxData {
        self.ix.proof = proof;
        self.ix
    }
}

impl ProverClient {
    pub fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        input_proofs: &[SpendProof],
        dummy_nullifier_proofs: &[NonInclusionProof],
    ) -> Result<TransactIxData, ClientError> {
        self.prove_transact_with_dummy_policy(
            proof_inputs,
            input_proofs,
            dummy_nullifier_proofs,
            true,
        )
    }

    pub fn prove_transact_with_dummy_policy(
        &self,
        proof_inputs: SppProofInputs,
        input_proofs: &[SpendProof],
        dummy_nullifier_proofs: &[NonInclusionProof],
        allow_dummy_inputs: bool,
    ) -> Result<TransactIxData, ClientError> {
        let assembled = assemble_with_dummy_policy(
            proof_inputs,
            input_proofs,
            dummy_nullifier_proofs,
            allow_dummy_inputs,
        )?;
        let proof = match &assembled.prover_inputs {
            ProverInputs::Eddsa(inputs) => self.prove_transfer(inputs)?,
        };
        Ok(assembled.with_proof(ProofCompressed::try_from(proof)?.to_transact_proof()))
    }
}

pub fn into_prover(
    proof_inputs: SppProofInputs,
    input_merkle_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<BuiltCircuit, ClientError> {
    into_prover_with_dummy_policy(
        proof_inputs,
        input_merkle_proofs,
        dummy_nullifier_proofs,
        true,
    )
}

pub fn into_prover_with_dummy_policy(
    proof_inputs: SppProofInputs,
    input_merkle_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    allow_dummy_inputs: bool,
) -> Result<BuiltCircuit, ClientError> {
    if !allow_dummy_inputs
        && proof_inputs
            .input_utxos
            .iter()
            .any(|input| input.is_dummy())
    {
        return Err(ClientError::DummyInputsNotAllowed);
    }
    if inputs_require_p256(&proof_inputs.input_utxos)? {
        return Err(ClientError::P256TransactUnsupported);
    }
    let shape = proof_inputs.check_shape()?;
    let signer_pk_hashes = proof_inputs.signer_pk_hashes(shape.n_inputs() + 1)?;
    let public_transfers = proof_inputs.public_transfers()?;
    let SppProofInputs {
        input_utxos: inputs,
        output_utxos: outputs,
        external_data,
        ..
    } = proof_inputs;

    let spends = attach_input_proofs(inputs, input_merkle_proofs, dummy_nullifier_proofs)?;

    let circuit = ProverVariant::Eddsa(TransferProver {
        inputs: spends,
        outputs,
        external_data,
        public_transfers,
        signer_pk_hashes,
        allow_dummy_inputs,
        shape: Some(shape),
    });
    Ok(BuiltCircuit { circuit })
}

/// Assemble the prover witness and the `Transact` instruction data in a single
/// pass over the already-padded transaction. The witness and the instruction
/// commit to identical values by construction: the nullifiers and
/// `private_tx_hash` come from the one prover build, and `external_data`
/// (including every dummy output hash) was finalized at signing time. Each padded
/// dummy input mirrors the first real input's signer; root indices come from each
/// real `SpendProof`.
pub fn assemble(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<AssembledTransfer, ClientError> {
    assemble_with_dummy_policy(proof_inputs, input_proofs, dummy_nullifier_proofs, true)
}

pub fn assemble_with_dummy_policy(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    allow_dummy_inputs: bool,
) -> Result<AssembledTransfer, ClientError> {
    let shape = proof_inputs.check_shape()?;
    if inputs_require_p256(&proof_inputs.input_utxos)? {
        return Err(ClientError::P256TransactUnsupported);
    }

    let zolana_transaction::ExternalData {
        expiry_unix_ts,
        interface_transfers,
        data_hash,
        ring_data_hash,
        tx_viewing_pk,
        salt,
        outputs,
        messages,
        ..
    } = proof_inputs.external_data.clone();
    let interface_transfers = interface_transfers
        .iter()
        .copied()
        .map(zolana_transaction::instructions::transact::SettlementTransfer::interface_transfer)
        .collect();

    let circuit_id = CircuitId::ConfidentialEddsa(
        shape.n_inputs() as u8,
        shape.n_outputs() as u8,
        N_PUBLIC_SLOTS as u8,
    );

    let BuiltCircuit { circuit } = into_prover_with_dummy_policy(
        proof_inputs,
        input_proofs,
        dummy_nullifier_proofs,
        allow_dummy_inputs,
    )?;

    let ProverVariant::Eddsa(prover) = circuit;
    let result = prover.build()?;
    let prover_inputs = ProverInputs::Eddsa(result.inputs);
    let public_input_hash = result.public_input_hash;
    let nullifiers = result.nullifiers;
    let private_tx = result.private_tx_hash;
    let root_indices = result.input_root_indices;

    if nullifiers.len() != shape.n_inputs() || root_indices.len() != shape.n_inputs() {
        return Err(ClientError::ProofInputCountMismatch {
            got: nullifiers.len(),
            expected: shape.n_inputs(),
        });
    }

    let mut inputs = Vec::with_capacity(shape.n_inputs());
    for i in 0..shape.n_inputs() {
        let nullifier_hash = *nullifiers
            .get(i)
            .ok_or(ClientError::ProofInputCountMismatch {
                got: nullifiers.len(),
                expected: shape.n_inputs(),
            })?;
        let &(utxo_tree_root_index, nullifier_tree_root_index) =
            root_indices
                .get(i)
                .ok_or(ClientError::ProofInputCountMismatch {
                    got: root_indices.len(),
                    expected: shape.n_inputs(),
                })?;
        inputs.push(InputUtxo {
            nullifier_hash,
            nullifier_tree_root_index,
            utxo_tree_root_index,
        });
    }

    let ix = TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts,
        private_tx_hash: private_tx,
        circuit: circuit_id,
        inputs,
        interface_transfers,
        data_hash,
        ring_data_hash,
        tx_viewing_pk,
        salt,
        outputs,
        messages,
    };

    Ok(AssembledTransfer {
        prover_inputs,
        public_input_hash,
        ix,
    })
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{
        instructions::{
            transact::{spp_proof_inputs::asset_field, SettlementTransfer, SppProofInputs},
            types::SppProofInputUtxo,
        },
        Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT,
    };

    use super::{attach_input_proofs, into_prover, ProverVariant};
    use crate::error::ClientError;
    use crate::rpc::{MerkleContext, NonInclusionProof, NULLIFIER_TREE_HEIGHT};

    #[test]
    fn attaches_dummy_nullifier_proofs_in_slot_order() {
        let inputs = vec![
            SppProofInputUtxo::new_dummy(),
            SppProofInputUtxo::new_dummy(),
        ];
        let proofs = [dummy_nullifier_proof(1), dummy_nullifier_proof(2)];

        let spends = attach_input_proofs(inputs, &[], &proofs).expect("attach dummy proofs");

        assert_eq!(spends[0].nullifier_proof.as_ref(), Some(&proofs[0]));
        assert_eq!(spends[1].nullifier_proof.as_ref(), Some(&proofs[1]));
    }

    #[test]
    fn default_transact_rejects_p256_owned_inputs() {
        let keypair = ShieldedKeypair::new().expect("P256 keypair");
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: keypair.signing_pubkey(),
                asset: SOL_MINT,
                amount: 1,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &keypair,
        );
        let proof_inputs = SppProofInputs::new(
            vec![input],
            vec![SppProofOutputUtxo::default()],
            ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new()),
            Address::default(),
        );

        assert!(matches!(
            into_prover(proof_inputs, &[], &[]),
            Err(ClientError::P256TransactUnsupported)
        ));
    }

    #[test]
    fn spl_only_transfer_occupies_public_slot_zero() {
        let mint = Address::new_from_array([41u8; 32]);
        let external_data =
            ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new())
                .with_interface_transfer(SettlementTransfer::Spl {
                    mint,
                    is_deposit: false,
                    amount: 9,
                    user_spl_token: Address::new_from_array([42u8; 32]),
                    spl_token_interface: Address::new_from_array([43u8; 32]),
                })
                .expect("valid SPL settlement");
        let proof_inputs = SppProofInputs::new(
            vec![SppProofInputUtxo::new_dummy()],
            vec![SppProofOutputUtxo::default()],
            external_data,
            Address::default(),
        );

        let built = into_prover(proof_inputs, &[], &[]).expect("assemble prover");
        let ProverVariant::Eddsa(prover) = built.circuit;
        assert_eq!(
            prover.public_transfers.assets.first().copied(),
            Some(asset_field(&mint).expect("asset field"))
        );
        assert!(prover
            .public_transfers
            .assets
            .iter()
            .skip(1)
            .all(|asset| *asset == [0u8; 32]));
    }

    fn dummy_nullifier_proof(marker: u8) -> NonInclusionProof {
        NonInclusionProof {
            leaf: [marker; 32],
            merkle_context: MerkleContext {
                tree_type: 1,
                tree: Address::new_from_array([marker; 32]),
            },
            path: vec![[marker; 32]; NULLIFIER_TREE_HEIGHT],
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [u8::MAX; 32],
            high_element_index: 1,
            root: [marker; 32],
            root_seq: u64::from(marker),
            root_index: u16::from(marker),
        }
    }
}
