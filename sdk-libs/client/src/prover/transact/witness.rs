use zolana_interface::instruction::instruction_data::transact::{
    CircuitId, CircuitVariant, InputUtxo, TransactIxData, TransactProof,
};
use zolana_keypair::SignatureType;
use zolana_transaction::instructions::{
    transact::{inputs_proof_variant, SppProofInputs},
    types::SppProofInputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        transact::{
            eddsa::TransferProver,
            p256_and_eddsa::{P256Owner, TransferP256Prover, TransferSpendInput},
        },
        ProofCompressed, ProverClient, TransferInputs, TransferP256Inputs,
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
/// for every slot). Callers whose circuit skips dummy non-inclusion (merge,
/// merge-zone) pass no dummy proofs; those dummies mirror the first real input's
/// witness during assembly. Shared by every witness builder (transact, merge,
/// merge-zone, zone-authority).
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
            zone_data_hash: spend.zone_data_hash,
            proof,
            nullifier_proof,
        });
    }
    Ok(spends)
}

pub enum ProverVariant {
    P256(TransferP256Prover),
    Eddsa(TransferProver),
}

/// A built circuit ready to hand to the prover client.
pub struct BuiltCircuit {
    pub circuit: ProverVariant,
}

/// Sentinel `eddsa_signer_index` marking a P256-owned input: it routes the
/// input to the transaction's shared P256 signing key and skips the eddsa
/// signer check. Valid only when the declared circuit selector is a P256
/// variant. Mirrors `P256_OWNED_SIGNER` in the shielded-pool program.
const P256_OWNED_SIGNER: u8 = 255;

/// Default output-tree slot every input is placed at (`tree_index` 0).
const DEFAULT_TREE_INDEX: u8 = 0;

/// Default eddsa signer account index for a Solana-owned input.
const DEFAULT_EDDSA_SIGNER_INDEX: u8 = 0;

/// Witness for one of the two proving rails, ready to hand to the prover client.
/// The `P256` variant is a placeholder for the removed rail: proving with it
/// fails with `ClientError::P256IsUnimplemented`.
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
            ProverInputs::P256(inputs) => self.prove_transfer_p256(inputs)?,
            ProverInputs::Eddsa(inputs) => self.prove_transfer(inputs)?,
        };
        Ok(assembled.with_proof(ProofCompressed::try_from(proof)?.to_transact_proof()))
    }
}

/// Recover the [`P256Owner`] witness from the stored 64-byte signature and the
/// first P256-owned input's signing pubkey. The transaction crate keeps only the
/// raw `r || s` bytes; the pubkey comes from the owner of a real P256 input.
fn p256_owner(proof_inputs: &SppProofInputs) -> Result<P256Owner, ClientError> {
    let signature = proof_inputs
        .p256_signature
        .ok_or(ClientError::MissingP256Signature)?;
    let pubkey = proof_inputs
        .input_utxos
        .iter()
        .filter(|spend| !spend.is_dummy())
        .map(|spend| spend.utxo.owner)
        .find(|owner| matches!(owner.signature_type(), Ok(SignatureType::P256)))
        .ok_or(ClientError::MissingP256Signature)?
        .as_p256()?;
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&signature[..32]);
    sig_s.copy_from_slice(&signature[32..]);
    Ok(P256Owner {
        pubkey,
        sig_r,
        sig_s,
    })
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
    // Derived here, once: the variant drives the prover witness below and the
    // `circuit` selector stamped by `assemble`, so they agree by construction.
    let variant = inputs_proof_variant(&proof_inputs.input_utxos)?;
    let p256_owner = if variant == CircuitVariant::P256 {
        Some(p256_owner(&proof_inputs)?)
    } else {
        None
    };
    let shape = proof_inputs.check_shape()?;
    let public_movements = proof_inputs.public_movements()?;
    let SppProofInputs {
        input_utxos: inputs,
        output_utxos: outputs,
        external_data,
        payer_pubkey_hash,
        ..
    } = proof_inputs;

    let spends = attach_input_proofs(inputs, input_merkle_proofs, dummy_nullifier_proofs)?;

    let circuit = if variant == CircuitVariant::P256 {
        let p256_owner = p256_owner.ok_or(ClientError::MissingP256Signature)?;
        ProverVariant::P256(TransferP256Prover {
            inputs: spends,
            outputs,
            external_data,
            public_movements,
            payer_pubkey_hash,
            allow_dummy_inputs,
            p256_owner,
            shape: Some(shape),
        })
    } else {
        ProverVariant::Eddsa(TransferProver {
            inputs: spends,
            outputs,
            external_data,
            public_movements,
            payer_pubkey_hash,
            allow_dummy_inputs,
            shape: Some(shape),
        })
    };
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

    // Signer indices for the real inputs only; dummies (zero owner) inherit the
    // first real input's signer below. A zero owner reads as P256, so it must
    // never reach `signature_type`.
    let mut real_signer_indices: Vec<u8> = Vec::new();
    for spend in proof_inputs
        .input_utxos
        .iter()
        .filter(|spend| !spend.is_dummy())
    {
        let signer = if spend.utxo.owner.signature_type()? == SignatureType::P256 {
            P256_OWNED_SIGNER
        } else {
            DEFAULT_EDDSA_SIGNER_INDEX
        };
        real_signer_indices.push(signer);
    }

    let zolana_transaction::ExternalData {
        expiry_unix_ts,
        public_legs,
        data_hash,
        zone_data_hash,
        tx_viewing_pk,
        salt,
        outputs,
        messages,
        ..
    } = proof_inputs.external_data.clone();
    let public_legs = public_legs
        .iter()
        .copied()
        .map(zolana_transaction::instructions::transact::SettlementLeg::public_leg)
        .collect();

    // The circuit selector derives from the same variant decision as the prover
    // witness: the spending key material, never a user choice. `assemble` only
    // builds default-zone `transact` data, so the type is always confidential.
    let circuit_id = CircuitId::confidential(inputs_proof_variant(&proof_inputs.input_utxos)?);

    let BuiltCircuit { circuit } = into_prover_with_dummy_policy(
        proof_inputs,
        input_proofs,
        dummy_nullifier_proofs,
        allow_dummy_inputs,
    )?;

    let (prover_inputs, public_input_hash, nullifiers, private_tx, root_indices, p256_signing_pk_x) =
        match circuit {
            ProverVariant::P256(prover) => {
                let result = prover.build()?;
                (
                    ProverInputs::P256(result.inputs),
                    result.public_input_hash,
                    result.nullifiers,
                    result.private_tx_hash,
                    result.input_root_indices,
                    Some(result.p256_signing_pk_x),
                )
            }
            ProverVariant::Eddsa(prover) => {
                let result = prover.build()?;
                (
                    ProverInputs::Eddsa(result.inputs),
                    result.public_input_hash,
                    result.nullifiers,
                    result.private_tx_hash,
                    result.input_root_indices,
                    None,
                )
            }
        };

    if nullifiers.len() != shape.n_inputs() || root_indices.len() != shape.n_inputs() {
        return Err(ClientError::WitnessInputCountMismatch {
            got: nullifiers.len(),
            expected: shape.n_inputs(),
        });
    }

    let dummy_signer = real_signer_indices
        .first()
        .copied()
        .unwrap_or(DEFAULT_EDDSA_SIGNER_INDEX);
    let mut inputs = Vec::with_capacity(shape.n_inputs());
    for i in 0..shape.n_inputs() {
        let nullifier_hash = *nullifiers
            .get(i)
            .ok_or(ClientError::WitnessInputCountMismatch {
                got: nullifiers.len(),
                expected: shape.n_inputs(),
            })?;
        let &(utxo_tree_root_index, nullifier_tree_root_index) =
            root_indices
                .get(i)
                .ok_or(ClientError::WitnessInputCountMismatch {
                    got: root_indices.len(),
                    expected: shape.n_inputs(),
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
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts,
        private_tx_hash: private_tx,
        circuit: circuit_id,
        p256_signing_pk_x,
        inputs,
        public_legs,
        data_hash,
        zone_data_hash,
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
    use zolana_transaction::{
        instructions::{
            transact::{spp_proof_inputs::asset_field, SettlementLeg, SppProofInputs},
            types::SppProofInputUtxo,
        },
        ExternalData, SppProofOutputUtxo,
    };

    use super::{attach_input_proofs, into_prover, ProverVariant};
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
    fn spl_only_movement_occupies_public_slot_zero() {
        let mint = Address::new_from_array([41u8; 32]);
        let external_data =
            ExternalData::new([0u8; 33], [0u8; 16], Vec::new(), Vec::new(), Vec::new())
                .with_public_leg(SettlementLeg::Spl {
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
        let ProverVariant::Eddsa(prover) = built.circuit else {
            panic!("dummy-only proof inputs use the eddsa rail");
        };
        assert_eq!(
            prover.public_movements.assets.first().copied(),
            Some(asset_field(&mint).expect("asset field"))
        );
        assert!(prover
            .public_movements
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
