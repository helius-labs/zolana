use zolana_interface::{
    instruction::instruction_data::transact::{CircuitId, TransactIxData, TransactProof},
    N_PUBLIC_SLOTS,
};
use zolana_transaction::instructions::{
    transact::{inputs_require_p256, SppProofInputs},
    types::SppProofInputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        transact::{
            assembly::{input_utxos, TransferSpendInput},
            eddsa::TransferProver,
        },
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
            tree_id: spend.tree_id,
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
    pub cached_inputs: Option<[[u8; 32]; 3]>,
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
            ProverInputs::Eddsa(inputs) => {
                let proof = self.prove_transfer(inputs)?;
                crate::verify_confidential_transfer_inputs(
                    inputs,
                    assembled.public_input_hash,
                    &proof,
                )?;
                proof
            }
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
    // `allow_dummy_inputs == 0` forces every slot to be a real spend: the
    // circuit rejects dummy and address slots alike, so reject them here with
    // the offending slot named rather than as an opaque proving failure.
    if !allow_dummy_inputs {
        if let Some(index) = proof_inputs
            .input_utxos
            .iter()
            .position(|input| input.is_dummy())
        {
            return Err(ClientError::NonSpendInputNotAllowed { index });
        }
    }
    if inputs_require_p256(&proof_inputs.input_utxos)? {
        return Err(ClientError::P256TransactUnsupported);
    }
    let shape = proof_inputs.check_shape()?;
    let signer_pk_hashes = proof_inputs.signer_pk_hashes(shape.signer_width())?;
    let public_transfers = proof_inputs.public_transfers()?;
    let SppProofInputs {
        input_utxos: inputs,
        output_utxos: outputs,
        blinding_seed,
        output_tree_id,
        external_data,
        ..
    } = proof_inputs;

    let spends = attach_input_proofs(inputs, input_merkle_proofs, dummy_nullifier_proofs)?;

    let circuit = ProverVariant::Eddsa(TransferProver {
        inputs: spends,
        outputs,
        blinding_seed,
        output_tree_id,
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

pub fn assemble_cached(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
) -> Result<AssembledTransfer, ClientError> {
    assemble_cached_with_dummy_proofs(proof_inputs, input_proofs, &[])
}

pub fn assemble_cached_with_dummy_proofs(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<AssembledTransfer, ClientError> {
    let expected = proof_inputs
        .input_utxos
        .iter()
        .filter(|input| input.is_dummy())
        .count();
    if dummy_nullifier_proofs.len() != expected {
        return Err(ClientError::WitnessInputCountMismatch {
            got: dummy_nullifier_proofs.len(),
            expected,
        });
    }
    assemble_inner(
        proof_inputs,
        input_proofs,
        dummy_nullifier_proofs,
        true,
        true,
    )
}

pub fn assemble_with_dummy_policy(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    allow_dummy_inputs: bool,
) -> Result<AssembledTransfer, ClientError> {
    assemble_inner(
        proof_inputs,
        input_proofs,
        dummy_nullifier_proofs,
        allow_dummy_inputs,
        false,
    )
}

fn assemble_inner(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    allow_dummy_inputs: bool,
    cached: bool,
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

    let mut circuit_id = CircuitId::ConfidentialEddsa(
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
    let result = if cached {
        prover.build_cached()?
    } else {
        prover.build()?
    };
    if cached {
        circuit_id = CircuitId::ConfidentialEddsaCached(
            shape.n_inputs() as u8,
            shape.n_outputs() as u8,
            N_PUBLIC_SLOTS as u8,
            zolana_interface::verifying_keys::CachedInputs {
                input_bitmap: u64::from_be_bytes(
                    result.cached_inputs.as_ref().unwrap()[0][24..]
                        .try_into()
                        .unwrap(),
                ),
            },
        );
    }
    let prover_inputs = ProverInputs::Eddsa(result.inputs);
    let public_input_hash = result.public_input_hash;
    let nullifiers = result.nullifiers;
    let private_tx = result.private_tx_hash;

    if nullifiers.len() != shape.n_inputs() {
        return Err(ClientError::WitnessInputCountMismatch {
            got: nullifiers.len(),
            expected: shape.n_inputs(),
        });
    }

    let inputs = input_utxos(&nullifiers, &result.input_tree_indexes)?;

    let ix = TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts,
        private_tx_hash: private_tx,
        circuit: circuit_id,
        inputs,
        tree_contexts: result.tree_contexts,
        interface_transfers,
        data_hash,
        ring_data_hash,
        tx_viewing_pk,
        salt,
        outputs,
        messages,
    };

    Ok(AssembledTransfer {
        cached_inputs: result.cached_inputs,
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
            transact::{
                spp_proof_inputs::asset_field, ConfidentialTransfer, SettlementTransfer, Shape,
                SppProofInputs,
            },
            types::SppProofInputUtxo,
        },
        AssetRegistry, Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT,
    };

    use super::{assemble, attach_input_proofs, into_prover, ProverVariant, SpendProof};
    use crate::error::ClientError;
    use crate::rpc::{
        MerkleContext, MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
    };

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
        let keypair = ShieldedKeypair::new_p256().expect("P256 keypair");
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

    /// The nullifiers `dummy_nullifiers()` requests non-inclusion witnesses for
    /// must be the ones the assembled witness carries. Both hash the dummy under
    /// the input tree's id; a tree other than 0 exposes any drift between them.
    #[test]
    fn assembled_dummy_nullifiers_match_the_requested_ones() {
        let sender = ShieldedKeypair::new_ed25519().expect("sender keypair");
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient keypair");
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &sender,
        )
        .in_tree(3);
        let payer = Address::new_from_array(
            sender
                .signing_pubkey()
                .as_ed25519()
                .expect("sender Ed25519 pubkey"),
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            vec![input],
            payer,
        )
        .with_shape(Shape::IN2_OUT3);
        transfer
            .send(
                &recipient.shielded_address().expect("recipient address"),
                SOL_MINT,
                4,
            )
            .expect("send");
        let proof_inputs = transfer
            .sign(&sender, &AssetRegistry::default())
            .expect("sign");

        let requested = proof_inputs.dummy_nullifiers().expect("dummy nullifiers");
        let assembled = assemble(proof_inputs, &[fake_spend_proof()], &[]).expect("assemble");

        let witnessed: Vec<[u8; 32]> = assembled
            .ix
            .inputs
            .iter()
            .skip(1)
            .map(|input| input.nullifier_hash)
            .collect();
        assert_eq!(requested.len(), 1);
        assert_eq!(witnessed, requested);
    }

    fn cached_fixture(
        real: usize,
        shape: Shape,
    ) -> (SppProofInputs, Vec<SpendProof>, Vec<NonInclusionProof>) {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let recipient = ShieldedKeypair::new_ed25519().unwrap();
        let inputs = (0..real)
            .map(|i| {
                SppProofInputUtxo::new(
                    Utxo {
                        owner: sender.signing_pubkey(),
                        asset: SOL_MINT,
                        amount: 10,
                        blinding: [i as u8 + 1; 32],
                        ring_program_id: None,
                        data: Data::default(),
                    },
                    &sender,
                )
                .in_tree(3)
            })
            .collect();
        let payer = Address::new_from_array(sender.signing_pubkey().as_ed25519().unwrap());
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address().unwrap(), inputs, payer)
                .with_compact_change()
                .with_shape(shape);
        transfer
            .send(
                &recipient.shielded_address().unwrap(),
                SOL_MINT,
                real as u64 * 10,
            )
            .unwrap();
        let prepared = transfer.sign(&sender, &AssetRegistry::default()).unwrap();
        let mut proof = fake_spend_proof();
        proof.state.root = [7; 32];
        proof.state.root_index = 9;
        let dummies = prepared
            .dummy_nullifiers()
            .unwrap()
            .into_iter()
            .map(|nullifier| {
                let mut nip = proof.nullifier.clone();
                nip.leaf = nullifier;
                nip
            })
            .collect();
        (prepared, vec![proof; real], dummies)
    }

    #[test]
    fn cached_padding_preserves_real_bitmap_zero_slots_and_root() {
        let (prepared, proofs, dummies) = cached_fixture(15, Shape::IN36_OUT2);
        let mut commitments = prepared
            .input_utxo_hashes()
            .unwrap()
            .into_iter()
            .map(|input| input.utxo_hash)
            .collect::<Vec<_>>();
        commitments.resize(36, [0; 32]);
        let expected_chain =
            zolana_hasher::hash_chain::create_hash_chain_4_from_slice(&commitments).unwrap();
        let assembled =
            super::assemble_cached_with_dummy_proofs(prepared, &proofs, &dummies).unwrap();
        assert_eq!(
            assembled.ix.circuit.cached_inputs().unwrap().input_bitmap,
            (1 << 15) - 1
        );
        let fields = assembled.cached_inputs.unwrap();
        assert_eq!(
            u64::from_be_bytes(fields[0][24..].try_into().unwrap()),
            (1 << 15) - 1
        );
        assert_eq!(fields[2], expected_chain);
        assert_eq!(assembled.ix.tree_contexts[0].utxo_tree_root_index, 9);
        let super::ProverInputs::Eddsa(witness) = assembled.prover_inputs;
        assert_eq!(
            witness.tree_slots[0].utxo_root,
            num_bigint::BigUint::from_bytes_be(&[7; 32])
        );
        for (input, nip) in witness.inputs[15..].iter().zip(&dummies) {
            assert_eq!(
                input.nullifier,
                num_bigint::BigUint::from_bytes_be(&nip.leaf)
            );
        }
    }

    #[test]
    fn cached_all_real_inputs_keep_canonical_zero_state_root() {
        let (prepared, proofs, dummies) = cached_fixture(1, Shape::IN1_OUT2);
        let assembled =
            super::assemble_cached_with_dummy_proofs(prepared, &proofs, &dummies).unwrap();
        assert_eq!(
            assembled.ix.circuit.cached_inputs().unwrap().input_bitmap,
            1
        );
        assert_eq!(assembled.ix.tree_contexts[0].utxo_tree_root_index, 0);
        let super::ProverInputs::Eddsa(witness) = assembled.prover_inputs;
        assert_eq!(witness.tree_slots[0].utxo_root, num_bigint::BigUint::ZERO);
    }

    #[test]
    fn cached_padding_rejects_missing_mismatched_and_noncanonical_witnesses() {
        let (prepared, proofs, dummies) = cached_fixture(15, Shape::IN36_OUT2);
        assert!(super::assemble_cached(prepared.clone(), &proofs).is_err());
        let mut mismatched = dummies.clone();
        mismatched[0].root = [1; 32];
        assert!(
            super::assemble_cached_with_dummy_proofs(prepared.clone(), &proofs, &mismatched)
                .is_err()
        );
        let mut noncanonical = prepared;
        noncanonical.input_utxos[15].utxo.amount = 1;
        assert!(super::assemble_cached_with_dummy_proofs(noncanonical, &proofs, &dummies).is_err());
    }

    fn fake_spend_proof() -> SpendProof {
        let context = MerkleContext {
            tree_type: 0,
            tree: Address::default(),
        };
        SpendProof {
            state: MerkleProof {
                leaf: [0u8; 32],
                merkle_context: context.clone(),
                path: vec![[0u8; 32]; STATE_TREE_HEIGHT],
                leaf_index: 0,
                root: [0u8; 32],
                root_seq: 0,
                root_index: 0,
            },
            nullifier: NonInclusionProof {
                leaf: [0u8; 32],
                merkle_context: context,
                path: vec![[0u8; 32]; NULLIFIER_TREE_HEIGHT],
                low_element: [0u8; 32],
                low_element_index: 0,
                high_element: [0u8; 32],
                high_element_index: 0,
                root: [0u8; 32],
                root_seq: 0,
                root_index: 0,
            },
        }
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
