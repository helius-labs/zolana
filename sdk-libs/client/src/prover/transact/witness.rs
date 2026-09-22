use zolana_interface::{
    instruction::instruction_data::transact::{CircuitId, TransactIxData, TransactProof},
    pda, N_PUBLIC_SLOTS,
};
use zolana_transaction::{
    instructions::transact::{inputs_require_p256, SppProofInputs},
    utxo::SppProofInputUtxo,
};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        transact::{
            assembly::{input_utxos_from_nullifiers, TransferInputUtxo},
            eddsa::TransferProver,
        },
        ProofCompressed, Prover, TransferInputs,
    },
    rpc::{MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
};

/// State-inclusion and nullifier-non-inclusion proofs for one real input UTXO.
#[derive(Clone)]
pub struct SpendProof {
    pub state: MerkleProof,
    pub nullifier: NonInclusionProof,
}

impl SpendProof {
    pub(crate) fn validate(
        &self,
        input: &SppProofInputUtxo,
        index: usize,
    ) -> Result<(), ClientError> {
        if self.state.leaf != input.utxo_hash {
            return Err(ClientError::StateProofLeafMismatch { index });
        }
        if self.state.merkle_context.tree != pda::tree(input.tree_id) {
            return Err(ClientError::StateProofTreeMismatch { index });
        }
        if self.state.leaf_index != input.leaf_index {
            return Err(ClientError::StateProofIndexMismatch { index });
        }
        if self.state.path.len() != STATE_TREE_HEIGHT {
            return Err(ClientError::ProofPathLength {
                got: self.state.path.len(),
                expected: STATE_TREE_HEIGHT,
            });
        }
        validate_nullifier_proof(&self.nullifier, input, index)
    }
}

pub(crate) fn validate_nullifier_proof(
    proof: &NonInclusionProof,
    input: &SppProofInputUtxo,
    index: usize,
) -> Result<(), ClientError> {
    if proof.leaf != input.nullifier {
        return Err(ClientError::NullifierProofLeafMismatch { index });
    }
    if proof.merkle_context.tree != pda::tree(input.tree_id) {
        return Err(ClientError::NullifierProofTreeMismatch { index });
    }
    if proof.path.len() != NULLIFIER_TREE_HEIGHT {
        return Err(ClientError::ProofPathLength {
            got: proof.path.len(),
            expected: NULLIFIER_TREE_HEIGHT,
        });
    }
    Ok(())
}

/// Attach the fetched Merkle proofs to the proof inputs positionally: each real
/// input (non-zero owner) consumes the next spend proof, each dummy slot consumes
/// the next dummy non-inclusion proof (the transact circuit checks non-inclusion
/// for every slot). Shared by every witness builder (transact, merge,
/// merge-ring, ring-authority).
///
/// No secret comes in here: a real input's nullifier secret is filled in by its
/// owner's [`ProofAuthority`](crate::authority::ProofAuthority), one call before
/// the witness goes to the prover.
pub fn attach_input_proofs(
    inputs: Vec<SppProofInputUtxo>,
    proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<Vec<TransferInputUtxo>, ClientError> {
    let real_count = inputs.iter().filter(|input| !input.is_dummy()).count();
    let dummy_count = inputs.len() - real_count;
    if proofs.len() != real_count || dummy_nullifier_proofs.len() != dummy_count {
        return Err(ClientError::InputProofCountMismatch {
            real: real_count,
            dummy: dummy_count,
            real_proofs: proofs.len(),
            dummy_proofs: dummy_nullifier_proofs.len(),
        });
    }
    let mut input_utxos = Vec::with_capacity(inputs.len());
    let mut real_index = 0;
    let mut dummy_index = 0;
    for input_utxo in inputs {
        let (proof, nullifier_proof) = if input_utxo.is_dummy() {
            let nullifier_proof = Some(
                dummy_nullifier_proofs
                    .get(dummy_index)
                    .ok_or(ClientError::MissingDummyNullifierProof { index: dummy_index })?
                    .clone(),
            );
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
        input_utxos.push(TransferInputUtxo {
            utxo: input_utxo,
            proof,
            nullifier_proof,
        });
    }
    Ok(input_utxos)
}

/// A transaction assembled exactly once: the prover witness, the public input it
/// commits to, and the `Transact` instruction data minus the proof bytes. The
/// per-input nullifiers, hash chains and `private_tx_hash` are
/// computed a single time and shared by the witness and the instruction, so they
/// are identical by construction. Call [`AssembledTransfer::with_proof`] once the
/// proof is produced from [`AssembledTransfer::prover_inputs`].
pub struct AssembledTransfer {
    pub prover_inputs: TransferInputs,
    pub public_input_hash: [u8; 32],
    /// The raw ids of the trees the inputs are nullified in, in the order
    /// `ix.tree_contexts` declares them. The `Transact` builder takes one tree
    /// account per context entry in that order, and `pda::tree` of these is the
    /// only place that list can come from.
    pub input_tree_ids: Vec<u16>,
    ix: TransactIxData,
}

impl AssembledTransfer {
    pub fn with_proof(mut self, proof: TransactProof) -> TransactIxData {
        self.ix.proof = proof;
        self.ix
    }

    /// Prove this assembly through `authority`, which fills in the nullifier
    /// secrets it owns, and verify the proof against the public input the
    /// assembly fixed.
    ///
    /// One call rather than "complete, then prove": the two belong together, and
    /// nothing between assembly and the prover has any use for a witness
    /// carrying key material.
    pub fn prove<P: Prover + ?Sized>(
        &mut self,
        prover: &P,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactProof, ClientError> {
        let inputs = &mut self.prover_inputs;
        authority.complete_inputs(&mut inputs.inputs)?;
        let proof = prover.prove_transfer(inputs)?;
        crate::verify_confidential_transfer_inputs(inputs, self.public_input_hash, &proof)?;
        Ok(ProofCompressed::try_from(proof)?.to_transact_proof())
    }
}

/// Assemble the prover witness and the `Transact` instruction data in a single
/// pass over the already-padded transaction. The witness and the instruction
/// commit to identical values by construction: the nullifiers and
/// `private_tx_hash` come from the one prover build, and `external_data`
/// was finalized before proving. Root indices come from the supplied proofs.
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

    let signer_pk_hashes = proof_inputs.signer_pk_hashes(shape.signer_width())?;
    let public_transfers = proof_inputs.public_transfers()?;
    let result = TransferProver {
        inputs: attach_input_proofs(
            proof_inputs.input_utxos,
            input_proofs,
            dummy_nullifier_proofs,
        )?,
        outputs: proof_inputs.output_utxos,
        blinding_seed: proof_inputs.blinding_seed,
        output_tree_id: proof_inputs.output_tree_id,
        external_data: proof_inputs.external_data,
        public_transfers,
        signer_pk_hashes,
        allow_dummy_inputs,
        shape,
    }
    .build()?;
    let prover_inputs = result.inputs;
    let public_input_hash = result.public_input_hash;
    let nullifiers = result.nullifiers;
    let private_tx = result.private_tx_hash;

    if nullifiers.len() != shape.n_inputs() {
        return Err(ClientError::WitnessInputCountMismatch {
            got: nullifiers.len(),
            expected: shape.n_inputs(),
        });
    }

    let inputs = input_utxos_from_nullifiers(&nullifiers, &result.input_tree_indexes)?;

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
        prover_inputs,
        public_input_hash,
        input_tree_ids: result.tree_ids,
        ix,
    })
}

#[cfg(test)]
mod tests {

    fn wallet_input(
        utxo: Utxo,
        key: &zolana_keypair::NullifierKey,
        tree_id: u16,
    ) -> zolana_transaction::WalletUtxo {
        let nullifier_pubkey = key.pubkey().unwrap();
        let utxo_hash = utxo
            .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
            .unwrap();
        let nullifier = key.nullifier(&utxo_hash, &utxo.blinding).unwrap();
        zolana_transaction::WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        }
    }

    use solana_address::Address;
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{
        instructions::transact::{
            asset_field, ConfidentialTransaction, SettlementTransfer, Shape, SppProofInputs,
        },
        Data, ExternalData, SppProofOutputUtxo, Utxo,
    };

    use super::{assemble, attach_input_proofs, SpendProof};
    use crate::error::ClientError;
    use crate::rpc::{
        MerkleContext, MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
    };
    use zolana_transaction::utxo::SppProofInputUtxo;

    #[test]
    fn attaches_dummy_nullifier_proofs_in_slot_order() {
        let inputs = vec![
            SppProofInputUtxo::dummy(0).expect("dummy input"),
            SppProofInputUtxo::dummy(0).expect("dummy input"),
        ];
        let proofs = [dummy_nullifier_proof(1), dummy_nullifier_proof(2)];

        let input_utxos = attach_input_proofs(inputs, &[], &proofs).expect("attach dummy proofs");

        let attached: Vec<_> = input_utxos
            .iter()
            .map(|input_utxo| input_utxo.nullifier_proof.clone())
            .collect();
        assert_eq!(attached, proofs.map(Some).to_vec());
    }

    #[test]
    fn default_transact_rejects_p256_owned_inputs() {
        let keypair = ShieldedKeypair::new_p256().expect("P256 keypair");
        let input = wallet_input(
            Utxo {
                owner: keypair.signing_pubkey(),
                asset: zolana_transaction::Mint::SOL,
                amount: 1,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &keypair.nullifier_key,
            0,
        );
        let proof_inputs = SppProofInputs {
            input_utxos: vec![input.into()],
            output_utxos: vec![SppProofOutputUtxo::default()],
            external_data: ExternalData::new(
                [0u8; 33],
                [0u8; 16],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            payer: Address::default(),
            blinding_seed: [7; 32],
            output_tree_id: 0,
        };

        assert!(matches!(
            assemble(proof_inputs, &[], &[]),
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
        let proof_inputs = SppProofInputs {
            input_utxos: vec![SppProofInputUtxo::dummy(0).unwrap()],
            output_utxos: vec![SppProofOutputUtxo::default()],
            external_data,
            payer: Address::default(),
            blinding_seed: [7; 32],
            output_tree_id: 0,
        };
        let transfers = proof_inputs.public_transfers().unwrap();
        assert_eq!(transfers.assets[0], asset_field(&mint).unwrap());
        assert!(transfers
            .assets
            .iter()
            .skip(1)
            .all(|asset| *asset == [0; 32]));
    }

    /// The nullifiers `dummy_nullifiers()` requests non-inclusion witnesses for
    /// must be the ones the assembled witness carries. Both hash the dummy under
    /// the input tree's id; a tree other than 0 exposes any drift between them.
    #[test]
    fn assembled_dummy_nullifiers_match_the_requested_ones() {
        let sender = ShieldedKeypair::new_ed25519().expect("sender keypair");
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient keypair");
        let input = wallet_input(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: zolana_transaction::Mint::SOL,
                amount: 10,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            3,
        );
        let payer = Address::new_from_array(
            sender
                .signing_pubkey()
                .as_ed25519()
                .expect("sender Ed25519 pubkey"),
        );
        let mut transfer = ConfidentialTransaction::new(vec![input], payer).unwrap();
        transfer
            .transfer_sol(&recipient.shielded_address().expect("recipient address"), 4)
            .expect("transfer");
        transfer
            .pad_utxos(Shape::IN2_OUT3, &sender.shielded_address().unwrap())
            .unwrap();
        let proof_inputs = transfer.encrypt(&sender).expect("encrypt");

        let requested = proof_inputs.dummy_nullifiers();
        let real = &proof_inputs.input_utxos[0];
        let mut proof = fake_spend_proof();
        proof.state.leaf = real.utxo_hash;
        proof.state.leaf_index = real.leaf_index;
        proof.state.merkle_context.tree = zolana_interface::pda::tree(real.tree_id);
        proof.nullifier.leaf = real.nullifier;
        proof.nullifier.merkle_context.tree = zolana_interface::pda::tree(real.tree_id);
        let dummy: Vec<_> = requested
            .iter()
            .map(|nullifier| {
                let mut nf = proof.nullifier.clone();
                nf.leaf = *nullifier;
                nf
            })
            .collect();
        let assembled = assemble(proof_inputs, &[proof], &dummy).expect("assemble");

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
