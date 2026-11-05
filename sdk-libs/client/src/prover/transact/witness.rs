use spr_interface::{
    instruction::instruction_data::transact::{CircuitId, TransactIxData, TransactProof},
    pda,
};
use spr_transaction::{
    instructions::transact::{SppProofInputs, TransactRail},
    utxo::SppProofInputUtxo,
};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        requests::CircuitRequest,
        transact::{
            assembly::{input_utxos_from_nullifiers, TransferInputUtxo},
            confidential_eddsa::{
                confidential_eddsa_signer_pk_hashes, ConfidentialEddsaProver,
                ConfidentialEddsaTransferInputs,
            },
            eddsa::TransferProver,
            OwnerAuthorization,
        },
        Proof, ProofCompressed, Prover, ProverExt, ProvingKeySet,
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

/// Attach the fetched Merkle proofs to the proof inputs positionally: each slot
/// that spends a state leaf (a real, uncached input) consumes the next spend
/// proof; every other slot (padding, compact padding included, a cached input
/// or an address) consumes the next non-inclusion proof (the transact circuit
/// checks non-inclusion for every slot). Shared by every witness builder
/// (transact, merge, merge-ring, ring-authority).
///
/// No secret comes in here: a real input's nullifier secret is filled in by its
/// owner's [`ProofAuthority`](crate::authority::ProofAuthority), one call before
/// the witness goes to the prover.
pub fn attach_input_proofs(
    inputs: Vec<SppProofInputUtxo>,
    proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<Vec<TransferInputUtxo>, ClientError> {
    let real_count = inputs
        .iter()
        .filter(|input| input.requires_inclusion())
        .count();
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
        let (proof, nullifier_proof) = if !input_utxo.requires_inclusion() {
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

/// Instruction data built from the same values as the prover inputs.
pub(crate) struct TransferInstructionData<'a> {
    pub external_data: spr_transaction::ExternalData,
    pub private_tx_hash: [u8; 32],
    pub circuit: CircuitId,
    pub nullifiers: &'a [[u8; 32]],
    pub input_tree_indexes: &'a [u8],
    pub tree_contexts: Vec<spr_interface::instruction::instruction_data::transact::TreeContext>,
}

impl TransferInstructionData<'_> {
    pub fn build(self) -> Result<TransactIxData, ClientError> {
        let external = self.external_data;
        Ok(TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: self.private_tx_hash,
            circuit: self.circuit,
            inputs: input_utxos_from_nullifiers(self.nullifiers, self.input_tree_indexes)?,
            tree_contexts: self.tree_contexts,
            interface_transfers: external
                .interface_transfers
                .into_iter()
                .map(
                    spr_transaction::instructions::transact::SettlementTransfer::interface_transfer,
                )
                .collect(),
            data_hash: external.data_hash,
            ring_data_hash: external.ring_data_hash,
            tx_viewing_pk: external.tx_viewing_pk,
            salt: external.salt,
            outputs: external.outputs,
            messages: external.messages,
        })
    }
}

impl super::TransferProofResult {
    pub fn with_proof(mut self, proof: TransactProof) -> TransactIxData {
        self.instruction_data.proof = proof;
        self.instruction_data
    }

    /// The selector the instruction carries, before any commitment.
    pub fn circuit(&self) -> CircuitId {
        self.instruction_data.circuit
    }

    /// The request that proves this assembly once its inputs are complete.
    pub(crate) fn request(&self) -> Result<CircuitRequest, ClientError> {
        match &self.authorization {
            Some(authorization) => crate::prover::requests::transfer_confidential_eddsa(
                &ConfidentialEddsaTransferInputs {
                    transfer: self.inputs.clone(),
                    authorization: authorization.clone(),
                },
            ),
            None => crate::prover::requests::transfer(&self.inputs),
        }
    }

    /// Runtime key sets currently support only transaction-signer rails.
    pub(crate) fn check_key_set(&self, keys: Option<&ProvingKeySet>) -> Result<(), ClientError> {
        if self.authorization.is_some() && keys.is_some() {
            return Err(ClientError::ProvingKeySet("unsupported_circuit"));
        }
        Ok(())
    }

    /// Encode the returned proof for its instruction without local verification.
    /// In-circuit signature rails also carry their BSB22 commitment in the selector.
    pub fn accept_proof(&mut self, proof: Proof) -> Result<TransactProof, ClientError> {
        let compressed = ProofCompressed::try_from(proof)?;
        match (&self.authorization, compressed.commitment) {
            (Some(_), _) => {
                let (transact, commitment) = compressed.into_committed_transact_parts()?;
                match &mut self.instruction_data.circuit {
                    CircuitId::ConfidentialEddsa(_, _, _, data)
                    | CircuitId::ConfidentialEddsaCached(_, _, _, data, _) => {
                        data.bsb22_commitment = commitment;
                    }
                    _ => {
                        return Err(ClientError::ProofParse(
                            "selector takes no commitment".into(),
                        ))
                    }
                }
                Ok(transact)
            }
            (None, Some(_)) => Err(ClientError::ProofParse(
                "signer proof carries an unexpected BSB22 commitment".into(),
            )),
            (None, None) => Ok(compressed.to_transact_proof()),
        }
    }

    /// Complete the inputs through `authority`, invoke the synchronous prover,
    /// and encode its returned proof. Verification is performed on chain.
    ///
    /// One call rather than "complete, then prove": the two belong together, and
    /// nothing between assembly and the prover has any use for a witness
    /// carrying key material.
    pub fn prove<P: Prover + ?Sized>(
        &mut self,
        prover: &P,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactProof, ClientError> {
        self.check_key_set(prover.key_set())?;
        authority.complete_inputs(&mut self.inputs.inputs)?;
        let proof = match &self.authorization {
            Some(authorization) => {
                prover.prove_transfer_confidential_eddsa(&ConfidentialEddsaTransferInputs {
                    transfer: self.inputs.clone(),
                    authorization: authorization.clone(),
                })?
            }
            None => prover.prove_transfer(&self.inputs)?,
        };
        self.accept_proof(proof)
    }
}

/// Build proof inputs and matching instruction data in one synchronous operation.
pub fn build_transfer(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
) -> Result<super::TransferProofResult, ClientError> {
    build_transfer_with_dummy_policy(proof_inputs, input_proofs, dummy_nullifier_proofs, true)
}

pub fn build_transfer_with_dummy_policy(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    allow_dummy_inputs: bool,
) -> Result<super::TransferProofResult, ClientError> {
    let shape = proof_inputs.check_shape()?;
    let signer_pk_hashes = proof_inputs.signer_pk_hashes(shape.signer_width())?;
    let public_transfers = proof_inputs.public_transfers()?;
    TransferProver {
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
        cache_accounts: proof_inputs.cache_accounts,
    }
    .build()
}

/// Build the same instruction and proof inputs with in-circuit owner authorization.
pub fn build_confidential_eddsa_transfer<'a>(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    owner: impl Into<OwnerAuthorization<'a>>,
) -> Result<super::TransferProofResult, ClientError> {
    build_confidential_eddsa_transfer_with_dummy_policy(
        proof_inputs,
        input_proofs,
        dummy_nullifier_proofs,
        true,
        owner,
    )
}

pub fn build_confidential_eddsa_transfer_with_dummy_policy<'a>(
    proof_inputs: SppProofInputs,
    input_proofs: &[SpendProof],
    dummy_nullifier_proofs: &[NonInclusionProof],
    allow_dummy_inputs: bool,
    owner: impl Into<OwnerAuthorization<'a>>,
) -> Result<super::TransferProofResult, ClientError> {
    let owner = owner.into();
    let shape = proof_inputs.check_shape_for(TransactRail::ConfidentialEddsa)?;
    let signer_pk_hashes = confidential_eddsa_signer_pk_hashes(&proof_inputs, &owner.public_key())?;
    let public_transfers = proof_inputs.public_transfers()?;
    let external = proof_inputs.external_data.clone();
    let cache_accounts = proof_inputs.cache_accounts;
    let computed = ConfidentialEddsaProver {
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
        owner,
        shape,
        cache_accounts,
    }
    .build()?;
    let ConfidentialEddsaTransferInputs {
        transfer: inputs,
        authorization,
    } = computed.inputs;
    let instruction_data = TransferInstructionData {
        external_data: external,
        private_tx_hash: computed.private_tx_hash,
        circuit: authorization.circuit(shape, computed.cache_access),
        nullifiers: &computed.nullifiers,
        input_tree_indexes: &computed.input_tree_indexes,
        tree_contexts: computed.tree_contexts.clone(),
    }
    .build()?;
    Ok(super::TransferProofResult {
        inputs,
        authorization: Some(authorization),
        instruction_data,
        cache_accounts,
        public_input_hash: computed.public_input_hash,
        nullifiers: computed.nullifiers,
        output_hashes: computed.output_hashes,
        private_tx_hash: computed.private_tx_hash,
        tree_contexts: computed.tree_contexts,
        tree_ids: computed.tree_ids,
        input_tree_indexes: computed.input_tree_indexes,
        cache_access: computed.cache_access,
    })
}

#[cfg(test)]
mod tests {

    fn wallet_input(
        utxo: Utxo,
        key: &spr_keypair::NullifierKey,
        tree_id: u16,
    ) -> spr_transaction::WalletUtxo {
        let nullifier_pubkey = key.pubkey().unwrap();
        let utxo_hash = utxo
            .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
            .unwrap();
        let nullifier = key.nullifier(&utxo_hash, &utxo.blinding).unwrap();
        spr_transaction::WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        }
    }

    use solana_address::Address;
    use spr_keypair::ShieldedKeypair;
    use spr_transaction::{
        instructions::transact::{
            asset_field, ConfidentialTransaction, SettlementTransfer, Shape, SppProofInputs,
        },
        Data, ExternalData, SppProofOutputUtxo, Utxo,
    };

    use super::{attach_input_proofs, build_transfer, SpendProof};
    use crate::rpc::{
        MerkleContext, MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
    };
    use spr_transaction::utxo::SppProofInputUtxo;

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
    fn cached_inputs_take_dummy_nullifier_proofs_in_slot_order() {
        let owner =
            ShieldedKeypair::from_keypair(spr_keypair::SigningKey::from_ed25519_bytes(&[3u8; 32]))
                .expect("ed25519 keypair");
        let cached: SppProofInputUtxo = wallet_input(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: spr_transaction::Mint::SOL,
                amount: 1,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &owner.nullifier_key,
            0,
        )
        .into();
        let inputs = vec![
            SppProofInputUtxo::dummy(0).expect("dummy input"),
            cached.with_cache_slot(4).expect("cached input"),
        ];
        let proofs = [dummy_nullifier_proof(1), dummy_nullifier_proof(2)];

        let input_utxos = attach_input_proofs(inputs, &[], &proofs).expect("attach proofs");

        assert!(input_utxos
            .iter()
            .all(|input_utxo| input_utxo.proof.is_none()));
        let attached: Vec<_> = input_utxos
            .iter()
            .map(|input_utxo| input_utxo.nullifier_proof.clone())
            .collect();
        assert_eq!(attached, proofs.map(Some).to_vec());
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
            cache_accounts: Default::default(),
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
                asset: spr_transaction::Mint::SOL,
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
            .pad_utxos(Shape::IN2_OUT4, &sender.shielded_address().unwrap())
            .unwrap();
        let proof_inputs = transfer.encrypt(&sender).expect("encrypt");

        use crate::prover::indexed::{PreparedIndexedTransfer, Request};
        let indexed = PreparedIndexedTransfer::new(proof_inputs.clone(), &sender).unwrap();
        let indexed_body: serde_json::Value =
            serde_json::from_str(&indexed.body().unwrap()).unwrap();
        let requested = proof_inputs.dummy_nullifiers();
        let real = proof_inputs.input_utxos.first().unwrap();
        let mut proof = fake_spend_proof();
        proof.state.leaf = real.utxo_hash;
        proof.state.leaf_index = real.leaf_index;
        proof.state.merkle_context.tree = spr_interface::pda::tree(real.tree_id);
        proof.nullifier.leaf = real.nullifier;
        proof.nullifier.merkle_context.tree = spr_interface::pda::tree(real.tree_id);
        let dummy: Vec<_> = requested
            .iter()
            .map(|nullifier| {
                let mut nf = proof.nullifier.clone();
                nf.leaf = *nullifier;
                nf
            })
            .collect();
        let mut assembled = build_transfer(proof_inputs, &[proof], &dummy).expect("build transfer");
        crate::authority::ProofAuthority::complete_inputs(&sender, &mut assembled.inputs.inputs)
            .unwrap();
        let mut complete_json: serde_json::Value =
            serde_json::from_str(&crate::prover::json::to_json(&assembled.inputs).unwrap())
                .unwrap();
        let object = complete_json.as_object_mut().unwrap();
        object.remove("treeSlots");
        object.remove("publicInputHash");
        for input in object["inputs"].as_array_mut().unwrap() {
            for field in [
                "statePathElements",
                "statePathIndex",
                "nullifierLowValue",
                "nullifierNextValue",
                "nullifierLowPathElements",
                "nullifierLowPathIndex",
            ] {
                input.as_object_mut().unwrap().remove(field);
            }
        }
        assert_eq!(indexed_body["prepared"], complete_json);

        let witnessed: Vec<[u8; 32]> = assembled
            .instruction_data
            .inputs
            .iter()
            .skip(1)
            .map(|input| input.nullifier_hash)
            .collect();
        assert_eq!(requested.len(), 1);
        assert_eq!(witnessed, requested);
    }

    /// A runtime set holds no EdDSA-authorized keys, so the assembly is
    /// refused before the prover is asked for a proof.
    #[test]
    fn a_runtime_set_refuses_an_eddsa_assembly_before_proving() {
        struct SetProver(crate::prover::ProvingKeySet);
        impl crate::prover::Prover for SetProver {
            fn prove(
                &self,
                _: &dyn crate::prover::ProveRequest,
            ) -> Result<crate::prover::Proof, crate::ClientError> {
                panic!("proved an assembly the set cannot verify")
            }
            fn key_set(&self) -> Option<&crate::prover::ProvingKeySet> {
                Some(&self.0)
            }
        }
        let keys = crate::prover::ProvingKeySet::from_attested_response(include_str!(
            "../../../../../test-vectors/runtime_proving_keys.json"
        ))
        .unwrap();

        let sender = ShieldedKeypair::new_ed25519().expect("sender keypair");
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient keypair");
        let input = wallet_input(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: spr_transaction::Mint::SOL,
                amount: 10,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
        );
        let payer = Address::new_from_array([9; 32]);
        let mut transfer = ConfidentialTransaction::new(vec![input], payer).unwrap();
        transfer
            .transfer_sol(&recipient.shielded_address().expect("recipient address"), 4)
            .expect("transfer");
        transfer
            .pad_utxos(Shape::IN2_OUT8, &sender.shielded_address().unwrap())
            .unwrap();
        let proof_inputs = transfer.encrypt(&sender).expect("encrypt");
        let requested = proof_inputs.dummy_nullifiers();
        let real = proof_inputs.input_utxos.first().unwrap();
        let mut proof = fake_spend_proof();
        proof.state.leaf = real.utxo_hash;
        proof.state.merkle_context.tree = spr_interface::pda::tree(real.tree_id);
        proof.nullifier.leaf = real.nullifier;
        proof.nullifier.merkle_context.tree = spr_interface::pda::tree(real.tree_id);
        let dummy: Vec<_> = requested
            .iter()
            .map(|nullifier| {
                let mut nf = proof.nullifier.clone();
                nf.leaf = *nullifier;
                nf
            })
            .collect();
        let mut assembled = super::build_confidential_eddsa_transfer(
            proof_inputs,
            &[proof],
            &dummy,
            &sender.signing_key,
        )
        .expect("assemble");
        assert!(matches!(
            assembled.prove(&SetProver(keys), &sender),
            Err(crate::ClientError::ProvingKeySet("unsupported_circuit"))
        ));
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
