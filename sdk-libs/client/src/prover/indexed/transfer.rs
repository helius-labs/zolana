use super::{
    hex_field, IndexedCircuit, IndexedLookup, IndexedProof, IndexedProofData, IndexedProofRequest,
    IndexedTree, Request,
};
use crate::{
    authority::ProofAuthority,
    prover::{
        field::{be, right_align_slice},
        json::{output_to_json, utxo_to_json, OutputParamsJson, UtxoParamsJson},
        transact::assembly::{assemble_outputs, input_utxos_from_nullifiers, PublicInputs},
        verify::TransferProofStatement,
        ExpectedProvingKey, Proof, ProofCompressed, ProofInputUtxo, TransferInput,
    },
    ClientError,
};
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_interface::{
    instruction::instruction_data::transact::{CircuitId, TransactIxData, TransactProof},
    tree_slot::pack_input_flags,
    MAX_INPUT_TREES, N_PUBLIC_SLOTS,
};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofInputs},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
};

pub enum IndexedTransferRail<'a> {
    Confidential,
    Ring(solana_address::Address),
    RingAuthority(solana_address::Address),
    /// Keeps the owner off chain while signing the exact root-independent statement.
    AnonymousRingEd25519 {
        ring: solana_address::Address,
        owner: &'a zolana_keypair::SigningKey,
    },
}

pub struct IndexedTransferPreparation<'a> {
    pub transaction: SppProofInputs,
    pub rail: IndexedTransferRail<'a>,
}

pub struct PreparedIndexedTransfer {
    request: IndexedProofRequest,
    data: TransactIxData,
}

pub struct ProvenIndexedTransfer {
    pub input_tree_ids: Vec<u16>,
    pub data: TransactIxData,
    pub public_input_hash: [u8; 32],
    pub proof: ProofCompressed,
}

impl IndexedTransferPreparation<'_> {
    pub fn prepare(
        self,
        authority: &dyn ProofAuthority,
    ) -> Result<PreparedIndexedTransfer, ClientError> {
        self.prepare_with_dummy_policy(authority, true)
    }

    pub fn prepare_with_dummy_policy(
        self,
        authority: &dyn ProofAuthority,
        allow_dummy_inputs: bool,
    ) -> Result<PreparedIndexedTransfer, ClientError> {
        let Self { transaction, rail } = self;
        if !allow_dummy_inputs {
            if let Some(index) = transaction
                .input_utxos
                .iter()
                .position(|input| input.is_dummy() && !input.is_compact())
            {
                return Err(ClientError::NonSpendInputNotAllowed { index });
            }
        }
        let shape = transaction.check_shape()?;
        if matches!(&rail, IndexedTransferRail::Ring(_)) {
            transaction
                .external_data
                .validate_ring_output_markers(&transaction.output_utxos)?;
        }
        let proof_inputs = transaction
            .input_utxos
            .iter()
            .cloned()
            .map(|utxo| crate::prover::TransferInputUtxo {
                utxo,
                proof: None,
                nullifier_proof: None,
            })
            .collect::<Vec<_>>();
        let cache = crate::prover::cache::CacheSelection::derive(
            &proof_inputs,
            &transaction.output_utxos,
            transaction.cache_accounts,
            &transaction.external_data,
        )?;
        let authority_rail = matches!(rail, IndexedTransferRail::RingAuthority(_));
        let hidden_owner = match &rail {
            IndexedTransferRail::AnonymousRingEd25519 { owner, .. } => Some(owner.pubkey()),
            _ => None,
        };
        let ring = match &rail {
            IndexedTransferRail::Confidential => None,
            IndexedTransferRail::Ring(ring)
            | IndexedTransferRail::RingAuthority(ring)
            | IndexedTransferRail::AnonymousRingEd25519 { ring, .. } => Some(*ring),
        };
        if authority_rail
            && (shape.n_inputs() != shape.n_outputs()
                || cache.access.is_some()
                || !transaction.external_data.interface_transfers.is_empty()
                || transaction
                    .input_utxos
                    .iter()
                    .any(|input| !input.is_dummy() && input.utxo.ring_program_id != ring)
                || transaction
                    .output_utxos
                    .iter()
                    .any(|output| !output.is_dummy() && output.ring_program_id != ring))
        {
            return Err(super::invalid());
        }
        if hidden_owner.is_some() {
            // Anonymous ownership has no cached wire variant or default-ring outputs.
            if cache.access.is_some() {
                return Err(super::invalid());
            }
            for (index, output) in transaction.output_utxos.iter().enumerate() {
                if !output.is_dummy() && output.ring_program_id != ring {
                    return Err(ClientError::AnonymousOutputNotInRing { index });
                }
            }
            transaction
                .external_data
                .validate_ring_output_markers(&transaction.output_utxos)?;
        }
        let mut trees: Vec<IndexedTree> = Vec::new();
        let mut lookups = Vec::new();
        let mut local_inputs = Vec::new();
        let mut input_hashes = Vec::new();
        let mut nullifiers = Vec::new();
        let mut indexes = Vec::new();
        for input in &transaction.input_utxos {
            // Inputs from different trees may interleave; a dummy joins the
            // tree it names, which a real input must already have opened.
            // Compact padding names the first tree, since SPP never receives
            // it and packs tree index 0 for it.
            let position = match trees.iter().position(|tree| tree.id == input.tree_id) {
                Some(position) => position,
                None => {
                    if input.is_dummy() {
                        return Err(ClientError::NoInputs);
                    }
                    if trees.len() == MAX_INPUT_TREES {
                        return Err(ClientError::TooManyInputTrees {
                            got: trees.len() + 1,
                            max: MAX_INPUT_TREES,
                        });
                    }
                    trees.push(IndexedTree {
                        id: input.tree_id,
                        tree: zolana_interface::pda::tree(input.tree_id).to_bytes().into(),
                    });
                    trees.len() - 1
                }
            };
            if input.is_compact() && position != 0 {
                return Err(ClientError::InputTreeUnresolved {
                    tree_id: input.tree_id,
                });
            }
            let tree_slot = u8::try_from(position).map_err(|_| ClientError::NoInputs)?;
            let utxo = ProofInputUtxo::try_from(input)?;
            let hash = utxo.hash()?;
            let nullifier = input.published_nullifier();
            if hash != input.utxo_hash {
                return Err(
                    zolana_transaction::TransactionError::InputCommitmentMismatch {
                        index: local_inputs.len(),
                    }
                    .into(),
                );
            }
            let owner = if input.is_dummy() || hidden_owner.as_ref() == Some(&input.utxo.owner) {
                [0; 32]
            } else {
                input.utxo.owner.owner_proof_input_hash()?
            };
            local_inputs.push(TransferInput {
                utxo,
                is_dummy: u8::from(input.is_dummy()).into(),
                state_path_elements: Vec::new(),
                state_path_index: 0u8.into(),
                nullifier_low_value: 0u8.into(),
                nullifier_next_value: 0u8.into(),
                nullifier_low_path_elements: Vec::new(),
                nullifier_low_path_index: 0u8.into(),
                tree_slot: tree_slot.into(),
                nullifier: be(&nullifier),
                owner_pk_hash: be(&owner),
                nullifier_secret: input.is_dummy().then(|| 0u8.into()),
            });
            lookups.push(IndexedLookup {
                tree_slot,
                commitment: (!input.is_dummy() && input.cache_slot.is_none()).then_some(hash),
                nullifier: input.is_compact().then_some(input.nullifier),
            });
            indexes.push(tree_slot);
            input_hashes.push(if input.is_dummy() { [0; 32] } else { hash });
            nullifiers.push(nullifier);
        }
        authority.complete_inputs(&mut local_inputs)?;
        let first = nullifiers.first().ok_or(ClientError::NoInputs)?;
        let seed = derive_output_blinding_seed(first, &transaction.blinding_seed)?;
        for (index, output) in transaction.output_utxos.iter().enumerate() {
            let slot = u32::try_from(index).map_err(|_| super::invalid())?;
            if output.blinding != derive_transact_output_blinding(first, &seed, slot)? {
                return Err(ClientError::OutputBlindingMismatch { index });
            }
        }
        let outputs = assemble_outputs(&transaction.output_utxos, transaction.output_tree_id)?;
        let external_hash = cache.external_data_hash;
        let blinding = derive_private_tx_blinding(first, &transaction.blinding_seed)?;
        let private_tx =
            PrivateTxHash::new(&input_hashes, &outputs.private_tx_output_hashes, &blinding)
                .hash()?;
        let public_transfers = transaction.public_transfers()?;
        let signers = if hidden_owner.is_some() {
            let mut signers = vec![[0; 32]; shape.signer_width()];
            *signers.first_mut().ok_or_else(super::invalid)? =
                zolana_hasher::primitives::solana_owner_identity(transaction.payer.as_array())?;
            signers
        } else if authority_rail {
            vec![zolana_hasher::primitives::solana_owner_identity(
                transaction.payer.as_array(),
            )?]
        } else {
            transaction.signer_pk_hashes(shape.signer_width())?
        };
        let ring_program_id = zolana_transaction::utxo::program_id_proof_input_hash(&ring)?;
        let owners = match rail {
            IndexedTransferRail::Confidential => Some(outputs.output_owner_pk_hashes.clone()),
            IndexedTransferRail::Ring(_) | IndexedTransferRail::AnonymousRingEd25519 { .. } => {
                Some(
                    crate::prover::transact::assembly::confidential_marked_output_owner_pk_hashes(
                        &transaction.external_data,
                        transaction.output_utxos.len(),
                    )?,
                )
            }
            IndexedTransferRail::RingAuthority(_) => None,
        };
        // Sign after outputs and external data are fixed. Resolved roots cannot change this digest.
        let digest = zolana_transaction::instructions::transact::transact_message_hash(
            &private_tx,
            &external_hash,
        );
        let authorization = match &rail {
            IndexedTransferRail::AnonymousRingEd25519 { owner, .. } => Some(
                crate::prover::transact::anonymous_ring_ed25519::owner_fields(
                    &owner.pubkey().as_ed25519()?,
                    &owner.sign_message(&digest)?,
                    &digest,
                ),
            ),
            _ => None,
        };
        let appendix = hidden_owner
            .map(|_| zolana_hasher::primitives::hash_bytes(&digest).map(|hash| [hash, [0; 32]]))
            .transpose()?;
        let flags = pack_input_flags(allow_dummy_inputs, indexes.iter().copied())?;
        let public_inputs = PublicInputs {
            nullifiers: &nullifiers,
            output_hashes: &outputs.output_hashes,
            tree_slots: (),
            output_tree_id: transaction.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_hash,
            public_transfers: &public_transfers,
            ring_program_id: &ring_program_id,
            input_flags: &flags,
            signer_pk_hashes: &signers,
            output_owner_pk_hashes: owners.as_deref(),
            cached_inputs: cache.public_fields,
        }
        .without_roots(appendix.as_ref().map_or(&[], |fields| fields.as_slice()))?;
        let prepared = PreparedTransferJson {
            authorization,
            circuit_type: match rail {
                IndexedTransferRail::Confidential => IndexedCircuit::TransferConfidential,
                IndexedTransferRail::Ring(_) => IndexedCircuit::TransferRing,
                IndexedTransferRail::RingAuthority(_) => IndexedCircuit::TransferRingAuthority,
                IndexedTransferRail::AnonymousRingEd25519 { .. } => {
                    IndexedCircuit::TransferAnonymousRingEd25519
                }
            },
            n_inputs: shape.n_inputs(),
            n_outputs: shape.n_outputs(),
            inputs: local_inputs
                .iter()
                .map(PreparedInputJson::try_from)
                .collect::<Result<_, _>>()?,
            outputs: outputs.outputs.iter().map(output_to_json).collect(),
            output_tree_id: format!("0x{:x}", transaction.output_tree_id),
            blinding_seed: SecretField(Zeroizing::new(transaction.blinding_seed)),
            external_data_hash: hex_field(&external_hash),
            private_tx_hash: hex_field(&private_tx),
            public_assets: public_transfers.assets.iter().map(hex_field).collect(),
            public_amounts: public_transfers.amounts.iter().map(hex_field).collect(),
            ring_program_id: hex_field(&ring_program_id),
            signer_pk_hashes: signers.iter().map(hex_field).collect(),
            input_flags: hex_field(&flags),
            cache: super::super::json::cache_reads_to_json(&cache.proof_inputs),
            // The hidden-owner decoder requires an empty vector, while the transcript binds zeros.
            published_output_owner_pk_hashes: owners
                .as_deref()
                .filter(|_| hidden_owner.is_none())
                .unwrap_or_default()
                .iter()
                .map(hex_field)
                .collect(),
        };
        let witness =
            Zeroizing::new(serde_json::to_string(&prepared).map_err(|_| super::invalid())?);
        let request = IndexedProofRequest::new(IndexedProofData {
            witness,
            trees,
            inputs: lookups,
            public_inputs,
        })?;
        let external = transaction.external_data;
        let data = TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: private_tx,
            circuit: {
                let n_in = u8::try_from(shape.n_inputs()).map_err(|_| super::invalid())?;
                let n_out = u8::try_from(shape.n_outputs()).map_err(|_| super::invalid())?;
                let slots = u8::try_from(N_PUBLIC_SLOTS).map_err(|_| super::invalid())?;
                match rail {
                    IndexedTransferRail::Confidential => match cache.access {
                        Some(access) => CircuitId::ConfidentialEd25519Cached(n_in, n_out, slots, access),
                        None => CircuitId::ConfidentialEd25519(n_in, n_out, slots),
                    },
                    IndexedTransferRail::Ring(_) => match cache.access {
                        Some(access) => CircuitId::ConfidentialRingEd25519Cached(n_in, n_out, slots, access),
                        None => CircuitId::ConfidentialRingEd25519(n_in, n_out, slots),
                    },
                    IndexedTransferRail::RingAuthority(_) => CircuitId::RingAuthority(n_in, n_out, slots),
                    IndexedTransferRail::AnonymousRingEd25519 { .. } => CircuitId::AnonymousRingEd25519(n_in, n_out, slots, zolana_interface::verifying_keys::Bsb22Commitment { commitment: [0; 32], commitment_pok: [0; 32] }),

                }
            },
            inputs: input_utxos_from_nullifiers(&nullifiers, &indexes)?,
            tree_contexts: Vec::new(),
            interface_transfers: external.interface_transfers.iter().copied()
                .map(zolana_transaction::instructions::transact::SettlementTransfer::interface_transfer).collect(),
            data_hash: external.data_hash,
            ring_data_hash: external.ring_data_hash,
            tx_viewing_pk: external.tx_viewing_pk,
            salt: external.salt,
            outputs: external.outputs,
            messages: external.messages,
        };
        Ok(PreparedIndexedTransfer { request, data })
    }
}

impl PreparedIndexedTransfer {
    pub fn new(
        transaction: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<Self, ClientError> {
        IndexedTransferPreparation {
            transaction,
            rail: IndexedTransferRail::Confidential,
        }
        .prepare(authority)
    }

    #[must_use]
    pub fn with_min_context_slot(mut self, slot: u64) -> Self {
        self.request = self.request.with_min_context_slot(slot);
        self
    }

    pub fn private_tx_hash(&self) -> [u8; 32] {
        self.data.private_tx_hash
    }

    /// Fixed-size proof placeholders and the exact accounts and ciphertexts.
    /// Used to reject transactions that cannot fit before requesting a proof.
    pub fn transaction_template(&self) -> &TransactIxData {
        &self.data
    }
}

impl Request for PreparedIndexedTransfer {
    type Output = ProvenIndexedTransfer;

    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        self.request.body()
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        self.request.proving_key()
    }

    fn delivery(&self) -> Option<crate::prover::client::Delivery> {
        matches!(self.data.circuit, CircuitId::AnonymousRingEd25519(..))
            .then_some(crate::prover::client::Delivery::InResponse)
    }

    fn finish(
        &self,
        proof: Proof,
        resolution: serde_json::Value,
    ) -> Result<ProvenIndexedTransfer, ClientError> {
        let IndexedProof { proof, resolution } = self.request.finish(proof, resolution)?;
        let mut data = self.data.clone();
        let public_input_hash = resolution.public_input_hash;
        // 2. Verify the resolved statement before exposing transaction bytes.
        TransferProofStatement {
            circuit: data.circuit,
            public_input_hash,
        }
        .verify(&proof)?;
        data.tree_contexts = resolution.trees.iter().map(|tree| tree.context).collect();
        let input_tree_ids = resolution.trees.iter().map(|tree| tree.id).collect();
        let proof = ProofCompressed::try_from(proof)?;
        if let CircuitId::AnonymousRingEd25519(_, _, _, commitment) = &mut data.circuit {
            let (transact, carried) = proof.into_committed_transact_parts()?;
            data.proof = transact;
            *commitment = carried;
        } else {
            data.proof = proof.to_transact_proof();
        }
        Ok(ProvenIndexedTransfer {
            input_tree_ids,
            data,
            public_input_hash,
            proof,
        })
    }
}

pub(super) struct SecretField(pub(super) Zeroizing<[u8; 32]>);
impl Serialize for SecretField {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(hex_field(&self.0));
        serializer.serialize_str(&encoded)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedInputJson {
    utxo: UtxoParamsJson,
    is_dummy: &'static str,
    tree_slot: String,
    nullifier: String,
    owner_pk_hash: String,
    nullifier_secret: SecretField,
}

impl TryFrom<&TransferInput> for PreparedInputJson {
    type Error = ClientError;

    fn try_from(input: &TransferInput) -> Result<Self, Self::Error> {
        let secret = input.nullifier_secret.as_ref().ok_or_else(super::invalid)?;
        Ok(Self {
            utxo: utxo_to_json(&input.utxo),
            is_dummy: if input.is_dummy == 0u8.into() {
                "0x0"
            } else {
                "0x1"
            },
            tree_slot: format!("0x{:x}", input.tree_slot),
            nullifier: format!("0x{:x}", input.nullifier),
            owner_pk_hash: format!("0x{:x}", input.owner_pk_hash),
            nullifier_secret: SecretField(Zeroizing::new(right_align_slice(
                &secret.to_bytes_be(),
            )?)),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedTransferJson {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    authorization: Option<serde_json::Map<String, serde_json::Value>>,
    n_inputs: usize,
    n_outputs: usize,
    #[serde(flatten)]
    cache: super::super::json::CacheReadsJson,
    circuit_type: IndexedCircuit,
    inputs: Vec<PreparedInputJson>,
    outputs: Vec<OutputParamsJson>,
    output_tree_id: String,
    blinding_seed: SecretField,
    external_data_hash: String,
    private_tx_hash: String,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    ring_program_id: String,
    signer_pk_hashes: Vec<String>,
    input_flags: String,
    published_output_owner_pk_hashes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MerkleContext, MerkleProof, NonInclusionProof, SpendProof, TransferInputUtxo};
    use solana_address::Address;
    use zolana_interface::instruction::{OwnerTag, TransactOutput, TreeContext};
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{
        utxo::SppProofInputUtxo, Data, ExternalData, Mint, SppProofOutputUtxo, Utxo, WalletUtxo,
    };

    fn fixture(owner: &ShieldedKeypair, ring: Option<Address>, n_inputs: usize) -> SppProofInputs {
        let utxo = Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount: 10,
            blinding: [2; 32],
            ring_program_id: ring,
            data: Data::default(),
        };
        let nullifier_pubkey = owner.nullifier_key.pubkey().unwrap();
        let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], 3).unwrap();
        let nullifier = owner
            .nullifier_key
            .nullifier(&utxo_hash, &utxo.blinding)
            .unwrap();
        let input = WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id: 3,
            leaf_index: 0,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        };
        let seed = [7; 32];
        let output_seed = derive_output_blinding_seed(&nullifier, &seed).unwrap();
        let mut output =
            SppProofOutputUtxo::new(Mint::SOL, 10, owner.shielded_address().unwrap()).unwrap();
        output.ring_program_id = ring;
        output.blinding = derive_transact_output_blinding(&nullifier, &output_seed, 0).unwrap();
        let mut external = ExternalData::new(
            [0; 33],
            [0; 16],
            vec![TransactOutput {
                utxo_hash: output.hash(4).unwrap(),
                owner_tag: OwnerTag::Inline([0; 32]),
                data: None,
            }],
            Vec::new(),
            Vec::new(),
        );
        external.resolved_owner_tags = vec![[0; 32]];
        let mut input_utxos = vec![SppProofInputUtxo::from(input)];
        input_utxos.resize(n_inputs, SppProofInputUtxo::compact(3).unwrap());
        SppProofInputs {
            input_utxos,
            output_utxos: vec![
                output,
                SppProofOutputUtxo {
                    compact: true,
                    blinding: derive_transact_output_blinding(&nullifier, &output_seed, 1).unwrap(),
                    ..Default::default()
                },
            ],
            blinding_seed: seed,
            output_tree_id: 4,
            external_data: external,
            payer: Address::new_from_array([5; 32]),
            cache_accounts: Default::default(),
        }
    }

    fn complete_inputs(transaction: &SppProofInputs) -> Vec<TransferInputUtxo> {
        transaction
            .input_utxos
            .iter()
            .cloned()
            .map(|utxo| {
                let tree = zolana_interface::pda::tree(utxo.tree_id);
                let nullifier = NonInclusionProof {
                    leaf: utxo.nullifier,
                    merkle_context: MerkleContext { tree, tree_type: 2 },
                    path: vec![[0; 32]; 40],
                    low_element: [0; 32],
                    high_element: [0; 32],
                    low_element_index: 0,
                    high_element_index: 1,
                    root: super::super::scalar_one(),
                    root_seq: 0,
                    root_index: 0,
                };
                if utxo.is_compact() {
                    return TransferInputUtxo {
                        utxo,
                        proof: None,
                        nullifier_proof: Some(nullifier),
                    };
                }
                let state = MerkleProof {
                    leaf: utxo.utxo_hash,
                    merkle_context: MerkleContext { tree, tree_type: 1 },
                    path: vec![[0; 32]; 32],
                    leaf_index: 0,
                    root: super::super::scalar_one(),
                    root_seq: 0,
                    root_index: 0,
                };
                TransferInputUtxo {
                    utxo,
                    proof: Some(SpendProof { state, nullifier }),
                    nullifier_proof: None,
                }
            })
            .collect()
    }

    #[test]
    fn ring_output_routing_is_checked_before_authority_or_proving() {
        struct NoAuthority;
        impl ProofAuthority for NoAuthority {
            fn complete_inputs(&self, _: &mut [TransferInput]) -> Result<(), ClientError> {
                panic!("invalid output routing reached the proof authority")
            }
        }
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let ring = Address::new_from_array([9; 32]);
        let mut transaction = fixture(&owner, Some(ring), 2);
        transaction.output_utxos[0].ring_program_id = None;
        let complete = |transaction: SppProofInputs| {
            let shape = transaction.check_shape().unwrap();
            crate::RingTransferProver {
                inputs: complete_inputs(&transaction),
                outputs: transaction.output_utxos.clone(),
                blinding_seed: transaction.blinding_seed,
                output_tree_id: transaction.output_tree_id,
                external_data: transaction.external_data.clone(),
                public_transfers: transaction.public_transfers().unwrap(),
                signer_pk_hashes: transaction.signer_pk_hashes(shape.signer_width()).unwrap(),
                allow_dummy_inputs: true,
                ring_program_id: Some(ring),
                shape,
            }
            .build()
        };
        for amount in [0, 10] {
            transaction.output_utxos[0].amount = amount;
            let indexed = IndexedTransferPreparation {
                transaction: transaction.clone(),
                rail: IndexedTransferRail::Ring(ring),
            }
            .prepare(&NoAuthority);
            assert!(matches!(
                indexed,
                Err(ClientError::Transaction(
                    zolana_transaction::TransactionError::RingOutputMarkerMismatch { index: 0 }
                ))
            ));
            assert!(matches!(
                complete(transaction.clone()),
                Err(ClientError::Transaction(
                    zolana_transaction::TransactionError::RingOutputMarkerMismatch { index: 0 }
                ))
            ));
        }
        let tag = owner.signing_pubkey().confidential_view_tag().unwrap();
        transaction.external_data.outputs[0].owner_tag = OwnerTag::Inline(tag);
        transaction.external_data.resolved_owner_tags[0] = tag;
        transaction.external_data.outputs[0].data = Some(
            borsh::to_vec(&zolana_event::OutputDataEncoding::Encrypted(vec![
                zolana_event::CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
                7,
            ]))
            .unwrap(),
        );
        transaction.external_data.outputs[0].utxo_hash = transaction.output_utxos[0]
            .hash(transaction.output_tree_id)
            .unwrap();
        let mut encoded = complete(transaction.clone()).unwrap().inputs;
        owner.complete_inputs(&mut encoded.inputs).unwrap();
        crate::prover::requests::transfer_ring(&encoded).unwrap();
        for amount in [0, 10] {
            let mut raw = encoded.clone();
            raw.outputs[0].utxo.amount = zolana_hasher::primitives::right_align(&[amount]);
            raw.outputs[0].owner_pk_hash = num_bigint::BigUint::ZERO;
            raw.published_output_owner_pk_hashes[0] = num_bigint::BigUint::ZERO;
            // A forged dummy flag cannot exempt a live UTXO domain.
            raw.outputs[0].is_dummy = num_bigint::BigUint::from(1u8);
            assert!(matches!(
                crate::prover::requests::transfer_ring(&raw),
                Err(ClientError::Transaction(
                    zolana_transaction::TransactionError::RingOutputMarkerMismatch { index: 0 }
                ))
            ));
        }
        let modulus =
            num_bigint::BigUint::from_bytes_be(&zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE);
        for field in 0..3 {
            let mut raw = encoded.clone();
            raw.outputs[0].owner_pk_hash = num_bigint::BigUint::ZERO;
            raw.published_output_owner_pk_hashes[0] = num_bigint::BigUint::ZERO;
            match field {
                0 => {
                    raw.outputs[0].owner_pk_hash = modulus.clone();
                    raw.published_output_owner_pk_hashes[0] = modulus.clone();
                }
                1 => {
                    raw.outputs[0].utxo.ring_program_id =
                        zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE
                }
                _ => {
                    raw.outputs[0].utxo.domain =
                        crate::prover::field::right_align_slice(&(&modulus + 1u8).to_bytes_be())
                            .unwrap()
                }
            }
            assert!(matches!(
                crate::prover::requests::transfer_ring(&raw),
                Err(ClientError::Transaction(
                    zolana_transaction::TransactionError::NonCanonicalField
                ))
            ));
        }
        IndexedTransferPreparation {
            transaction: transaction.clone(),
            rail: IndexedTransferRail::Ring(ring),
        }
        .prepare(&owner)
        .unwrap();
        // Hidden-owner transfers still prohibit default-ring exits even when marked.
        let anonymous = IndexedTransferPreparation {
            transaction,
            rail: IndexedTransferRail::AnonymousRingEd25519 {
                ring,
                owner: &owner.signing_key,
            },
        }
        .prepare(&NoAuthority);
        assert!(matches!(
            anonymous,
            Err(ClientError::AnonymousOutputNotInRing { index: 0 })
        ));
    }

    #[test]
    fn indexed_statements_match_complete_transfer_rails() {
        for (rail, allow_dummy_inputs) in
            (0..4).flat_map(|rail| [true, false].map(|allowed| (rail, allowed)))
        {
            if rail == 0 && !allow_dummy_inputs {
                continue;
            }
            let owner = ShieldedKeypair::new_ed25519().unwrap();
            let ring = (rail != 0).then_some(Address::new_from_array([9; 32]));
            let n_inputs = if rail >= 2 { 2 } else { 1 };
            let transaction = fixture(&owner, ring, n_inputs);
            let shape = transaction.check_shape().unwrap();
            let inputs = complete_inputs(&transaction);
            let public_transfers = transaction.public_transfers().unwrap();
            let signers = transaction.signer_pk_hashes(shape.signer_width()).unwrap();
            let (mode, expected) = match rail {
                0 => {
                    let result = crate::prover::transact::witness::assemble(
                        transaction.clone(),
                        &[inputs[0].proof.clone().unwrap()],
                        &[],
                    )
                    .unwrap();
                    (
                        IndexedTransferRail::Confidential,
                        result.prover_inputs.public_input_hash,
                    )
                }
                1 => {
                    let result = crate::RingTransferProver {
                        inputs,
                        outputs: transaction.output_utxos.clone(),
                        blinding_seed: transaction.blinding_seed,
                        output_tree_id: transaction.output_tree_id,
                        external_data: transaction.external_data.clone(),
                        public_transfers,
                        signer_pk_hashes: signers,
                        allow_dummy_inputs,
                        ring_program_id: ring,
                        shape,
                    }
                    .build()
                    .unwrap();
                    (
                        IndexedTransferRail::Ring(ring.unwrap()),
                        result.inputs.public_input_hash,
                    )
                }
                2 => {
                    let result = crate::RingAuthorityProver {
                        inputs,
                        outputs: transaction.output_utxos.clone(),
                        blinding_seed: transaction.blinding_seed,
                        output_tree_id: transaction.output_tree_id,
                        external_data: transaction.external_data.clone(),
                        public_transfers,
                        payer: transaction.payer,
                        allow_dummy_inputs,
                        ring_program_id: ring,
                        shape,
                    }
                    .build()
                    .unwrap();
                    (
                        IndexedTransferRail::RingAuthority(ring.unwrap()),
                        result.inputs.public_input_hash,
                    )
                }
                3 => {
                    let mut signers = vec![[0; 32]; shape.signer_width()];
                    signers[0] = zolana_hasher::primitives::solana_owner_identity(
                        transaction.payer.as_array(),
                    )
                    .unwrap();
                    let result = crate::prover::transact::AnonymousRingEd25519Prover {
                        inputs,
                        outputs: transaction.output_utxos.clone(),
                        blinding_seed: transaction.blinding_seed,
                        output_tree_id: transaction.output_tree_id,
                        external_data: transaction.external_data.clone(),
                        public_transfers,
                        signer_pk_hashes: signers,
                        allow_dummy_inputs,
                        owner: &owner.signing_key,
                        ring_program_id: ring,
                        shape,
                    }
                    .build()
                    .unwrap();
                    (
                        IndexedTransferRail::AnonymousRingEd25519 {
                            ring: ring.unwrap(),
                            owner: &owner.signing_key,
                        },
                        result.inputs.transfer.public_input_hash,
                    )
                }
                _ => unreachable!(),
            };
            let prepared = IndexedTransferPreparation {
                transaction,
                rail: mode,
            }
            .prepare_with_dummy_policy(&owner, allow_dummy_inputs)
            .unwrap();
            let resolution = super::super::ProofResolution {
                public_input_hash: [0; 32],
                trees: vec![super::super::ResolvedProofTree {
                    tree: zolana_interface::pda::tree(3),
                    id: 3,
                    utxo_root: super::super::scalar_one(),
                    nullifier_root: super::super::scalar_one(),
                    context: TreeContext {
                        utxo_tree_root_index: 0,
                        nullifier_tree_root_index: 0,
                    },
                }],
            };
            assert_eq!(
                resolution
                    .hash(&prepared.request.data.public_inputs)
                    .unwrap(),
                crate::prover::field::right_align_slice(&expected.to_bytes_be()).unwrap(),
                "rail {rail}"
            );
        }
    }
    #[test]
    fn indexed_anonymous_authorization_hides_owner_and_binds_the_external_statement() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let ring = Address::new_from_array([9; 32]);
        let transaction = fixture(&owner, Some(ring), 2);
        let prepare = |transaction| {
            IndexedTransferPreparation {
                transaction,
                rail: IndexedTransferRail::AnonymousRingEd25519 {
                    ring,
                    owner: &owner.signing_key,
                },
            }
            .prepare(&owner)
        };
        let prepared = prepare(transaction.clone()).unwrap();
        let witness: serde_json::Value =
            serde_json::from_str(&prepared.request.data.witness).unwrap();
        assert_eq!(witness["circuitType"], "transfer-ed25519-ring");
        // Go rejects even zero-filled published owner vectors on the anonymous rail.
        assert_eq!(
            witness["publishedOutputOwnerPkHashes"],
            serde_json::json!([])
        );
        assert_eq!(witness["inputs"][0]["ownerPkHash"], "0x0");
        let signers = witness["signerPkHashes"].as_array().unwrap();
        assert_eq!(
            signers.len(),
            transaction.check_shape().unwrap().signer_width()
        );
        assert!(signers[1..]
            .iter()
            .all(|signer| signer == &hex_field(&[0; 32])));
        assert_eq!(
            witness["signerPkHashes"][0],
            hex_field(
                &zolana_hasher::primitives::solana_owner_identity(transaction.payer.as_array())
                    .unwrap()
            )
        );
        assert_eq!(prepared.request.data.public_inputs.len(), 19);
        let digest = zolana_transaction::instructions::transact::transact_message_hash(
            &prepared.private_tx_hash(),
            &transaction.external_data.hash().unwrap(),
        );
        let signature = hex::decode(
            witness["ownerSignature"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let signature: [u8; 64] = signature.try_into().unwrap();
        assert!(owner.signing_pubkey().verify_message(&digest, &signature));
        let mut changed = transaction.clone();
        changed.external_data.expiry_unix_ts -= 1;
        let changed = prepare(changed).unwrap();
        let changed_witness: serde_json::Value =
            serde_json::from_str(&changed.request.data.witness).unwrap();
        assert_ne!(witness["ownerSignature"], changed_witness["ownerSignature"]);
        let mut cached = transaction.clone();
        cached.cache_accounts.write = Some(Address::new_from_array([12; 32]));
        cached.output_utxos[0].cache_slot = Some(3);
        assert!(prepare(cached).is_err());
        let mut outside = transaction;
        outside.output_utxos[0].ring_program_id = None;
        assert!(matches!(
            prepare(outside),
            Err(ClientError::AnonymousOutputNotInRing { index: 0 })
        ));
    }
}
