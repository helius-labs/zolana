use super::{
    hex_field, IndexedCircuit, IndexedLookup, IndexedProof, IndexedProofData, IndexedProofRequest,
    IndexedTree,
};
use crate::{
    authority::ProofAuthority,
    prover::{
        field::{be, right_align_slice},
        json::{output_to_json, utxo_to_json, OutputParamsJson, UtxoParamsJson},
        transact::assembly::{assemble_outputs, input_utxos_from_nullifiers, PublicInputs},
        verify::TransferProofStatement,
        ProofCompressed, ProofInputUtxo, TransferInput,
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
    instructions::transact::{
        inputs_require_p256, validate_input_tree_order, PrivateTxHash, SppProofInputs,
    },
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
};

pub enum IndexedTransferRail {
    Confidential,
    Ring(solana_address::Address),
    RingAuthority(solana_address::Address),
    RingP256 {
        ring: solana_address::Address,
        authorization: zolana_transaction::P256Signature,
    },
}

pub struct IndexedTransferPreparation {
    pub transaction: SppProofInputs,
    pub rail: IndexedTransferRail,
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

impl IndexedTransferPreparation {
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
                .position(|input| input.is_dummy())
            {
                return Err(ClientError::NonSpendInputNotAllowed { index });
            }
        }
        let shape = transaction.check_shape()?;
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
        let ring = match &rail {
            IndexedTransferRail::Confidential => None,
            IndexedTransferRail::Ring(ring)
            | IndexedTransferRail::RingAuthority(ring)
            | IndexedTransferRail::RingP256 { ring, .. } => Some(*ring),
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
        if !authority_rail
            && !matches!(rail, IndexedTransferRail::RingP256 { .. })
            && inputs_require_p256(&transaction.input_utxos)?
        {
            return Err(ClientError::P256TransactUnsupported);
        }
        validate_input_tree_order(transaction.input_utxos.iter().map(|input| input.tree_id))?;
        let mut trees: Vec<IndexedTree> = Vec::new();
        let mut lookups = Vec::new();
        let mut local_inputs = Vec::new();
        let mut input_hashes = Vec::new();
        let mut nullifiers = Vec::new();
        let mut indexes = Vec::new();
        for input in &transaction.input_utxos {
            if trees.last().is_none_or(|tree| tree.id != input.tree_id) {
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
            }
            let tree_slot = u8::try_from(trees.len() - 1).map_err(|_| ClientError::NoInputs)?;
            let utxo = ProofInputUtxo::try_from(input)?;
            let hash = utxo.hash()?;
            let nullifier = input.nullifier;
            if hash != input.utxo_hash {
                return Err(
                    zolana_transaction::TransactionError::InputCommitmentMismatch {
                        index: local_inputs.len(),
                    }
                    .into(),
                );
            }
            let owner = if input.is_dummy()
                || (matches!(rail, IndexedTransferRail::RingP256 { .. })
                    && input.utxo.owner.curve()? == zolana_keypair::Curve::P256)
            {
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
        let private_tx = PrivateTxHash::new(
            &input_hashes,
            &outputs.private_tx_output_hashes,
            &external_hash,
            &blinding,
        )
        .hash()?;
        let movements = transaction.public_transfers()?;
        let signers = if authority_rail {
            vec![zolana_hasher::primitives::solana_owner_identity(
                transaction.payer.as_array(),
            )?]
        } else {
            transaction.signer_pk_hashes(shape.signer_width())?
        };
        let ring_program_id = zolana_transaction::utxo::program_id_proof_input_hash(&ring)?;
        let owners = match rail {
            IndexedTransferRail::Confidential => Some(outputs.output_owner_pk_hashes.clone()),
            IndexedTransferRail::Ring(_) | IndexedTransferRail::RingP256 { .. } => Some(
                crate::prover::transact::assembly::confidential_marked_output_owner_pk_hashes(
                    &transaction.external_data,
                )?,
            ),
            IndexedTransferRail::RingAuthority(_) => None,
        };
        let p256 = match &rail {
            IndexedTransferRail::RingP256 { authorization, .. } => Some(
                crate::prover::transact::ring_p256::P256AuthorizationPreparation {
                    inputs: &proof_inputs,
                    authorization,
                    private_tx: &private_tx,
                    published_owners: owners.as_deref().unwrap_or_default(),
                }
                .prepare()?,
            ),
            _ => None,
        };
        let appendix = p256
            .as_ref()
            .map(|auth| {
                Ok::<_, ClientError>([
                    zolana_hasher::primitives::hash_bytes(&auth.message_digest)?,
                    auth.default_p256_owner_pk_hash,
                ])
            })
            .transpose()?;
        let flags = pack_input_flags(allow_dummy_inputs, indexes.iter().copied())?;
        let public_inputs = PublicInputs {
            nullifiers: &nullifiers,
            output_hashes: &outputs.output_hashes,
            tree_slots: (),
            output_tree_id: transaction.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_hash,
            public_transfers: &movements,
            ring_program_id: &ring_program_id,
            input_flags: &flags,
            signer_pk_hashes: &signers,
            output_owner_pk_hashes: owners.as_deref(),
            cached_inputs: cache.public_fields,
        }
        .without_roots(appendix.as_ref().map_or(&[], |fields| fields.as_slice()))?;
        let prepared = PreparedTransferJson {
            p256: match (&rail, &p256) {
                (IndexedTransferRail::RingP256 { authorization, .. }, Some(auth)) => {
                    Some(PreparedP256Json {
                        p256_pub_x: hex_field(&auth.pub_x),
                        p256_pub_y: hex_field(&auth.pub_y),
                        p256_sig_r: hex_field(&authorization.sig_r),
                        p256_sig_s: hex_field(&authorization.sig_s),
                        p256_message_hash_low: hex_field(&right_align_slice(
                            &auth.message_digest[16..],
                        )?),
                        p256_message_hash_high: hex_field(&right_align_slice(
                            &auth.message_digest[..16],
                        )?),
                        default_p256_owner_pk_hash: hex_field(&auth.default_p256_owner_pk_hash),
                    })
                }
                _ => None,
            },
            circuit_type: match rail {
                IndexedTransferRail::Confidential => IndexedCircuit::TransferConfidential,
                IndexedTransferRail::Ring(_) => IndexedCircuit::TransferRing,
                IndexedTransferRail::RingAuthority(_) => IndexedCircuit::TransferRingAuthority,
                IndexedTransferRail::RingP256 { .. } => IndexedCircuit::TransferP256Ring,
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
            public_assets: movements.assets.iter().map(hex_field).collect(),
            public_amounts: movements.amounts.iter().map(hex_field).collect(),
            ring_program_id: hex_field(&ring_program_id),
            signer_pk_hashes: signers.iter().map(hex_field).collect(),
            input_flags: hex_field(&flags),
            cache: super::super::json::cache_reads_to_json(&cache.proof_inputs),
            published_output_owner_pk_hashes: owners
                .as_deref()
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
                        Some(access) => CircuitId::ConfidentialEddsaCached(n_in, n_out, slots, access),
                        None => CircuitId::ConfidentialEddsa(n_in, n_out, slots),
                    },
                    IndexedTransferRail::Ring(_) => match cache.access {
                        Some(access) => CircuitId::RingEddsaCached(n_in, n_out, slots, access),
                        None => CircuitId::RingEddsa(n_in, n_out, slots),
                    },
                    IndexedTransferRail::RingAuthority(_) => CircuitId::RingAuthority(n_in, n_out, slots),
                    IndexedTransferRail::RingP256 { .. } => {
                        let auth = p256.as_ref().ok_or_else(super::invalid)?;
                        let data = zolana_interface::verifying_keys::RingP256ProofData {
                            default_owner_tag: auth.default_owner_tag,
                            bsb22_commitment: zolana_interface::instruction::instruction_data::transact::Bsb22Commitment { commitment: [0; 32], commitment_pok: [0; 32] },
                        };
                        match cache.access {
                            Some(access) => CircuitId::RingP256Cached(n_in, n_out, slots, data, access),
                            None => CircuitId::RingP256(n_in, n_out, slots, data),
                        }
                    }
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

    pub fn request(&self) -> &IndexedProofRequest {
        &self.request
    }

    pub fn private_tx_hash(&self) -> [u8; 32] {
        self.data.private_tx_hash
    }

    pub fn finish(&self, proof: IndexedProof) -> Result<ProvenIndexedTransfer, ClientError> {
        let proof = self.request.validate(proof)?;
        let mut data = self.data.clone();
        let public_input_hash = proof.resolution.public_input_hash;
        // 2. Verify the resolved statement before exposing transaction bytes.
        TransferProofStatement {
            circuit: data.circuit,
            public_input_hash,
        }
        .verify(&proof.proof)?;
        data.tree_contexts = proof
            .resolution
            .trees
            .iter()
            .map(|tree| tree.context)
            .collect();
        let input_tree_ids = proof.resolution.trees.iter().map(|tree| tree.id).collect();
        let proof = ProofCompressed::try_from(proof.proof)?;
        match &mut data.circuit {
            CircuitId::RingP256(_, _, _, authorization)
            | CircuitId::RingP256Cached(_, _, _, authorization, _) => {
                let (transact, commitment) = proof.into_ring_p256_transact_parts()?;
                data.proof = transact;
                authorization.bsb22_commitment = commitment;
            }
            _ => data.proof = proof.to_transact_proof(),
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
    #[serde(flatten)]
    p256: Option<PreparedP256Json>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedP256Json {
    p256_pub_x: String,
    p256_pub_y: String,
    p256_sig_r: String,
    p256_sig_s: String,
    p256_message_hash_low: String,
    p256_message_hash_high: String,
    default_p256_owner_pk_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MerkleContext, MerkleProof, NonInclusionProof, SpendProof, TransferInputUtxo};
    use solana_address::Address;
    use zolana_interface::instruction::{OwnerTag, TransactOutput, TreeContext};
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{
        Data, ExternalData, Mint, P256Signature, SppProofOutputUtxo, Utxo, WalletUtxo,
    };

    fn fixture(owner: &ShieldedKeypair, ring: Option<Address>) -> SppProofInputs {
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
        SppProofInputs {
            input_utxos: vec![input.into()],
            output_utxos: vec![output],
            blinding_seed: seed,
            output_tree_id: 4,
            external_data: external,
            payer: Address::new_from_array([5; 32]),
            cache_accounts: Default::default(),
        }
    }

    fn authorization(transaction: &SppProofInputs, owner: &ShieldedKeypair) -> P256Signature {
        let signature = owner
            .sign_hash(&transaction.message_hash().unwrap())
            .unwrap();
        P256Signature {
            pubkey: owner.signing_pubkey().as_p256().unwrap(),
            sig_r: signature[..32].try_into().unwrap(),
            sig_s: signature[32..].try_into().unwrap(),
        }
    }

    fn complete_inputs(transaction: &SppProofInputs) -> Vec<TransferInputUtxo> {
        transaction
            .input_utxos
            .iter()
            .cloned()
            .map(|utxo| {
                let tree = zolana_interface::pda::tree(utxo.tree_id);
                let state = MerkleProof {
                    leaf: utxo.utxo_hash,
                    merkle_context: MerkleContext { tree, tree_type: 1 },
                    path: vec![[0; 32]; 32],
                    leaf_index: 0,
                    root: super::super::scalar_one(),
                    root_seq: 0,
                    root_index: 0,
                };
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
                TransferInputUtxo {
                    utxo,
                    proof: Some(SpendProof { state, nullifier }),
                    nullifier_proof: None,
                }
            })
            .collect()
    }

    #[test]
    fn indexed_statements_match_complete_transfer_rails() {
        for (rail, allow_dummy_inputs) in
            (0..4).flat_map(|rail| [true, false].map(|allowed| (rail, allowed)))
        {
            if rail == 0 && !allow_dummy_inputs {
                continue;
            }
            let owner = if rail == 3 {
                ShieldedKeypair::new_p256().unwrap()
            } else {
                ShieldedKeypair::new_ed25519().unwrap()
            };
            let ring = (rail != 0).then_some(Address::new_from_array([9; 32]));
            let transaction = fixture(&owner, ring);
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
                _ => {
                    let authorization = authorization(&transaction, &owner);
                    let result = crate::RingTransferP256Prover {
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
                        authorization,
                    }
                    .build()
                    .unwrap();
                    (
                        IndexedTransferRail::RingP256 {
                            ring: ring.unwrap(),
                            authorization,
                        },
                        result.inputs.public_input_hash,
                    )
                }
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
    fn p256_signature_binds_cache_write_address_and_slot() {
        let owner = ShieldedKeypair::new_p256().unwrap();
        let ring = Address::new_from_array([9; 32]);
        let mut transaction = fixture(&owner, Some(ring));
        transaction.cache_accounts.write = Some(Address::new_from_array([12; 32]));
        transaction.output_utxos[0].cache_slot = Some(3);
        let authorization = authorization(&transaction, &owner);
        let prepare = |transaction| {
            IndexedTransferPreparation {
                transaction,
                rail: IndexedTransferRail::RingP256 {
                    ring,
                    authorization,
                },
            }
            .prepare(&owner)
        };
        assert!(prepare(transaction.clone()).is_ok());
        let mut changed = transaction.clone();
        changed.cache_accounts.write = Some(Address::new_from_array([13; 32]));
        assert!(matches!(
            prepare(changed),
            Err(ClientError::InvalidP256Authorization(_))
        ));
        transaction.output_utxos[0].cache_slot = Some(4);
        assert!(matches!(
            prepare(transaction),
            Err(ClientError::InvalidP256Authorization(_))
        ));
    }
}
