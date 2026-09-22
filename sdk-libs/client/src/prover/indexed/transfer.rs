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
        verify::ConfidentialProofStatement,
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

pub struct PreparedIndexedTransfer {
    request: IndexedProofRequest,
    data: TransactIxData,
    n_inputs: usize,
    n_outputs: usize,
}

pub struct ProvenIndexedTransfer {
    pub input_tree_ids: Vec<u16>,
    pub data: TransactIxData,
    pub public_input_hash: [u8; 32],
    pub proof: ProofCompressed,
}

impl PreparedIndexedTransfer {
    pub fn new(
        transaction: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<Self, ClientError> {
        let shape = transaction.check_shape()?;
        if inputs_require_p256(&transaction.input_utxos)? {
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
            let owner = if input.is_dummy() {
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
                commitment: (!input.is_dummy()).then_some(hash),
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
        let external_hash = transaction.external_data.hash()?;
        let blinding = derive_private_tx_blinding(first, &transaction.blinding_seed)?;
        let private_tx = PrivateTxHash::new(
            &input_hashes,
            &outputs.private_tx_output_hashes,
            &external_hash,
            &blinding,
        )
        .hash()?;
        let movements = transaction.public_transfers()?;
        let signers = transaction.signer_pk_hashes(shape.signer_width())?;
        let flags = pack_input_flags(true, indexes.iter().copied())?;
        let public_inputs = PublicInputs {
            nullifiers: &nullifiers,
            output_hashes: &outputs.output_hashes,
            tree_slots: (),
            output_tree_id: transaction.output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_hash,
            public_transfers: &movements,
            ring_program_id: &[0; 32],
            input_flags: &flags,
            signer_pk_hashes: &signers,
            output_owner_pk_hashes: Some(&outputs.output_owner_pk_hashes),
        }
        .without_roots(&[])?;
        let prepared = PreparedTransferJson {
            circuit_type: IndexedCircuit::TransferConfidential,
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
            ring_program_id: "0x0",
            signer_pk_hashes: signers.iter().map(hex_field).collect(),
            input_flags: hex_field(&flags),
            published_output_owner_pk_hashes: outputs
                .output_owner_pk_hashes
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
            circuit: CircuitId::ConfidentialEddsa(
                u8::try_from(shape.n_inputs()).map_err(|_| super::invalid())?,
                u8::try_from(shape.n_outputs()).map_err(|_| super::invalid())?,
                u8::try_from(N_PUBLIC_SLOTS).map_err(|_| super::invalid())?,
            ),
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
        Ok(Self {
            request,
            data,
            n_inputs: shape.n_inputs(),
            n_outputs: shape.n_outputs(),
        })
    }

    #[must_use]
    pub fn with_min_context_slot(mut self, slot: u64) -> Self {
        self.request = self.request.with_min_context_slot(slot);
        self
    }

    pub fn request(&self) -> &IndexedProofRequest {
        &self.request
    }

    pub fn finish(mut self, proof: IndexedProof) -> Result<ProvenIndexedTransfer, ClientError> {
        let proof = self.request.validate(proof)?;
        let public_input_hash = proof.resolution.public_input_hash;
        // 2. Verify the resolved statement before exposing transaction bytes.
        ConfidentialProofStatement {
            n_inputs: self.n_inputs,
            n_outputs: self.n_outputs,
            public_input_hash,
        }
        .verify(&proof.proof)?;
        self.data.tree_contexts = proof
            .resolution
            .trees
            .iter()
            .map(|tree| tree.context)
            .collect();
        let input_tree_ids = proof.resolution.trees.iter().map(|tree| tree.id).collect();
        let proof = ProofCompressed::try_from(proof.proof)?;
        self.data.proof = proof.to_transact_proof();
        Ok(ProvenIndexedTransfer {
            input_tree_ids,
            data: self.data,
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
    circuit_type: IndexedCircuit,
    n_inputs: usize,
    n_outputs: usize,
    inputs: Vec<PreparedInputJson>,
    outputs: Vec<OutputParamsJson>,
    output_tree_id: String,
    blinding_seed: SecretField,
    external_data_hash: String,
    private_tx_hash: String,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    ring_program_id: &'static str,
    signer_pk_hashes: Vec<String>,
    input_flags: String,
    published_output_owner_pk_hashes: Vec<String>,
}
