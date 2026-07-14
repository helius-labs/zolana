use zolana_interface::instruction::instruction_data::transact::{
    InputUtxo, TransactIxData, TransactProof,
};
use zolana_keypair::SignatureType;
use zolana_transaction::instructions::transact::{inputs_require_p256, SppProofInputs};

use crate::{
    error::ClientError,
    prover::{
        shape::Shape,
        transact::{
            eddsa::TransferProver,
            p256_and_eddsa::{P256Owner, PublicAmounts, TransferP256Prover, TransferSpendInput},
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

pub enum CircuitType {
    P256(TransferP256Prover),
    Eddsa(TransferProver),
}

/// A built circuit ready to hand to the prover client.
pub struct BuiltCircuit {
    pub circuit: CircuitType,
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
    ) -> Result<TransactIxData, ClientError> {
        let assembled = assemble(proof_inputs, input_proofs)?;
        let proof = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => self.prove_transfer_p256(inputs)?,
            ProverInputs::Eddsa(inputs) => self.prove_transfer(inputs)?,
        };
        Ok(assembled.with_proof(ProofCompressed::try_from(proof)?.to_transact_proof()))
    }
}

fn client_shape(shape: zolana_transaction::instructions::transact::Shape) -> Shape {
    Shape::new(shape.n_inputs(), shape.n_outputs())
}

fn client_public_amounts(
    amounts: zolana_transaction::instructions::transact::PublicAmounts,
) -> PublicAmounts {
    PublicAmounts {
        sol: amounts.sol,
        spl: amounts.spl,
        asset: amounts.asset,
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
) -> Result<BuiltCircuit, ClientError> {
    let requires_p256 = inputs_require_p256(&proof_inputs.input_utxos)?;
    let p256_owner = if requires_p256 {
        Some(p256_owner(&proof_inputs)?)
    } else {
        None
    };
    let SppProofInputs {
        input_utxos: inputs,
        output_utxos: outputs,
        public_amounts,
        external_data,
        payer_pubkey_hash,
        shape,
        ..
    } = proof_inputs;

    let mut spends = Vec::with_capacity(inputs.len());
    let mut real_index = 0;
    for spend in inputs {
        let utxo = spend.utxo;
        let nullifier_key = spend.nullifier_key;
        let data_hash = spend.data_hash;
        let zone_data_hash = spend.zone_data_hash;
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
            data_hash,
            zone_data_hash,
            proof,
        });
    }

    let shape = client_shape(shape);
    let public_amounts = client_public_amounts(public_amounts);

    let circuit = if requires_p256 {
        let p256_owner = p256_owner.ok_or(ClientError::MissingP256Signature)?;
        CircuitType::P256(TransferP256Prover {
            inputs: spends,
            outputs,
            external_data,
            public_amounts,
            payer_pubkey_hash,
            p256_owner,
            shape: Some(shape),
        })
    } else {
        CircuitType::Eddsa(TransferProver {
            inputs: spends,
            outputs,
            external_data,
            public_amounts,
            payer_pubkey_hash,
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
) -> Result<AssembledTransfer, ClientError> {
    let shape = proof_inputs.shape;

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
        relayer_fee,
        public_sol_amount,
        public_spl_amount,
        data_hash,
        zone_data_hash,
        tx_viewing_pk,
        salt,
        outputs,
        messages,
        ..
    } = proof_inputs.external_data.clone();

    let BuiltCircuit { circuit } = into_prover(proof_inputs, input_proofs)?;

    let (prover_inputs, public_input_hash, nullifiers, private_tx, root_indices, p256_signing_pk_x) =
        match circuit {
            CircuitType::P256(prover) => {
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
            CircuitType::Eddsa(prover) => {
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
        relayer_fee,
        private_tx_hash: private_tx,
        p256_signing_pk_x,
        inputs,
        public_sol_amount,
        public_spl_amount,
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
