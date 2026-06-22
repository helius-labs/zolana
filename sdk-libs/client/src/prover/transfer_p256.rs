use num_bigint::BigUint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use zolana_keypair::hash::{hash_field, owner_hash, sha256, split_be_128};
use zolana_keypair::{NullifierKey, P256Pubkey, SignatureType};
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::{ExternalData, OutputUtxo, Utxo};

use crate::error::ClientError;
use crate::private_transaction::field::{be, hash_chain, right_align_slice};
use crate::private_transaction::transaction::SpendProof;
use crate::prover::shape::{resolve_shape, Shape};
use crate::prover::{TransferInput, TransferOutput, TransferP256Inputs, UtxoInputs};
use crate::rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT};
use crate::wallet_authority::ScopedSpendWitness;

pub struct TransferSpendInput {
    pub utxo: Utxo,
    pub witness: ScopedSpendWitness,
    pub nullifier_key: Option<NullifierKey>,
    /// `Some` for a real spend, `None` for a padding (dummy) slot. A dummy mirrors
    /// the first real input's roots, so it has no proof of its own.
    pub proof: Option<SpendProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAmounts {
    pub sol: [u8; 32],
    pub spl: [u8; 32],
    pub asset: [u8; 32],
}

impl PublicAmounts {
    pub fn transfer() -> Self {
        Self {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        }
    }
}
/// The P256 ownership signature, computed once over the finalized transaction in
/// [`crate::private_transaction::Transaction::sign`]. The prover only converts it
/// into witness coordinates; it never signs.
#[derive(Clone)]
pub struct P256Owner {
    pub pubkey: P256Pubkey,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

pub struct TransferP256Prover {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<OutputUtxo>,
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    pub p256_owner: P256Owner,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct TransferP256ProofResult {
    pub inputs: TransferP256Inputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub input_root_indices: Vec<(u16, u16)>,
}

impl TransferP256Prover {
    pub fn build(self) -> Result<TransferP256ProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        let assembled_inputs = assemble_inputs(&self.inputs, true)?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )?;
        let p256_message_hash = sha256(&private_tx);
        let signature = self.p256_owner.witness()?;
        let (p256_message_low, p256_message_high) = split_be_128(&p256_message_hash);
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            utxo_roots: &assembled_inputs.utxo_roots,
            nullifier_tree_roots: &assembled_inputs.nullifier_tree_roots,
            private_tx: &private_tx,
            p256_message_hash: &p256_message_hash,
            external_data_hash: &external_data_hash,
            public_amounts: &self.public_amounts,
            payer_pubkey_hash: &self.payer_pubkey_hash,
            solana_owner_pk_hashes: &assembled_inputs.solana_owner_pk_hashes,
        }
        .hash()?;

        let inputs = TransferP256Inputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            p256_pub_x: be(&signature.pub_x),
            p256_pub_y: be(&signature.pub_y),
            p256_sig_r: be(&signature.sig_r),
            p256_sig_s: be(&signature.sig_s),
            private_tx_hash: be(&private_tx),
            p256_message_hash_low: be(&p256_message_low),
            p256_message_hash_high: be(&p256_message_high),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            program_id_hashchain: BigUint::ZERO,
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            data_hash: BigUint::ZERO,
            zone_data_hash: BigUint::ZERO,
            public_input_hash: be(&public_input),
        };

        Ok(TransferP256ProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
        })
    }
}

struct P256SignatureWitness {
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
}

impl P256Owner {
    fn witness(&self) -> Result<P256SignatureWitness, ClientError> {
        let public_key = self.pubkey.to_p256()?;
        let point = public_key.to_encoded_point(false);
        let (pub_x, pub_y) = encoded_xy(&point)?;
        Ok(P256SignatureWitness {
            pub_x,
            pub_y,
            sig_r: self.sig_r,
            sig_s: self.sig_s,
        })
    }
}

fn encoded_xy(point: &p256::EncodedPoint) -> Result<([u8; 32], [u8; 32]), ClientError> {
    let x = point
        .x()
        .ok_or_else(|| ClientError::P256Signature("missing x coordinate".into()))?;
    let y = point
        .y()
        .ok_or_else(|| ClientError::P256Signature("missing y coordinate".into()))?;
    let mut pub_x = [0u8; 32];
    let mut pub_y = [0u8; 32];
    pub_x.copy_from_slice(x);
    pub_y.copy_from_slice(y);
    Ok((pub_x, pub_y))
}

pub(crate) struct AssembledInputs {
    pub inputs: Vec<TransferInput>,
    pub input_hashes: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
    pub utxo_roots: Vec<[u8; 32]>,
    pub nullifier_tree_roots: Vec<[u8; 32]>,
    pub solana_owner_pk_hashes: Vec<[u8; 32]>,
    /// Per-slot `(utxo_tree_root_index, nullifier_tree_root_index)`, length
    /// `n_inputs`. Real slots take the index from their `SpendProof`; padded
    /// dummy slots mirror the first real input so the on-chain root lookup
    /// reproduces the witness root.
    pub root_indices: Vec<(u16, u16)>,
}

pub(crate) struct AssembledOutputs {
    pub outputs: Vec<TransferOutput>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_output_hashes: Vec<[u8; 32]>,
}

/// Convert the already-padded inputs into circuit witness fields. Makes no padding
/// decisions: each slot with a [`SpendProof`] is a real spend; each slot without one
/// is a dummy that mirrors the first real input's roots, indices, and owner hash so
/// the public-input chain and the on-chain root lookup agree. A transaction must
/// spend at least one real input to supply those roots.
pub(crate) fn assemble_inputs(
    spends: &[TransferSpendInput],
    allow_p256: bool,
) -> Result<AssembledInputs, ClientError> {
    let mut inputs = Vec::with_capacity(spends.len());
    let mut input_hashes = Vec::with_capacity(spends.len());
    let mut nullifiers = Vec::with_capacity(spends.len());
    let mut utxo_roots = Vec::with_capacity(spends.len());
    let mut nullifier_tree_roots = Vec::with_capacity(spends.len());
    let mut solana_owner_pk_hashes = Vec::with_capacity(spends.len());
    let mut root_indices = Vec::with_capacity(spends.len());

    for (index, spend) in spends.iter().enumerate() {
        let Some(proof) = &spend.proof else {
            let utxo_root = *utxo_roots.first().ok_or(ClientError::NoInputs)?;
            let nf_root = *nullifier_tree_roots.first().ok_or(ClientError::NoInputs)?;
            let owner = *solana_owner_pk_hashes
                .first()
                .ok_or(ClientError::NoInputs)?;
            let &(ur_index, nr_index) = root_indices.first().ok_or(ClientError::NoInputs)?;
            let (input, nullifier) =
                TransferInput::new_dummy(&spend.utxo.blinding, &utxo_root, &nf_root, &owner)?;
            inputs.push(input);
            input_hashes.push([0u8; 32]);
            nullifiers.push(nullifier);
            utxo_roots.push(utxo_root);
            nullifier_tree_roots.push(nf_root);
            solana_owner_pk_hashes.push(owner);
            root_indices.push((ur_index, nr_index));
            continue;
        };

        let nullifier_pubkey = match &spend.nullifier_key {
            Some(key) => key.pubkey()?,
            None => spend.witness.nullifier_pubkey,
        };
        let owner_field = owner_hash(&spend.utxo.owner, &nullifier_pubkey)?;
        let utxo_inputs = UtxoInputs::new(
            &owner_field,
            &spend.utxo.asset,
            spend.utxo.amount,
            &spend.utxo.blinding,
        )?;
        let utxo_hash = spend.utxo.hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])?;
        let nullifier = match &spend.nullifier_key {
            Some(key) => key.nullifier(&utxo_hash, &spend.utxo.blinding)?,
            None => spend.witness.nullifier,
        };

        let is_p256 = spend.utxo.owner.signature_type()? == SignatureType::P256;
        let solana_owner_pk_hash = if is_p256 {
            if !allow_p256 {
                return Err(ClientError::EddsaInputNotSolanaOwned { index });
            }
            [0u8; 32]
        } else {
            spend.utxo.owner.hash()?
        };

        let nullifier_secret = match &spend.nullifier_key {
            Some(key) => right_align_slice(key.secret())?,
            None => right_align_slice(&spend.witness.nullifier_secret)?,
        };
        let state = &proof.state;
        let nf = &proof.nullifier;
        check_path_length(state.path.len(), STATE_TREE_HEIGHT)?;
        check_path_length(nf.path.len(), NULLIFIER_TREE_HEIGHT)?;

        inputs.push(TransferInput {
            utxo: utxo_inputs,
            is_dummy: BigUint::ZERO,
            state_path_elements: state.path.iter().map(be).collect(),
            state_path_index: BigUint::from(state.leaf_index),
            nullifier_low_value: be(&nf.low_element),
            nullifier_next_value: be(&nf.high_element),
            nullifier_low_path_elements: nf.path.iter().map(be).collect(),
            nullifier_low_path_index: BigUint::from(nf.low_element_index),
            utxo_tree_root: be(&state.root),
            nullifier_tree_root: be(&nf.root),
            nullifier: be(&nullifier),
            solana_owner_pk_hash: be(&solana_owner_pk_hash),
            nullifier_secret: be(&nullifier_secret),
        });
        input_hashes.push(utxo_hash);
        nullifiers.push(nullifier);
        utxo_roots.push(state.root);
        nullifier_tree_roots.push(nf.root);
        solana_owner_pk_hashes.push(solana_owner_pk_hash);
        root_indices.push((state.root_index, nf.root_index));
    }

    Ok(AssembledInputs {
        inputs,
        input_hashes,
        nullifiers,
        utxo_roots,
        nullifier_tree_roots,
        solana_owner_pk_hashes,
        root_indices,
    })
}

/// Convert the already-padded outputs into circuit witness fields. A dummy output
/// (`owner_hash == 0`: empty change or tail padding) still puts its real hash in the
/// public `output_hashes` but contributes `0` to the private-tx hash chain.
pub(crate) fn assemble_outputs(outputs: &[OutputUtxo]) -> Result<AssembledOutputs, ClientError> {
    let mut assembled = Vec::with_capacity(outputs.len());
    let mut hashes = Vec::with_capacity(outputs.len());
    let mut private_tx_hashes = Vec::with_capacity(outputs.len());

    for output in outputs {
        let is_dummy = output.is_dummy();
        let hash = output.hash()?;
        assembled.push(TransferOutput {
            utxo: UtxoInputs::from_output(output)?,
            is_dummy: if is_dummy {
                BigUint::from(1u8)
            } else {
                BigUint::ZERO
            },
            hash: be(&hash),
        });
        hashes.push(hash);
        private_tx_hashes.push(if is_dummy { [0u8; 32] } else { hash });
    }

    Ok(AssembledOutputs {
        outputs: assembled,
        output_hashes: hashes,
        private_tx_output_hashes: private_tx_hashes,
    })
}

pub(crate) struct PublicInputs<'a> {
    pub nullifiers: &'a [[u8; 32]],
    pub output_hashes: &'a [[u8; 32]],
    pub utxo_roots: &'a [[u8; 32]],
    pub nullifier_tree_roots: &'a [[u8; 32]],
    pub private_tx: &'a [u8; 32],
    pub p256_message_hash: &'a [u8; 32],
    pub external_data_hash: &'a [u8; 32],
    pub public_amounts: &'a PublicAmounts,
    pub payer_pubkey_hash: &'a [u8; 32],
    pub solana_owner_pk_hashes: &'a [[u8; 32]],
}

impl PublicInputs<'_> {
    pub(crate) fn hash(&self) -> Result<[u8; 32], ClientError> {
        let elements = [
            hash_chain(self.nullifiers)?,
            hash_chain(self.output_hashes)?,
            hash_chain(self.utxo_roots)?,
            hash_chain(self.nullifier_tree_roots)?,
            *self.private_tx,
            hash_field(self.p256_message_hash)?,
            *self.external_data_hash,
            self.public_amounts.sol,
            self.public_amounts.spl,
            self.public_amounts.asset,
            [0u8; 32],
            *self.payer_pubkey_hash,
            [0u8; 32],
            [0u8; 32],
            hash_chain(self.solana_owner_pk_hashes)?,
        ];
        hash_chain(&elements)
    }
}
fn check_path_length(got: usize, expected: usize) -> Result<(), ClientError> {
    if got == expected {
        Ok(())
    } else {
        Err(ClientError::ProofPathLength { got, expected })
    }
}
