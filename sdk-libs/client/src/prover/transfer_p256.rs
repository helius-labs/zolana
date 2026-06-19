use num_bigint::BigUint;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use zolana_keypair::hash::{hash_field, owner_hash, sha256, sha256_be, split_be_128};
use zolana_keypair::{NullifierKey, P256Pubkey, SignatureType};
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::{ExternalData, OutputUtxo, Utxo};

use crate::error::ClientError;
use crate::private_transaction::field::{be, hash_chain, right_align_slice};
use crate::prover::shape::{resolve_shape, Shape};
use crate::prover::{TransferInput, TransferOutput, TransferP256Inputs, UtxoInputs};
use crate::rpc::{NullifierNonInclusionProof, StateInclusionProof};

pub struct TransferSpendInput {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub state_proof: StateInclusionProof,
    pub nullifier_proof: NullifierNonInclusionProof,
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
// Why does this exist? What does Precomputed mean?
#[derive(Clone)]
pub enum P256Owner {
    Signer(SigningKey),
    Precomputed {
        pubkey: P256Pubkey,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    },
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
}

impl TransferP256Prover {
    pub fn build(self) -> Result<TransferP256ProofResult, ClientError> {
        let shape = resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        let assembled_inputs = assemble_inputs(&self.inputs, shape, true)?;
        let assembled_outputs = assemble_outputs(&self.outputs, shape)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.output_hashes,
            &external_data_hash,
        )?;
        let p256_message_hash = sha256(&private_tx);
        let signature = self.p256_owner.witness(&p256_message_hash)?;
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
            program_id_hashchain: zero(),
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            data_hash: zero(),
            zone_data_hash: zero(),
            public_input_hash: be(&public_input),
        };

        Ok(TransferP256ProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
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
    fn witness(&self, message_hash: &[u8; 32]) -> Result<P256SignatureWitness, ClientError> {
        match self {
            P256Owner::Signer(signing_key) => {
                let point = signing_key.verifying_key().to_encoded_point(false);
                let (pub_x, pub_y) = encoded_xy(&point)?;
                let signature: Signature = signing_key
                    .sign_prehash(message_hash)
                    .map_err(|e| ClientError::P256Signature(e.to_string()))?;
                let bytes = signature.to_bytes();
                let mut sig_r = [0u8; 32];
                let mut sig_s = [0u8; 32];
                sig_r.copy_from_slice(&bytes[..32]);
                sig_s.copy_from_slice(&bytes[32..]);
                Ok(P256SignatureWitness {
                    pub_x,
                    pub_y,
                    sig_r,
                    sig_s,
                })
            }
            P256Owner::Precomputed {
                pubkey,
                sig_r,
                sig_s,
            } => {
                let public_key = pubkey.to_p256()?;
                let point = public_key.to_encoded_point(false);
                let (pub_x, pub_y) = encoded_xy(&point)?;
                Ok(P256SignatureWitness {
                    pub_x,
                    pub_y,
                    sig_r: *sig_r,
                    sig_s: *sig_s,
                })
            }
        }
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
}

pub(crate) struct AssembledOutputs {
    pub outputs: Vec<TransferOutput>,
    pub output_hashes: Vec<[u8; 32]>,
}

pub(crate) fn assemble_inputs(
    spends: &[TransferSpendInput],
    shape: Shape,
    allow_p256: bool,
) -> Result<AssembledInputs, ClientError> {
    if spends.len() > shape.n_inputs {
        return Err(ClientError::TooManyInputs {
            got: spends.len(),
            max: shape.n_inputs,
        });
    }

    let mut inputs = Vec::with_capacity(shape.n_inputs);
    let mut input_hashes = Vec::with_capacity(shape.n_inputs);
    let mut nullifiers = Vec::with_capacity(shape.n_inputs);
    let mut utxo_roots = Vec::with_capacity(shape.n_inputs);
    let mut nullifier_tree_roots = Vec::with_capacity(shape.n_inputs);
    let mut solana_owner_pk_hashes = Vec::with_capacity(shape.n_inputs);

    for (index, spend) in spends.iter().enumerate() {
        let nullifier_pk = spend.nullifier_key.pubkey()?;
        let owner_field = owner_hash(&spend.utxo.owner, &nullifier_pk)?;
        let utxo_inputs = UtxoInputs::new(
            &owner_field,
            &spend.utxo.asset,
            spend.utxo.amount,
            &spend.utxo.blinding,
        )?;
        let utxo_hash = spend.utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])?;
        let nullifier = spend
            .nullifier_key
            .nullifier(&utxo_hash, &spend.utxo.blinding)?;

        let is_p256 = spend.utxo.owner.signature_type()? == SignatureType::P256;
        let solana_owner_pk_hash = if is_p256 {
            if !allow_p256 {
                return Err(ClientError::EddsaInputNotSolanaOwned { index });
            }
            [0u8; 32]
        } else {
            spend.utxo.owner.hash()?
        };

        let nullifier_secret = right_align_slice(spend.nullifier_key.secret())?;
        let state = &spend.state_proof;
        let nf = &spend.nullifier_proof;

        inputs.push(TransferInput {
            utxo: utxo_inputs,
            is_dummy: zero(),
            state_path_elements: state.path_elements.iter().map(be).collect(),
            state_path_index: BigUint::from(state.leaf_index),
            nullifier_low_value: be(&nf.low_value),
            nullifier_next_value: be(&nf.next_value),
            nullifier_low_path_elements: nf.low_path_elements.iter().map(be).collect(),
            nullifier_low_path_index: BigUint::from(nf.low_leaf_index),
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
    }

    let dummy_utxo_root = utxo_roots.first().copied().unwrap_or_default();
    let dummy_nullifier_root = nullifier_tree_roots.first().copied().unwrap_or_default();
    let dummy_owner_hash = solana_owner_pk_hashes.first().copied().unwrap_or_default();
    let real_nullifiers = nullifiers.clone();
    for pad_index in 0..shape.n_inputs.saturating_sub(spends.len()) {
        let dummy_nullifier = dummy_nullifier(&real_nullifiers, pad_index);
        inputs.push(dummy_input(
            &dummy_nullifier,
            &dummy_utxo_root,
            &dummy_nullifier_root,
            &dummy_owner_hash,
        ));
        input_hashes.push([0u8; 32]);
        nullifiers.push(dummy_nullifier);
        utxo_roots.push(dummy_utxo_root);
        nullifier_tree_roots.push(dummy_nullifier_root);
        solana_owner_pk_hashes.push(dummy_owner_hash);
    }

    Ok(AssembledInputs {
        inputs,
        input_hashes,
        nullifiers,
        utxo_roots,
        nullifier_tree_roots,
        solana_owner_pk_hashes,
    })
}

pub(crate) fn dummy_nullifier(real_nullifiers: &[[u8; 32]], pad_index: usize) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 + real_nullifiers.len() * 32 + 8);
    preimage.extend_from_slice(b"zolana-dummy-nullifier-v1");
    for nullifier in real_nullifiers {
        preimage.extend_from_slice(nullifier);
    }
    preimage.extend_from_slice(&(pad_index as u64).to_be_bytes());
    sha256_be(&preimage)
}

fn dummy_input(
    nullifier: &[u8; 32],
    utxo_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    owner_hash: &[u8; 32],
) -> TransferInput {
    let zero_bytes = [0u8; 32];
    TransferInput {
        utxo: UtxoInputs::new_dummy(),
        is_dummy: be(&one()),
        state_path_elements: vec![be(&zero_bytes); crate::STATE_TREE_HEIGHT],
        state_path_index: zero(),
        nullifier_low_value: be(&zero_bytes),
        nullifier_next_value: be(&zero_bytes),
        nullifier_low_path_elements: vec![be(&zero_bytes); crate::NULLIFIER_TREE_HEIGHT],
        nullifier_low_path_index: zero(),
        utxo_tree_root: be(utxo_root),
        nullifier_tree_root: be(nullifier_root),
        nullifier: be(nullifier),
        solana_owner_pk_hash: be(owner_hash),
        nullifier_secret: be(&zero_bytes),
    }
}

pub(crate) fn assemble_outputs(
    outputs: &[OutputUtxo],
    shape: Shape,
) -> Result<AssembledOutputs, ClientError> {
    if outputs.len() > shape.n_outputs {
        return Err(ClientError::TooManyOutputs {
            got: outputs.len(),
            max: shape.n_outputs,
        });
    }

    let mut assembled = Vec::with_capacity(shape.n_outputs);
    let mut hashes = Vec::with_capacity(shape.n_outputs);

    for output in outputs {
        let hash = output.hash()?;
        assembled.push(TransferOutput {
            utxo: UtxoInputs::from_output(output)?,
            is_dummy: zero(),
            hash: be(&hash),
        });
        hashes.push(hash);
    }

    for _ in outputs.len()..shape.n_outputs {
        assembled.push(TransferOutput::new_dummy());
        hashes.push([0u8; 32]);
    }

    Ok(AssembledOutputs {
        outputs: assembled,
        output_hashes: hashes,
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
fn zero() -> BigUint {
    BigUint::from(0u8)
}

fn one() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = 1;
    out
}
