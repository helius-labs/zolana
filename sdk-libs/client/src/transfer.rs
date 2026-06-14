use num_bigint::BigUint;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use solana_address::Address;
use zolana_keypair::hash::{owner_hash, poseidon, sha256_be};
use zolana_keypair::{NullifierKey, P256Pubkey, SignatureType};
use zolana_transaction::utxo::UTXO_DOMAIN;
use zolana_transaction::{ExternalData, Utxo};

use crate::error::ClientError;
use crate::field::{asset_field, be, hash_chain, right_align, right_align_slice};
use crate::merkle::{
    NullifierNonInclusionProof, StateInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use crate::prover::{TransferInput, TransferInputs, TransferOutput, UtxoInputs};
use crate::shape::{resolve_shape, Shape};

pub struct TransferSpendInput {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub state_proof: StateInclusionProof,
    pub nullifier_proof: NullifierNonInclusionProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferNewOutput {
    pub owner_hash: [u8; 32],
    pub asset: Address,
    pub amount: u64,
    pub blinding: [u8; 31],
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

pub enum P256Owner {
    Signer(SigningKey),
    Precomputed {
        pubkey: P256Pubkey,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    },
}

pub struct TransferProver {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<TransferNewOutput>,
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    pub p256_owner: P256Owner,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct TransferProofResult {
    pub inputs: TransferInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
}

impl TransferProver {
    pub fn build(self) -> Result<TransferProofResult, ClientError> {
        let shape = resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        let assembled_inputs = assemble_inputs(&self.inputs, shape, true)?;
        let assembled_outputs = assemble_outputs(&self.outputs, shape)?;
        let external_data_hash = self.external_data.hash();
        let private_tx = private_tx_hash(
            &assembled_inputs.input_hashes,
            &assembled_outputs.output_hashes,
            &external_data_hash,
        )?;
        let p256_message_hash = sha256_be(&private_tx);
        let signature = self.p256_owner.witness(&p256_message_hash)?;
        let public_input = public_input_hash(
            &assembled_inputs.nullifiers,
            &assembled_outputs.output_hashes,
            &assembled_inputs.utxo_roots,
            &assembled_inputs.nullifier_tree_roots,
            &private_tx,
            &p256_message_hash,
            &external_data_hash,
            &self.public_amounts,
            &self.payer_pubkey_hash,
            &assembled_inputs.solana_owner_pk_hashes,
        )?;

        let inputs = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            p256_pub_x: be(&signature.pub_x),
            p256_pub_y: be(&signature.pub_y),
            p256_sig_r: be(&signature.sig_r),
            p256_sig_s: be(&signature.sig_s),
            private_tx_hash: be(&private_tx),
            p256_message_hash: be(&p256_message_hash),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            program_id_hashchain: zero(),
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            data_hash: zero(),
            zone_data_hash: zero(),
            public_input_hash: be(&public_input),
        };

        Ok(TransferProofResult {
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
        let (utxo_wire, utxo_hash) = real_utxo(
            owner_field,
            &spend.utxo.asset,
            spend.utxo.amount,
            &spend.utxo.blinding,
        )?;
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
            utxo: utxo_wire,
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

    for _ in spends.len()..shape.n_inputs {
        inputs.push(dummy_input());
        input_hashes.push([0u8; 32]);
        nullifiers.push([0u8; 32]);
        utxo_roots.push([0u8; 32]);
        nullifier_tree_roots.push([0u8; 32]);
        solana_owner_pk_hashes.push([0u8; 32]);
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

pub(crate) fn assemble_outputs(
    outputs: &[TransferNewOutput],
    shape: Shape,
) -> Result<AssembledOutputs, ClientError> {
    if outputs.len() > shape.n_outputs {
        return Err(ClientError::TooManyOutputs {
            got: outputs.len(),
            max: shape.n_outputs,
        });
    }

    let mut wire = Vec::with_capacity(shape.n_outputs);
    let mut hashes = Vec::with_capacity(shape.n_outputs);

    for output in outputs {
        let (utxo_wire, hash) = real_utxo(
            output.owner_hash,
            &output.asset,
            output.amount,
            &output.blinding,
        )?;
        wire.push(TransferOutput {
            utxo: utxo_wire,
            is_dummy: zero(),
            hash: be(&hash),
        });
        hashes.push(hash);
    }

    for _ in outputs.len()..shape.n_outputs {
        wire.push(TransferOutput {
            utxo: dummy_utxo(),
            is_dummy: BigUint::from(1u8),
            hash: zero(),
        });
        hashes.push([0u8; 32]);
    }

    Ok(AssembledOutputs {
        outputs: wire,
        output_hashes: hashes,
    })
}

pub(crate) fn private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], ClientError> {
    let input_chain = hash_chain(input_hashes)?;
    let output_chain = hash_chain(output_hashes)?;
    poseidon(&[&input_chain, &output_chain, external_data_hash])
        .map_err(|e| ClientError::Hasher(e.to_string()))
}
// TODO: refactor into struct with method hash -> use method pattern
#[allow(clippy::too_many_arguments)]
pub(crate) fn public_input_hash(
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    utxo_roots: &[[u8; 32]],
    nullifier_tree_roots: &[[u8; 32]],
    private_tx: &[u8; 32],
    p256_message_hash: &[u8; 32],
    external_data_hash: &[u8; 32],
    public_amounts: &PublicAmounts,
    payer_pubkey_hash: &[u8; 32],
    solana_owner_pk_hashes: &[[u8; 32]],
) -> Result<[u8; 32], ClientError> {
    let elements = [
        hash_chain(nullifiers)?,
        hash_chain(output_hashes)?,
        hash_chain(utxo_roots)?,
        hash_chain(nullifier_tree_roots)?,
        *private_tx,
        *p256_message_hash,
        *external_data_hash,
        public_amounts.sol,
        public_amounts.spl,
        public_amounts.asset,
        [0u8; 32],
        *payer_pubkey_hash,
        [0u8; 32],
        [0u8; 32],
        hash_chain(solana_owner_pk_hashes)?,
    ];
    hash_chain(&elements)
}

pub fn input_utxo_hash(utxo: &Utxo, nullifier_key: &NullifierKey) -> Result<[u8; 32], ClientError> {
    let nullifier_pk = nullifier_key.pubkey()?;
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk)?;
    let (_, hash) = real_utxo(owner_field, &utxo.asset, utxo.amount, &utxo.blinding)?;
    Ok(hash)
}

pub fn output_utxo_hash(output: &TransferNewOutput) -> Result<[u8; 32], ClientError> {
    let (_, hash) = real_utxo(
        output.owner_hash,
        &output.asset,
        output.amount,
        &output.blinding,
    )?;
    Ok(hash)
}

fn real_utxo(
    owner_field: [u8; 32],
    asset: &Address,
    amount: u64,
    blinding: &[u8; 31],
) -> Result<(UtxoInputs, [u8; 32]), ClientError> {
    let domain_fe = right_align(&UTXO_DOMAIN.to_be_bytes());
    let asset_fe = asset_field(asset)?;
    let amount_fe = right_align(&amount.to_be_bytes());
    let blinding_fe = right_align(blinding);
    let zero_fe = [0u8; 32];

    let owner_utxo_hash =
        poseidon(&[&owner_field, &blinding_fe]).map_err(|e| ClientError::Hasher(e.to_string()))?;
    let hash = poseidon(&[
        &domain_fe,
        &asset_fe,
        &amount_fe,
        &zero_fe,
        &zero_fe,
        &zero_fe,
        &owner_utxo_hash,
    ])
    .map_err(|e| ClientError::Hasher(e.to_string()))?;

    let wire = UtxoInputs {
        domain: be(&domain_fe),
        owner: be(&owner_field),
        asset: be(&asset_fe),
        amount: be(&amount_fe),
        blinding: be(&blinding_fe),
        data_hash: zero(),
        zone_data_hash: zero(),
        zone_program_id: zero(),
    };
    Ok((wire, hash))
}

fn dummy_utxo() -> UtxoInputs {
    UtxoInputs {
        domain: zero(),
        owner: zero(),
        asset: zero(),
        amount: zero(),
        blinding: zero(),
        data_hash: zero(),
        zone_data_hash: zero(),
        zone_program_id: zero(),
    }
}

fn dummy_input() -> TransferInput {
    TransferInput {
        utxo: dummy_utxo(),
        is_dummy: BigUint::from(1u8),
        state_path_elements: vec![zero(); STATE_TREE_HEIGHT],
        state_path_index: zero(),
        nullifier_low_value: zero(),
        nullifier_next_value: zero(),
        nullifier_low_path_elements: vec![zero(); NULLIFIER_TREE_HEIGHT],
        nullifier_low_path_index: zero(),
        utxo_tree_root: zero(),
        nullifier_tree_root: zero(),
        nullifier: zero(),
        solana_owner_pk_hash: zero(),
        nullifier_secret: zero(),
    }
}

fn zero() -> BigUint {
    BigUint::from(0u8)
}
