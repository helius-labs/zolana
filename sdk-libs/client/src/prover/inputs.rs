use num_bigint::BigUint;
use solana_address::Address;
use zolana_keypair::hash::poseidon;
use zolana_transaction::{
    utxo::{zone_program_id_field, UTXO_DOMAIN},
    OutputUtxo,
};

use crate::{
    error::ClientError,
    private_transaction::field::{asset_field, be, right_align},
    rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
};

/// UTXO commitment fields, pre-computed by the caller. Mirrors the circuit's
/// UtxoCircuitFields (prover/server/circuits/spp_transaction/utxo.go).
#[derive(Debug, Clone)]
pub struct UtxoInputs {
    pub domain: BigUint,
    pub owner: BigUint,
    pub asset: BigUint,
    pub amount: BigUint,
    pub blinding: BigUint,
    pub data_hash: BigUint,
    pub zone_data_hash: BigUint,
    pub zone_program_id: BigUint,
}

impl UtxoInputs {
    pub fn new(
        owner_field: &[u8; 32],
        asset: &Address,
        amount: u64,
        blinding: &[u8; 31],
    ) -> Result<Self, ClientError> {
        Ok(Self {
            domain: be(&right_align(&UTXO_DOMAIN.to_be_bytes())),
            owner: be(owner_field),
            asset: be(&asset_field(asset)?),
            amount: be(&right_align(&amount.to_be_bytes())),
            blinding: be(&right_align(blinding)),
            data_hash: BigUint::ZERO,
            zone_data_hash: BigUint::ZERO,
            zone_program_id: BigUint::ZERO,
        })
    }

    pub fn from_output(output: &OutputUtxo) -> Result<Self, ClientError> {
        Ok(Self {
            domain: be(&right_align(&UTXO_DOMAIN.to_be_bytes())),
            owner: be(&output.owner_hash),
            asset: be(&asset_field(&output.asset)?),
            amount: be(&right_align(&output.amount.to_be_bytes())),
            blinding: be(&right_align(&output.blinding)),
            data_hash: be(&output.program_data_hash.unwrap_or_default()),
            zone_data_hash: be(&output.zone_data_hash.unwrap_or_default()),
            zone_program_id: be(&zone_program_id_field(&output.zone_program_id)?),
        })
    }

    pub fn new_dummy(blinding: BigUint) -> Self {
        Self {
            domain: BigUint::ZERO,
            owner: BigUint::ZERO,
            asset: BigUint::ZERO,
            amount: BigUint::ZERO,
            blinding,
            data_hash: BigUint::ZERO,
            zone_data_hash: BigUint::ZERO,
            zone_program_id: BigUint::ZERO,
        }
    }
}

/// One spend input. Mirrors txcircuit.Input.
#[derive(Debug, Clone)]
pub struct TransferInput {
    pub utxo: UtxoInputs,
    pub is_dummy: BigUint,
    pub state_path_elements: Vec<BigUint>,
    pub state_path_index: BigUint,
    pub nullifier_low_value: BigUint,
    pub nullifier_next_value: BigUint,
    pub nullifier_low_path_elements: Vec<BigUint>,
    pub nullifier_low_path_index: BigUint,
    pub utxo_tree_root: BigUint,
    pub nullifier_tree_root: BigUint,
    pub nullifier: BigUint,
    pub solana_owner_pk_hash: BigUint,
    pub nullifier_secret: BigUint,
}

impl TransferInput {
    /// Padding input over the sender's chosen random `blinding` (secret 0). The roots,
    /// indices, and owner hash are mirrored from the first real input by the caller;
    /// the circuit skips ownership, inclusion, and the nullifier check for it.
    pub fn new_dummy(
        blinding: &[u8; 31],
        utxo_tree_root: &[u8; 32],
        nullifier_tree_root: &[u8; 32],
        solana_owner_pk_hash: &[u8; 32],
    ) -> Result<(Self, [u8; 32]), ClientError> {
        let blinding_32 = right_align(blinding);
        let utxo_hash = dummy_utxo_hash(&blinding_32)?;
        let nullifier = dummy_nullifier(&utxo_hash, &blinding_32)?;
        Ok((
            Self {
                utxo: UtxoInputs::new_dummy(be(&blinding_32)),
                is_dummy: BigUint::from(1u8),
                state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
                state_path_index: BigUint::ZERO,
                nullifier_low_value: BigUint::ZERO,
                nullifier_next_value: BigUint::ZERO,
                nullifier_low_path_elements: vec![BigUint::ZERO; NULLIFIER_TREE_HEIGHT],
                nullifier_low_path_index: BigUint::ZERO,
                utxo_tree_root: be(utxo_tree_root),
                nullifier_tree_root: be(nullifier_tree_root),
                nullifier: be(&nullifier),
                solana_owner_pk_hash: be(solana_owner_pk_hash),
                nullifier_secret: BigUint::ZERO,
            },
            nullifier,
        ))
    }
}

/// One output. Mirrors txcircuit.Output.
#[derive(Debug, Clone)]
pub struct TransferOutput {
    pub utxo: UtxoInputs,
    pub is_dummy: BigUint,
    pub hash: BigUint,
}

fn dummy_utxo_hash(blinding_32: &[u8; 32]) -> Result<[u8; 32], ClientError> {
    let zero = [0u8; 32];
    let owner_utxo_hash =
        poseidon(&[&zero, blinding_32]).map_err(|e| ClientError::Hasher(e.to_string()))?;
    poseidon(&[&zero, &zero, &zero, &zero, &zero, &zero, &owner_utxo_hash])
        .map_err(|e| ClientError::Hasher(e.to_string()))
}

fn dummy_nullifier(utxo_hash: &[u8; 32], blinding_32: &[u8; 32]) -> Result<[u8; 32], ClientError> {
    let secret = [0u8; 32];
    poseidon(&[utxo_hash, blinding_32, &secret]).map_err(|e| ClientError::Hasher(e.to_string()))
}

/// Flat, pre-computed witness for the P256-capable spp_transaction circuit.
/// Mirrors prover/server/prover/transfer/params.go TransferParameters.
#[derive(Debug, Clone)]
pub struct TransferP256Inputs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: BigUint,
    pub p256_pub_x: BigUint,
    pub p256_pub_y: BigUint,
    pub p256_sig_r: BigUint,
    pub p256_sig_s: BigUint,
    pub private_tx_hash: BigUint,
    /// Full SHA-256 P256 ECDSA message digest as two big-endian 128-bit limbs;
    /// both 0 on the Solana-only rail.
    pub p256_message_hash_low: BigUint,
    pub p256_message_hash_high: BigUint,
    pub public_sol_amount: BigUint,
    pub public_spl_amount: BigUint,
    pub public_spl_asset_pubkey: BigUint,
    pub program_id_hashchain: BigUint,
    pub payer_pubkey_hash: BigUint,
    pub data_hash: BigUint,
    pub zone_data_hash: BigUint,
    pub public_input_hash: BigUint,
}

/// Flat, pre-computed witness for the 8-in/1-out merge circuit. Mirrors
/// prover/server/prover/merge/params.go MergeParameters. The per-input and output
/// witness reuses [`TransferInput`]/[`TransferOutput`] (assembled the same way as
/// a transfer); the merge circuit ignores the transfer-only `solanaOwnerPkHash`
/// and per-input `nullifierSecret` (the secret is shared, below).
#[derive(Debug, Clone)]
pub struct MergeInputs {
    pub inputs: Vec<TransferInput>,
    pub output: TransferOutput,
    /// Shared owner P256 signing pubkey coordinates and nullifier secret/commitment.
    pub p256_pub_x: BigUint,
    pub p256_pub_y: BigUint,
    pub user_nullifier_pk: BigUint,
    pub user_nullifier_secret: BigUint,
    /// Ephemeral P-256 scalar (must be < BN254 modulus so it is a valid circuit
    /// witness as well as a P-256 scalar) and the owner's viewing pubkey as the
    /// 65 bytes of the uncompressed point.
    pub tx_viewing_sk: BigUint,
    pub user_viewing_pubkey: Vec<BigUint>,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    pub public_input_hash: BigUint,
}

/// Flat, pre-computed witness for the Solana-only spp_transaction circuit. This
/// rail has no P256 gadget, so there is no P256 pubkey/signature/message-hash.
/// Mirrors prover/server/prover/transfer_eddsa_only/params.go TransferParameters.
#[derive(Debug, Clone)]
pub struct TransferInputs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    pub public_sol_amount: BigUint,
    pub public_spl_amount: BigUint,
    pub public_spl_asset_pubkey: BigUint,
    pub program_id_hashchain: BigUint,
    pub payer_pubkey_hash: BigUint,
    pub data_hash: BigUint,
    pub zone_data_hash: BigUint,
    pub public_input_hash: BigUint,
}
