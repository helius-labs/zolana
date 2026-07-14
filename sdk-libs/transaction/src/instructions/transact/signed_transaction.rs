use num_bigint::{BigInt, BigUint, Sign};
use solana_address::Address;
use zolana_keypair::hash::{hash_field, sha256};

use super::{
    builder::Shape,
    types::{no_address_hashes, private_tx_hash},
};
use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SpendUtxo},
    ExternalData, OutputUtxo,
};

pub const BN254_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn modulus() -> BigUint {
    BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("valid BN254 modulus literal")
}

fn right_align_slice(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    out
}

pub fn signed_to_field(value: i128) -> [u8; 32] {
    let m = BigInt::from_biguint(Sign::Plus, modulus());
    let v = BigInt::from(value);
    let reduced = ((v % &m) + &m) % &m;
    let (_, bytes) = reduced.to_bytes_be();
    right_align_slice(&bytes)
}

pub fn asset_field(asset: &Address) -> Result<[u8; 32], TransactionError> {
    Ok(hash_field(asset.as_array())?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicAmounts {
    pub sol: [u8; 32],
    pub spl: [u8; 32],
    pub asset: [u8; 32],
}

// TODO: rename to SppProofinputs
// Sent to the ProverServer
#[derive(Clone)]
pub struct SignedTransaction {
    pub inputs: Vec<SpendUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub public_amounts: PublicAmounts,
    pub external_data: ExternalData,
    pub payer_pubkey_hash: [u8; 32],
    pub shape: Shape,
    pub p256_owner: Option<[u8; 64]>,
}

impl SignedTransaction {
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                let nullifier_pubkey = spend.nullifier_key.pubkey()?;
                let utxo_hash = spend.utxo.hash(
                    &nullifier_pubkey,
                    &spend.data_hash.unwrap_or([0u8; 32]),
                    &spend.zone_data_hash.unwrap_or([0u8; 32]),
                )?;
                let nullifier = spend
                    .nullifier_key
                    .nullifier(&utxo_hash, &spend.utxo.blinding)?;
                Ok(InputUtxoContext {
                    index,
                    utxo_hash,
                    nullifier,
                })
            })
            .collect()
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        // Dummies contribute zero to match circuit private_tx hashing.
        let mut input_hashes = Vec::with_capacity(self.shape.n_inputs);
        for spend in &self.inputs {
            if spend.is_dummy() {
                input_hashes.push([0u8; 32]);
            } else {
                let nullifier_pubkey = spend.nullifier_key.pubkey()?;
                input_hashes.push(spend.utxo.hash(
                    &nullifier_pubkey,
                    &spend.data_hash.unwrap_or([0u8; 32]),
                    &spend.zone_data_hash.unwrap_or([0u8; 32]),
                )?);
            }
        }

        let mut output_hashes = Vec::with_capacity(self.shape.n_outputs);
        for output in &self.outputs {
            if output.is_dummy() {
                output_hashes.push([0u8; 32]);
            } else {
                output_hashes.push(output.hash()?);
            }
        }

        let external_data_hash = self.external_data.hash()?;
        let private_tx = private_tx_hash(
            &input_hashes,
            &output_hashes,
            &no_address_hashes(self.shape.n_inputs),
            &external_data_hash,
        )?;
        Ok(sha256(&private_tx))
    }
}
