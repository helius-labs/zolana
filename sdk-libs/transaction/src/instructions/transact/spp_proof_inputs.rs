use num_bigint::BigUint;
use solana_address::Address;
use zolana_keypair::{
    hash::{hash_field, sha256, sha256_be},
    ShieldedKeypairTrait, SignatureType, ViewingKey, ViewingKeyTrait,
};

use super::{
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    types::PrivateTxHash,
};
use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SppProofInputUtxo},
    ExternalData, SppProofOutputUtxo, SOL_MINT,
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

pub fn signed_to_field(value: i64) -> [u8; 32] {
    let magnitude = BigUint::from(value.unsigned_abs());
    let field = if value < 0 {
        modulus() - magnitude
    } else {
        magnitude
    };
    right_align_slice(&field.to_bytes_be())
}

pub fn asset_field(asset: &Address) -> Result<[u8; 32], TransactionError> {
    Ok(hash_field(asset.as_array())?)
}

pub fn inputs_require_p256(inputs: &[SppProofInputUtxo]) -> Result<bool, TransactionError> {
    for spend in inputs {
        // A dummy's zero owner reads as P256; skip it so it never forces the rail.
        if spend.is_dummy() {
            continue;
        }
        if spend.utxo.owner.signature_type()? == SignatureType::P256 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn first_nullifier(input_utxos: &[SppProofInputUtxo]) -> Result<[u8; 32], TransactionError> {
    input_utxos
        .first()
        .ok_or(TransactionError::NoInputs)?
        .nullifier()
}

pub fn get_transaction_viewing_key<K: ViewingKeyTrait>(
    keypair: &K,
    input_utxos: &[SppProofInputUtxo],
) -> Result<ViewingKey, TransactionError> {
    let first_nullifier = first_nullifier(input_utxos)?;
    Ok(keypair.get_transaction_viewing_key(&first_nullifier)?)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicAmounts {
    pub sol: [u8; 32],
    pub spl: [u8; 32],
    pub asset: [u8; 32],
}

#[derive(Clone)]
pub struct SppProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    pub payer_pubkey_hash: [u8; 32],
    pub p256_signature: Option<[u8; 64]>,
}

impl SppProofInputs {
    pub fn new(
        input_utxos: Vec<SppProofInputUtxo>,
        output_utxos: Vec<SppProofOutputUtxo>,
        external_data: ExternalData,
        payer: Address,
    ) -> Self {
        Self {
            input_utxos,
            output_utxos,
            external_data,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            p256_signature: None,
        }
    }

    pub fn sign_p256<K: ShieldedKeypairTrait>(
        &mut self,
        keypair: &K,
    ) -> Result<(), TransactionError> {
        if keypair.curve()? != SignatureType::P256 {
            return Err(TransactionError::SignerNotP256);
        }
        let message_hash = self.message_hash()?;
        self.p256_signature = Some(keypair.sign(&message_hash));
        Ok(())
    }

    pub fn check_shape(&self) -> Result<Shape, TransactionError> {
        let n_in = self.input_utxos.len();
        let n_out = self.output_utxos.len();
        SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() == n_in && shape.n_outputs() == n_out)
            .ok_or(TransactionError::UnsupportedShape { n_in, n_out })
    }

    pub fn public_amounts(&self) -> Result<PublicAmounts, TransactionError> {
        let sol = self.external_data.public_sol_amount.unwrap_or(0);
        let spl = self.external_data.public_spl_amount.unwrap_or(0);
        let asset = if spl != 0 {
            asset_field(&self.check_public_spl_asset()?)?
        } else {
            [0u8; 32]
        };
        Ok(PublicAmounts {
            sol: signed_to_field(sol),
            spl: signed_to_field(spl),
            asset,
        })
    }

    fn check_public_spl_asset(&self) -> Result<Address, TransactionError> {
        let mut found: Option<Address> = None;
        let assets = self
            .input_utxos
            .iter()
            .map(|spend| spend.utxo.asset)
            .chain(self.output_utxos.iter().map(|output| output.asset));
        for asset in assets {
            if asset != SOL_MINT {
                match found {
                    Some(existing) if existing != asset => {
                        return Err(TransactionError::MultiplePublicSplAssets)
                    }
                    _ => found = Some(asset),
                }
            }
        }
        found.ok_or(TransactionError::MissingPublicSplAsset)
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.input_utxos
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                Ok(InputUtxoContext {
                    index,
                    utxo_hash: spend.hash()?,
                    nullifier: spend.nullifier()?,
                })
            })
            .collect()
    }

    pub fn message_hash(&self) -> Result<[u8; 32], TransactionError> {
        // Dummies contribute zero to match circuit private_tx hashing.
        let mut input_hashes = Vec::with_capacity(self.input_utxos.len());
        for spend in &self.input_utxos {
            if spend.is_dummy() {
                input_hashes.push([0u8; 32]);
            } else {
                input_hashes.push(spend.hash()?);
            }
        }

        let mut output_hashes = Vec::with_capacity(self.output_utxos.len());
        for output in &self.output_utxos {
            if output.is_dummy() {
                output_hashes.push([0u8; 32]);
            } else {
                output_hashes.push(output.hash()?);
            }
        }

        let external_data_hash = self.external_data.hash()?;
        let private_tx =
            PrivateTxHash::new(&input_hashes, &output_hashes, &external_data_hash).hash()?;
        Ok(sha256(&private_tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_public_amounts_match_the_field_encoding_of_zero() {
        assert_eq!(PublicAmounts::default().sol, signed_to_field(0));
        assert_eq!(PublicAmounts::default().spl, signed_to_field(0));
    }
}
