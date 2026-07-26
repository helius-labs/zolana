use num_bigint::BigUint;
use solana_address::Address;
use zolana_interface::{
    instruction::instruction_data::transact::CircuitVariant, MAX_WIRE_PUBLIC_LEGS, N_PUBLIC_SLOTS,
    SOL_ASSET_FIELD,
};
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
    signed_magnitude_to_field(value >= 0, value.unsigned_abs())
}

pub fn signed_magnitude_to_field(is_deposit: bool, amount: u64) -> [u8; 32] {
    if amount == 0 {
        return [0u8; 32];
    }
    let magnitude = BigUint::from(amount);
    let field = if is_deposit {
        magnitude
    } else {
        modulus() - magnitude
    };
    right_align_slice(&field.to_bytes_be())
}

pub fn asset_field(asset: &Address) -> Result<[u8; 32], TransactionError> {
    Ok(hash_field(asset.as_array())?)
}

/// The proving variant the spending key material requires: P256 iff any real
/// input is P256-owned. This is the single derivation of the variant; the
/// `circuit` selector stamped on the instruction data and the prover witness
/// both come from it, so they agree by construction.
pub fn inputs_proof_variant(
    inputs: &[SppProofInputUtxo],
) -> Result<CircuitVariant, TransactionError> {
    for spend in inputs {
        // A dummy's zero owner reads as P256; skip it so it never forces the
        // P256 variant.
        if spend.is_dummy() {
            continue;
        }
        if spend.utxo.owner.signature_type()? == SignatureType::P256 {
            return Ok(CircuitVariant::P256);
        }
    }
    Ok(CircuitVariant::Eddsa)
}

pub fn inputs_require_p256(inputs: &[SppProofInputUtxo]) -> Result<bool, TransactionError> {
    Ok(inputs_proof_variant(inputs)? == CircuitVariant::P256)
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

/// Uniform public movement slots: ordered settlement legs are accumulated per
/// asset in first-appearance order. Net-zero assets are omitted and idle slots
/// are `(0, 0)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicMovements {
    pub assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub amounts: [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PublicMovements {
    pub fn interleaved(&self) -> [[u8; 32]; 2 * N_PUBLIC_SLOTS] {
        core::array::from_fn(|index| {
            let slot = index / 2;
            if index % 2 == 0 {
                self.assets.get(slot).copied().unwrap_or_default()
            } else {
                self.amounts.get(slot).copied().unwrap_or_default()
            }
        })
    }
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

    pub fn public_movements(&self) -> Result<PublicMovements, TransactionError> {
        if self.external_data.public_legs.len() > MAX_WIRE_PUBLIC_LEGS {
            return Err(TransactionError::TooManyPublicLegs {
                got: self.external_data.public_legs.len(),
                max: MAX_WIRE_PUBLIC_LEGS,
            });
        }

        let mut aggregated: Vec<(Address, i128)> = Vec::new();
        for leg in &self.external_data.public_legs {
            let asset = leg.asset();
            let amount = leg.amount();
            if amount == 0 {
                return Err(TransactionError::ZeroPublicLegAmount);
            }
            if leg.public_leg().is_spl() && asset == SOL_MINT {
                return Err(TransactionError::SettlementTargetMismatch { asset });
            }
            let magnitude = i128::from(amount);
            let signed = if leg.is_deposit() {
                magnitude
            } else {
                -magnitude
            };
            if let Some((_, total)) = aggregated
                .iter_mut()
                .find(|(existing, _)| *existing == asset)
            {
                *total = total
                    .checked_add(signed)
                    .ok_or(TransactionError::PublicMovementOverflow { asset })?;
            } else {
                aggregated.push((asset, signed));
            }
        }
        aggregated.retain(|(_, amount)| *amount != 0);
        if aggregated.len() > N_PUBLIC_SLOTS {
            return Err(TransactionError::TooManyPublicAssets {
                got: aggregated.len(),
                max: N_PUBLIC_SLOTS,
            });
        }

        let mut movements = PublicMovements::default();
        for ((asset_slot, amount_slot), (asset, amount)) in movements
            .assets
            .iter_mut()
            .zip(movements.amounts.iter_mut())
            .zip(aggregated)
        {
            let magnitude = u64::try_from(amount.unsigned_abs())
                .map_err(|_| TransactionError::PublicMovementOverflow { asset })?;
            *asset_slot = if asset == SOL_MINT {
                SOL_ASSET_FIELD
            } else {
                asset_field(&asset)?
            };
            *amount_slot = signed_magnitude_to_field(amount > 0, magnitude);
        }
        Ok(movements)
    }

    /// Nullifiers of the padding (dummy) input slots, in slot order. The circuit
    /// checks nullifier non-inclusion for every slot, so each dummy needs a real
    /// low-element witness fetched for its own nullifier.
    pub fn dummy_nullifiers(&self) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.input_utxos
            .iter()
            .filter(|spend| spend.is_dummy())
            .map(|spend| spend.nullifier())
            .collect()
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
