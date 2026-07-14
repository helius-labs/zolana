use num_bigint::{BigInt, BigUint, Sign};
use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::TransactOutput;
use zolana_keypair::{
    hash::{hash_field, sha256, sha256_be},
    ShieldedKeypairTrait, SignatureType, ViewingKeyTrait,
};

use super::{
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    slots::{EncodeOutputSlot, SlotCx},
    types::{no_address_hashes, private_tx_hash},
};
use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SppProofInputUtxo},
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
    let spend = input_utxos.first().ok_or(TransactionError::NoInputs)?;
    let nullifier_pubkey = spend.nullifier_key.pubkey()?;
    let utxo_hash = spend.utxo.hash(
        &nullifier_pubkey,
        &spend.data_hash.unwrap_or([0u8; 32]),
        &spend.zone_data_hash.unwrap_or([0u8; 32]),
    )?;
    Ok(spend
        .nullifier_key
        .nullifier(&utxo_hash, &spend.utxo.blinding)?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicAmounts {
    pub sol: [u8; 32],
    pub spl: [u8; 32],
    pub asset: [u8; 32],
}
// TODO: implement constructor and builder pattern for deposit and withdraw
// Sent to the ProverServer
#[derive(Clone)]
pub struct SppProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<OutputUtxo>,
    pub public_amounts: PublicAmounts,
    pub external_data: ExternalData,
    pub payer_pubkey_hash: [u8; 32],
    pub shape: Shape,
    pub p256_signature: Option<[u8; 64]>,
}

impl SppProofInputs {
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.input_utxos
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
        for spend in &self.input_utxos {
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
        for output in &self.output_utxos {
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

pub struct SlotTransact {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub payer: Address,
    pub expiry_unix_ts: u64,
}

impl SlotTransact {
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        slots: &[&dyn EncodeOutputSlot],
        keypair: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        let shape = Shape::new(self.input_utxos.len(), slots.len());
        if !SPP_SUPPORTED_SHAPES.contains(&shape) {
            return Err(TransactionError::UnsupportedShape {
                n_in: shape.n_inputs,
                n_out: shape.n_outputs,
            });
        }

        let first_nullifier = first_nullifier(&self.input_utxos)?;
        let tx = keypair.get_transaction_viewing_key(&first_nullifier)?;
        let salt = zolana_keypair::random_salt();
        let tx_viewing_pk = tx.pubkey();
        let self_pubkey = keypair.viewing_pubkey();

        let mut output_utxos = Vec::with_capacity(slots.len());
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        // AES ordinal: only data-bearing slots consume an index. Every
        // slot signed here is data-bearing, so the ordinal equals the slot
        // position, matching the historical `i as u32`.
        let mut ordinal = 0u32;
        for slot in slots.iter() {
            let encoded = slot.encode_slot(&SlotCx {
                tx: &tx,
                self_pubkey,
                salt,
                slot_index: ordinal,
            })?;
            let output = slot.output().clone();
            let utxo_hash = output.hash()?;
            if encoded.data.is_some() {
                ordinal += 1;
            }
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: encoded.owner_tag,
                data: encoded.data,
            });
            resolved_owner_tags.push(encoded.resolved_owner_tag);
            output_utxos.push(output);
        }

        let external_data = ExternalData::new(
            *tx_viewing_pk.as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
            self.expiry_unix_ts,
        );

        let mut signed = SppProofInputs {
            input_utxos: self.input_utxos,
            output_utxos,
            public_amounts: PublicAmounts {
                sol: signed_to_field(0),
                spl: signed_to_field(0),
                asset: [0u8; 32],
            },
            external_data,
            payer_pubkey_hash: sha256_be(self.payer.as_array()),
            shape,
            p256_signature: None,
        };
        if keypair.curve()? == SignatureType::P256 {
            let message_hash = signed.message_hash()?;
            signed.p256_signature = Some(keypair.sign(&message_hash));
        }
        Ok(signed)
    }
}
