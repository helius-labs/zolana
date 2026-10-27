//! Browser transaction construction; proof generation is supplied by Xark.

mod types;
pub use types::{DataUtxo, FinalizedTransaction, OwnerTag, ProgramTransaction, ResolvedOwnerTag};

use serde::{Deserialize, Serialize};
use solana_address::Address;
use wasm_bindgen::prelude::*;
use zolana_keypair::{ShieldedAddress, SHIELDED_ADDRESS_LEN};
use zolana_transaction::{Mint, WalletUtxo};
use zolana_circuit::{Input, protocol::CheckedTransaction};
use crate::{InputRecords, CircuitError, EncryptionCodec, hasher::DataHasher};

fn js(error: impl core::fmt::Display) -> JsValue { JsValue::from_str(&error.to_string()) }

pub fn from_js<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js)
}
pub fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value.serialize(&serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true).serialize_maps_as_objects(true)).map_err(js)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Records {
    inputs: Vec<WalletUtxo>,
    addresses: Vec<Vec<u8>>,
    #[serde(default)]
    mints: Vec<Mint>,
}

fn address(bytes: &[u8]) -> Result<ShieldedAddress, JsValue> {
    let bytes: &[u8; SHIELDED_ADDRESS_LEN] = bytes.try_into().map_err(|_| js("invalid shielded address length"))?;
    ShieldedAddress::from_bytes(bytes).map_err(js)
}

pub fn program_transaction<P: Input>(inputs: JsValue, records: JsValue, sender: &[u8], payer: &str,
    execute: impl FnOnce(&P) -> Result<CheckedTransaction, CircuitError>) -> Result<JsValue, JsValue>
{
    let json: serde_json::Value = from_js(inputs)?;
    let program: P = zolana_circuit::xark::client::from_json(&json).map_err(js)?;
    let data: Records = from_js(records)?;
    let mut records = InputRecords::new();
    for input in &data.inputs { records.utxo(input).map_err(js)?; }
    for value in &data.addresses { records.address(&address(value)?).map_err(js)?; }
    for mint in data.mints { records.asset(mint); }
    let sender = address(sender)?;
    let payer: Address = payer.parse().map_err(js)?;
    let checked = execute(&program).map_err(js)?;
    let transaction = records.create_program_transaction(&program, checked, &sender, payer).map_err(js)?;
    to_js(&ProgramTransaction::try_from(&transaction).map_err(js)?)
}

pub fn data_utxo<T: Input + EncryptionCodec + DataHasher>(utxo: JsValue) -> Result<JsValue, JsValue> {
    let value = crate::DataUtxo::<T>::try_from(from_js::<WalletUtxo>(utxo)?).map_err(js)?;
    let data = zolana_circuit::xark::client::to_json(&value.data).map_err(js)?;
    to_js(&DataUtxo { utxo: value.utxo, data, address: value.address.map(zolana_keypair::serde_helpers::bytes::ByteArray::new) })
}

#[wasm_bindgen(js_name = compressedProgramProof)]
pub fn compressed_program_proof(proof: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof = crate::proof::compressed_proof(proof).map_err(js)?;
    wincode::serialize(&proof).map_err(js)
}

#[wasm_bindgen(js_name = proofToSnarkjs)]
pub fn proof_to_snarkjs(proof: &[u8]) -> Result<JsValue, JsValue> {
    to_js(&crate::proof::snarkjs_proof(proof).map_err(js)?)
}

#[wasm_bindgen(js_name = verifyingKeyToSnarkjs)]
pub fn verifying_key_to_snarkjs(key: &[u8]) -> Result<JsValue, JsValue> {
    to_js(&crate::proof::snarkjs_verifying_key(key).map_err(js)?)
}
