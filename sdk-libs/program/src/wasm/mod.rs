//! Browser transaction construction; proof generation is supplied by Xark.

/// Xark's proving runtime, linked into the application's existing WASM module.
#[cfg(all(feature = "wasm-prover", target_arch = "wasm32"))]
pub use xark_wasm as runtime;

mod types;
pub use types::{
    DataUtxo, FinalizedTransaction, OwnerTag, ProgramProof, ProgramTransaction, ResolvedOwnerTag,
};

use crate::{hasher::DataHasher, CircuitError, EncryptionCodec, InputRecords};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_circuit::{protocol::CheckedTransaction, Input};
use spr_keypair::{ShieldedAddress, SHIELDED_ADDRESS_LEN};
use spr_transaction::Mint;
pub use spr_transaction::WalletUtxo;
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const CLIENT_TYPES: &str = r#"
export interface ProgramInputRecords {
    inputs: WalletUtxo[];
    addresses: number[][];
    mints?: Mint[];
}
export interface ProofInputContext {
    blindingSeed: Uint8Array;
    outputTreeId?: number | null;
}
export type SnarkjsG1 = [string, string, string];
export type SnarkjsG2 = [[string, string], [string, string], [string, string]];
export interface SnarkjsProof {
    protocol: "groth16";
    curve: "bn128";
    pi_a: SnarkjsG1;
    pi_b: SnarkjsG2;
    pi_c: SnarkjsG1;
}
export interface SnarkjsVerifyingKey {
    protocol: "groth16";
    curve: "bn128";
    nPublic: number;
    vk_alpha_1: SnarkjsG1;
    vk_beta_2: SnarkjsG2;
    vk_gamma_2: SnarkjsG2;
    vk_delta_2: SnarkjsG2;
    IC: SnarkjsG1[];
}
"#;

fn js(error: impl core::fmt::Display) -> JsValue {
    js_sys::Error::new(&error.to_string()).into()
}

fn named_error(name: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name(name);
    error.into()
}

/// Validate exact proving-key bytes against a SHA-256 pin from trusted build metadata.
#[wasm_bindgen(js_name = checkProvingKey)]
pub fn check_proving_key(
    proving_key: &[u8],
    expected_sha256: Option<Vec<u8>>,
) -> Result<(), JsValue> {
    let expected: &[u8; 32] = expected_sha256
        .as_deref()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            named_error(
                "InvalidProvingKeyHash",
                "expected proving key SHA-256 must contain exactly 32 bytes",
            )
        })?;
    crate::proof::check_proving_key(proving_key, expected)
        .map_err(|error| named_error("KeyChecksumMismatch", &error.to_string()))
}

pub fn from_js<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(js)
}
pub fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_large_number_types_as_bigints(true)
                .serialize_maps_as_objects(true),
        )
        .map_err(js)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Records {
    inputs: Vec<WalletUtxo>,
    addresses: Vec<Vec<u8>>,
    #[serde(default)]
    mints: Vec<Mint>,
}

/// A caller-supplied value the transaction builders cannot decode, as `ClientError.InvalidInput`.
fn invalid(error: impl core::fmt::Display) -> JsValue {
    client_error(crate::client::transaction::fail(error))
}

fn decode<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(invalid)
}

fn address(bytes: &[u8]) -> Result<ShieldedAddress, JsValue> {
    let bytes: &[u8; SHIELDED_ADDRESS_LEN] = bytes
        .try_into()
        .map_err(|_| invalid("invalid shielded address length"))?;
    ShieldedAddress::from_bytes(bytes).map_err(invalid)
}

fn payer_address(value: &str) -> Result<Address, JsValue> {
    value.parse().map_err(invalid)
}

#[wasm_bindgen(js_name = proofInputUtxo, unchecked_return_type = "Record<string, unknown>")]
pub fn proof_input_utxo(
    #[wasm_bindgen(unchecked_optional_param_type = "WalletUtxo | null")] value: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let input = match value {
        Some(value) => InputRecords::new()
            .utxo(&decode::<WalletUtxo>(value)?)
            .map_err(client_error)?,
        None => spr_circuit::protocol::Utxo::dummy(),
    };
    to_js(&spr_circuit::xark::client::to_json(&input).map_err(js)?)
}

#[wasm_bindgen(js_name = proofInputAddress, unchecked_return_type = "Record<string, unknown>")]
pub fn proof_input_address(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let input = InputRecords::new()
        .address(&address(bytes)?)
        .map_err(client_error)?;
    to_js(&spr_circuit::xark::client::to_json(&input).map_err(js)?)
}

#[wasm_bindgen(js_name = proofInputContext, unchecked_return_type = "Record<string, unknown>")]
pub fn proof_input_context(
    #[wasm_bindgen(unchecked_param_type = "ProofInputContext")] value: JsValue,
) -> Result<JsValue, JsValue> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Context {
        #[serde(with = "spr_keypair::serde_helpers::bytes")]
        blinding_seed: [u8; 32],
        output_tree_id: Option<u16>,
    }
    let value: Context = decode(value)?;
    let input =
        InputRecords::context(&value.blinding_seed, value.output_tree_id).map_err(client_error)?;
    to_js(&spr_circuit::xark::client::to_json(&input).map_err(js)?)
}

pub fn program_transaction<P: Input>(
    inputs: JsValue,
    records: JsValue,
    sender: &[u8],
    payer: &str,
    execute: impl FnOnce(&P) -> Result<CheckedTransaction, CircuitError>,
) -> Result<Ts<ProgramTransaction>, JsValue> {
    let json: serde_json::Value = decode(inputs)?;
    let program: P = spr_circuit::xark::client::from_json(&json).map_err(invalid)?;
    let data: Records = decode(records)?;
    let mut records = InputRecords::new();
    for input in &data.inputs {
        records.utxo(input).map_err(client_error)?;
    }
    for value in &data.addresses {
        records.address(&address(value)?).map_err(client_error)?;
    }
    for mint in data.mints {
        records.asset(mint).map_err(client_error)?;
    }
    let sender = address(sender)?;
    let payer = payer_address(payer)?;
    let checked =
        spr_circuit::checked(|| execute(&program)).map_err(|error| client_error(error.into()))?;
    let transaction = records
        .create_program_transaction(&program, checked, &sender, payer)
        .map_err(client_error)?;
    Ts::from_rust(&ProgramTransaction::try_from(&transaction).map_err(js)?).map_err(js)
}

pub fn prepare_program_transaction<I: Tsify + serde::de::DeserializeOwned>(
    inputs: Ts<I>,
    sender: &[u8],
    payer: &str,
    prepare: impl FnOnce(
        I,
        &ShieldedAddress,
        Address,
    ) -> Result<crate::ProgramTransaction, crate::ClientError>,
) -> Result<Ts<ProgramTransaction>, JsValue> {
    let sender = address(sender)?;
    let payer = payer_address(payer)?;
    let inputs = client_request(inputs.js_value())?;
    let transaction = prepare(inputs, &sender, payer).map_err(client_error)?;
    Ts::from_rust(&ProgramTransaction::try_from(&transaction).map_err(js)?).map_err(js)
}

fn client_request<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    if !value.is_object() || value.is_null() || js_sys::Array::is_array(&value) {
        return Err(invalid("a program client expects a request object"));
    }
    // serde-wasm-bindgen's struct fast path visits only known fields. Enumerate
    // the map so Serde's deny_unknown_fields also checks caller-supplied keys.
    let entries = js_sys::Object::entries(&js_sys::Object::from(value));
    let fields = entries.iter().map(|entry| {
        let pair = js_sys::Array::from(&entry);
        (
            serde_wasm_bindgen::Deserializer::from(pair.get(0)),
            serde_wasm_bindgen::Deserializer::from(pair.get(1)),
        )
    });
    T::deserialize(serde::de::value::MapDeserializer::new(fields)).map_err(invalid)
}

/// Decodes a generated client input's `Field` from JavaScript: a canonical
/// decimal string, refusing leading zeros and values at or above the modulus.
pub use spr_circuit::field_serde::deserialize as deserialize_field;

/// Keeps unknown-field checks active when decoding nested generated client inputs.
pub fn deserialize_client_input<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    struct ClientMap<D>(D);
    impl<'de, D: serde::Deserializer<'de>> serde::Deserializer<'de> for ClientMap<D> {
        type Error = D::Error;
        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error> {
            self.0.deserialize_any(visitor)
        }
        fn deserialize_struct<V: serde::de::Visitor<'de>>(
            self,
            _name: &'static str,
            _fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error> {
            self.0.deserialize_map(visitor)
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }
    T::deserialize(ClientMap(deserializer))
}

fn client_error(error: crate::ClientError) -> JsValue {
    let (name, code) = match &error {
        crate::ClientError::DataHashMismatch => (
            "ClientError.DataHashMismatch",
            "TRANSACTION_OUTPUT_DATA_MISMATCH",
        ),
        crate::ClientError::TooManyInputs { .. } => {
            ("ClientError.TooManyInputs", "TRANSACTION_TOO_MANY_INPUTS")
        }
        crate::ClientError::InvalidInput(_) => {
            ("ClientError.InvalidInput", "TRANSACTION_INVALID_INPUT")
        }
        crate::ClientError::Circuit(circuit) => match circuit.kind() {
            spr_circuit::CircuitErrorKind::RequirementFailed { .. } => (
                "CircuitError.RequirementFailed",
                "PROGRAM_REQUIREMENT_FAILED",
            ),
            _ => ("CircuitError", "PROGRAM_CIRCUIT_ERROR"),
        },
    };
    let value = js_sys::Error::new(&error.to_string());
    value.set_name(name);
    match js_sys::Reflect::set(&value, &JsValue::from_str("code"), &JsValue::from_str(code)) {
        Ok(true) => value.into(),
        _ => js("cannot encode the client error code"),
    }
}

/// Decodes the state `S` of a data UTXO and returns it to JS as `J`, the JS
/// view `UtxoState` generates for `S`.
pub fn data_utxo<S: EncryptionCodec + DataHasher, J: From<S> + Serialize + Tsify>(
    utxo: Ts<WalletUtxo>,
) -> Result<Ts<DataUtxo<J>>, JsValue> {
    let value =
        crate::DataUtxo::<S>::try_from(utxo.to_rust().map_err(js)?).map_err(client_error)?;
    Ts::from_rust(&DataUtxo::from(value)).map_err(js)
}

#[wasm_bindgen(js_name = compressedProgramProof)]
pub fn compressed_program_proof(proof: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof = crate::proof::compressed_proof(proof).map_err(js)?;
    wincode::serialize(&proof).map_err(js)
}

/// Formats a proof and binds its public input to the prepared transaction.
/// The caller verifies the proof against the circuit's trusted verifying key.
#[wasm_bindgen(js_name = programProof)]
pub fn program_proof(
    proof: &[u8],
    public_inputs: &[u8],
    expected_hash: &[u8],
) -> Result<Ts<ProgramProof>, JsValue> {
    use ark_serialize::CanonicalDeserialize;
    let mut input = public_inputs;
    let count = u64::deserialize_compressed(&mut input).map_err(js)?;
    if count != 1 {
        return Err(js("a program proof has one public input"));
    }
    let value = ark_bn254::Fr::deserialize_compressed(&mut input).map_err(js)?;
    if !input.is_empty() {
        return Err(js("trailing public input bytes"));
    }
    let hash = spr_circuit::to_bytes(&spr_circuit::Field::from(value));
    if hash.as_slice() != expected_hash {
        return Err(js("proof public hash differs from its transaction"));
    }
    let value = ProgramProof {
        public_inputs: [spr_keypair::serde_helpers::bytes::ByteArray::new(hash)],
        compressed_proof: crate::proof::compressed_proof(proof).map_err(js)?,
    };
    Ts::from_rust(&value).map_err(js)
}

#[cfg(feature = "wasm-verify")]
#[wasm_bindgen(js_name = proofToSnarkjs, unchecked_return_type = "SnarkjsProof")]
pub fn proof_to_snarkjs(proof: &[u8]) -> Result<JsValue, JsValue> {
    to_js(&crate::proof::snarkjs_proof(proof).map_err(js)?)
}

#[cfg(feature = "wasm-verify")]
#[wasm_bindgen(js_name = verifyingKeyToSnarkjs, unchecked_return_type = "SnarkjsVerifyingKey")]
pub fn verifying_key_to_snarkjs(key: &[u8]) -> Result<JsValue, JsValue> {
    to_js(&crate::proof::snarkjs_verifying_key(key).map_err(js)?)
}
