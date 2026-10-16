mod types;

use core::str::FromStr;

use serde::{de::DeserializeOwned, Serialize};
use solana_address::Address;
use wasm_bindgen::prelude::*;
use zolana_keypair::{ShieldedAddress, SHIELDED_ADDRESS_LEN};

pub use types::{
    CompressedGroth16Proof, DataUtxo, FinalizedTransaction, Groth16Proof, OwnerTag, ProgramProof,
    ProgramTransaction, ResolvedOwnerTag,
};

use borsh::BorshDeserialize;
use zolana_transaction::WalletUtxo;
use zolana_zk_dsl::js_error::js_error;

use crate::{hasher::DataHasher, ClientError, ClientErrorKind, ZkProgram};
#[cfg(feature = "wasm-prover")]
use crate::{Groth16Keys, Groth16Prover, ProofInputs};

#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "wasm-threads")]
#[wasm_bindgen(js_name = initProverThreads, unchecked_return_type = "Promise<void>")]
pub fn init_prover_threads(threads: Option<usize>) -> js_sys::Promise {
    init_thread_pool(threads.unwrap_or_else(hardware_concurrency).max(1))
}

#[cfg(feature = "wasm-threads")]
fn hardware_concurrency() -> usize {
    js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("navigator"))
        .and_then(|navigator| {
            js_sys::Reflect::get(&navigator, &JsValue::from_str("hardwareConcurrency"))
        })
        .ok()
        .and_then(|value| value.as_f64())
        .filter(|count| count.is_finite() && *count >= 1.0)
        .map(|count| count as usize)
        .unwrap_or(1)
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

impl From<ClientError> for JsValue {
    fn from(error: ClientError) -> Self {
        js_error(error.name(), &error.to_string(), error.location())
    }
}

pub fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    Ok(serde_wasm_bindgen::from_value(value)
        .map_err(|error| ClientError::from(ClientErrorKind::InvalidArgument(error.to_string())))?)
}

pub fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    Ok(value
        .serialize(
            &serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true),
        )
        .map_err(|error| {
            ClientError::from(ClientErrorKind::JavaScriptConversion(error.to_string()))
        })?)
}

pub fn program_transaction<P>(
    inputs: JsValue,
    sender: &[u8],
    payer: &str,
) -> Result<JsValue, JsValue>
where
    P: ZkProgram + DeserializeOwned,
{
    let program: P = from_js(inputs)?;
    let sender = shielded_address(sender)?;
    let payer = Address::from_str(payer)
        .map_err(|error| ClientError::from(ClientErrorKind::InvalidPayer(error)))?;
    let transaction = program.create_program_transaction(&sender, payer)?;
    to_js(&ProgramTransaction::try_from(&transaction)?)
}

pub fn data_utxo<T>(utxo: JsValue) -> Result<JsValue, JsValue>
where
    T: BorshDeserialize + DataHasher + Serialize,
{
    let utxo: WalletUtxo = from_js(utxo)?;
    to_js(&DataUtxo::from(crate::DataUtxo::<T>::try_from(utxo)?))
}

/// Loads a memory-image key after checking its SHA-256 against a trusted
/// digest pinned by the application. Do not derive the expected digest from
/// the downloaded key itself. `prover_from_zkey` accepts the canonical format.
#[cfg(feature = "wasm-prover")]
pub fn prover_from_key<P: ZkProgram>(
    proving_key: &[u8],
    expected_sha256: &[u8],
) -> Result<Groth16Prover<P>, JsValue> {
    let checksum = <&[u8; 32]>::try_from(expected_sha256).map_err(|_| {
        ClientError::from(ClientErrorKind::InvalidArgument(
            "expectedSha256 must contain exactly 32 bytes".into(),
        ))
    })?;
    Ok(Groth16Keys::from_image_checked(proving_key, checksum).and_then(Groth16Prover::new)?)
}

#[cfg(feature = "wasm-prover")]
pub fn prover_from_zkey<P: ZkProgram>(zkey: &[u8]) -> Result<Groth16Prover<P>, JsValue> {
    Ok(Groth16Prover::from_zkey_bytes(zkey)?)
}

#[cfg(feature = "wasm-prover")]
pub fn prove<P: ZkProgram>(
    prover: &Groth16Prover<P>,
    proof_inputs: &[u8],
) -> Result<JsValue, JsValue> {
    let result = ProofInputs::from_bytes(proof_inputs)
        .and_then(|proof_inputs| prover.prove_inputs(&proof_inputs))?;
    to_js(&ProgramProof::try_from(&result)?)
}

fn shielded_address(bytes: &[u8]) -> Result<ShieldedAddress, ClientError> {
    let bytes = <[u8; SHIELDED_ADDRESS_LEN]>::try_from(bytes)
        .map_err(|_| ClientErrorKind::SenderLength { found: bytes.len() })?;
    Ok(ShieldedAddress::from_bytes(&bytes).map_err(ClientErrorKind::InvalidSender)?)
}

#[cfg(feature = "wasm-verify")]
#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof(
    #[wasm_bindgen(js_name = verifyingKey)] verifying_key: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ProgramProof")] proof: JsValue,
) -> Result<bool, JsValue> {
    use groth16_solana::{groth16::Groth16Verifier, vk::gnark::parse_gnark_vk_bytes};

    let proof: ProgramProof = from_js(proof)?;
    if !compressed_matches(&proof) {
        return Ok(false);
    }
    let verifying_key = parse_gnark_vk_bytes(verifying_key).map_err(|error| {
        crate::ProverError::from(crate::ProverErrorKind::InvalidVerifyingKey(error))
    })?;
    let verifying_key = verifying_key.as_borrowed();
    let public_inputs = [proof.public_hash];
    Ok(Groth16Verifier::new(
        &proof.proof.a,
        &proof.proof.b,
        &proof.proof.c,
        &public_inputs,
        &verifying_key,
    )
    .and_then(|mut verifier| verifier.verify())
    .is_ok())
}

#[cfg(feature = "wasm-verify")]
fn compressed_matches(proof: &ProgramProof) -> bool {
    use solana_bn254::compression::prelude::{
        alt_bn128_g1_decompress_be, alt_bn128_g2_decompress_be,
    };

    alt_bn128_g1_decompress_be(&proof.compressed_proof.a).is_ok_and(|a| a == proof.proof.a)
        && alt_bn128_g2_decompress_be(&proof.compressed_proof.b).is_ok_and(|b| b == proof.proof.b)
        && alt_bn128_g1_decompress_be(&proof.compressed_proof.c).is_ok_and(|c| c == proof.proof.c)
}
