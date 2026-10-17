//! The browser and Node runtime of a circuit compiled to wasm: the generated
//! `<Name>Prover` classes call into it, and it exports `verifyProof` and
//! `initProverThreads` to JavaScript.

mod types;

use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

pub use types::{CompressedGroth16Proof, Groth16Proof, Proof};

#[cfg(feature = "wasm-prover")]
use crate::{Groth16Keys, Groth16Prover, ProofInputs};
use crate::{ProverError, ProverErrorKind, ZkCircuit};

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

pub fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    Ok(serde_wasm_bindgen::from_value(value)
        .map_err(|error| ProverError::from(ProverErrorKind::InvalidArgument(error.to_string())))?)
}

pub fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    Ok(value
        .serialize(
            &serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true),
        )
        .map_err(|error| {
            ProverError::from(ProverErrorKind::JavaScriptConversion(error.to_string()))
        })?)
}

/// The proof inputs (a WTNS assignment) of a circuit from its typed inputs,
/// for `<Name>Prover.prove`.
pub fn proof_inputs<C: ZkCircuit + DeserializeOwned>(inputs: JsValue) -> Result<Vec<u8>, JsValue> {
    let circuit: C = from_js(inputs)?;
    Ok(circuit.export_assignment()?)
}

/// Loads a memory-image key after checking its SHA-256 against a trusted
/// digest pinned by the application. Do not derive the expected digest from
/// the downloaded key itself. `prover_from_zkey` accepts the canonical format.
#[cfg(feature = "wasm-prover")]
pub fn prover_from_key<P: ZkCircuit + 'static>(
    proving_key: &[u8],
    expected_sha256: &[u8],
) -> Result<Groth16Prover<P>, JsValue> {
    let checksum = <&[u8; 32]>::try_from(expected_sha256).map_err(|_| {
        ProverError::from(ProverErrorKind::InvalidArgument(
            "expectedSha256 must contain exactly 32 bytes".into(),
        ))
    })?;
    Ok(Groth16Keys::from_image_checked(proving_key, checksum).and_then(Groth16Prover::new)?)
}

#[cfg(feature = "wasm-prover")]
pub fn prover_from_zkey<P: ZkCircuit + 'static>(zkey: &[u8]) -> Result<Groth16Prover<P>, JsValue> {
    Ok(Groth16Prover::from_zkey_bytes(zkey)?)
}

#[cfg(feature = "wasm-prover")]
pub fn prove<P: ZkCircuit + 'static>(
    prover: &Groth16Prover<P>,
    proof_inputs: &[u8],
) -> Result<JsValue, JsValue> {
    let result = ProofInputs::from_bytes(proof_inputs)
        .and_then(|proof_inputs| prover.prove_inputs(&proof_inputs))?;
    to_js(&Proof::try_from(&result)?)
}

/// Checks a proof against a gnark verifying key. Returns false for a proof
/// that does not verify or whose compressed form is not the proof's.
#[cfg(feature = "wasm-verify")]
#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof(
    #[wasm_bindgen(js_name = verifyingKey)] verifying_key: &[u8],
    #[wasm_bindgen(unchecked_param_type = "Proof")] proof: JsValue,
) -> Result<bool, JsValue> {
    use groth16_solana::vk::gnark::parse_gnark_vk_bytes;

    let proof: Proof = from_js(proof)?;
    if !compressed_matches(&proof) {
        return Ok(false);
    }
    let verifying_key = parse_gnark_vk_bytes(verifying_key)
        .map_err(|error| ProverError::from(ProverErrorKind::InvalidVerifyingKey(error)))?;
    let public_inputs: Vec<[u8; 32]> = proof.public_inputs.iter().map(|input| **input).collect();
    let solana_proof = crate::SolanaProof {
        a: proof.proof.a,
        b: proof.proof.b,
        c: proof.proof.c,
    };
    Ok(
        crate::prover::verify_groth16(&solana_proof, &public_inputs, &verifying_key.as_borrowed())
            .is_ok(),
    )
}

#[cfg(feature = "wasm-verify")]
fn compressed_matches(proof: &Proof) -> bool {
    use solana_bn254::compression::prelude::{
        alt_bn128_g1_decompress_be, alt_bn128_g2_decompress_be,
    };

    alt_bn128_g1_decompress_be(&proof.compressed_proof.a).is_ok_and(|a| a == proof.proof.a)
        && alt_bn128_g2_decompress_be(&proof.compressed_proof.b).is_ok_and(|b| b == proof.proof.b)
        && alt_bn128_g1_decompress_be(&proof.compressed_proof.c).is_ok_and(|c| c == proof.proof.c)
}
