mod types;

use core::str::FromStr;

use serde::{de::DeserializeOwned, Serialize};
use solana_address::Address;
use wasm_bindgen::prelude::*;
use zolana_keypair::{ShieldedAddress, SHIELDED_ADDRESS_LEN};
use zolana_transaction::WalletUtxo;

pub use types::{
    CompressedGroth16Proof, FinalizedTransaction, Groth16Proof, OwnerTag, ProgramProof,
    ProgramTransaction, ResolvedOwnerTag,
};
pub use zk_program_sdk_macros::ZkProgramWasm;

use crate::{CircuitError, ClientError, ClientErrorKind, ProverError, SourceLocation, ZkProgram};
#[cfg(feature = "wasm-prover")]
use crate::{Groth16Keys, Groth16Prover, ProofInputs};

#[doc(hidden)]
pub mod __private {
    pub use js_sys;
    pub use serde_wasm_bindgen;
    pub use tsify;
    pub use wasm_bindgen;
}

#[cfg(feature = "wasm-prover")]
#[doc(hidden)]
#[macro_export]
macro_rules! __zk_program_wasm_prover {
    ($prover:ident, $program:ty) => {
        #[wasm_bindgen(wasm_bindgen = $crate::wasm::__private::wasm_bindgen)]
        pub struct $prover($crate::Groth16Prover<$program>);

        #[wasm_bindgen]
        impl $prover {
            #[wasm_bindgen(js_name = fromKey)]
            pub fn from_key(
                #[wasm_bindgen(js_name = provingKey)] proving_key: &[u8],
            ) -> ::core::result::Result<$prover, $crate::wasm::__private::wasm_bindgen::JsValue>
            {
                $crate::wasm::prover_from_key::<$program>(proving_key).map(Self)
            }

            #[wasm_bindgen(js_name = fromZkey)]
            pub fn from_zkey(
                zkey: &[u8],
            ) -> ::core::result::Result<$prover, $crate::wasm::__private::wasm_bindgen::JsValue>
            {
                $crate::wasm::prover_from_zkey::<$program>(zkey).map(Self)
            }

            #[wasm_bindgen(unchecked_return_type = "ProgramProof")]
            pub fn prove(
                &self,
                #[wasm_bindgen(js_name = proofInputs)] proof_inputs: &[u8],
            ) -> ::core::result::Result<
                $crate::wasm::__private::wasm_bindgen::JsValue,
                $crate::wasm::__private::wasm_bindgen::JsValue,
            > {
                $crate::wasm::prove(&self.0, proof_inputs)
            }
        }
    };
}

#[cfg(not(feature = "wasm-prover"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __zk_program_wasm_prover {
    ($prover:ident, $program:ty) => {};
}

fn js_error(name: &str, message: &str, location: SourceLocation) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name(name);
    let _ = js_sys::Reflect::set(
        &error,
        &JsValue::from_str("location"),
        &JsValue::from_str(&location.to_string()),
    );
    error.into()
}

impl From<CircuitError> for JsValue {
    fn from(error: CircuitError) -> Self {
        js_error(error.name(), &error.to_string(), error.location())
    }
}

impl From<ClientError> for JsValue {
    fn from(error: ClientError) -> Self {
        js_error(error.name(), &error.to_string(), error.location())
    }
}

impl From<ProverError> for JsValue {
    fn from(error: ProverError) -> Self {
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

#[cfg(feature = "wasm-prover")]
pub fn prover_from_key<P: ZkProgram>(proving_key: &[u8]) -> Result<Groth16Prover<P>, JsValue> {
    Ok(Groth16Keys::from_bytes(proving_key).and_then(Groth16Prover::new)?)
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

#[wasm_bindgen(js_name = dummyWalletUtxo, unchecked_return_type = "WalletUtxo")]
pub fn dummy_wallet_utxo(
    #[wasm_bindgen(js_name = treeId)] tree_id: u16,
) -> Result<JsValue, JsValue> {
    let utxo = WalletUtxo::dummy(tree_id)
        .map_err(|error| ClientError::from(ClientErrorKind::InvalidUtxo(error)))?;
    to_js(&utxo)
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
    let verifying_key = parse_gnark_vk_bytes(verifying_key)
        .map_err(|error| ProverError::from(crate::ProverErrorKind::InvalidVerifyingKey(error)))?;
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
