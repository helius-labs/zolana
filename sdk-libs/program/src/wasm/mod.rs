//! The ZK program bindings of a wasm build: the `<name>Transaction` and
//! `<name>DataUtxo` functions the derives emit. The prover classes,
//! `verifyProof` and the proof types are the zk DSL's
//! (`zolana_zk_dsl::wasm`).

mod types;

use core::str::FromStr;

use serde::{de::DeserializeOwned, Serialize};
use solana_address::Address;
use wasm_bindgen::prelude::*;
use zolana_keypair::{ShieldedAddress, SHIELDED_ADDRESS_LEN};

pub use types::{DataUtxo, FinalizedTransaction, OwnerTag, ProgramTransaction, ResolvedOwnerTag};
pub use zolana_zk_dsl::wasm::{proof_inputs, CompressedGroth16Proof, Groth16Proof, Proof};
#[cfg(feature = "wasm-prover")]
pub use zolana_zk_dsl::wasm::{prove, prover_from_key, prover_from_zkey};

use zolana_transaction::WalletUtxo;
use zolana_zk_dsl::js_error::js_error;

use crate::{hasher::DataHasher, ClientError, ClientErrorKind, EncryptionCodec, ZkProgramCircuit};

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
    P: ZkProgramCircuit + DeserializeOwned,
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
    T: EncryptionCodec + DataHasher + Serialize,
{
    let utxo: WalletUtxo = from_js(utxo)?;
    to_js(&DataUtxo::from(crate::DataUtxo::<T>::try_from(utxo)?))
}

fn shielded_address(bytes: &[u8]) -> Result<ShieldedAddress, ClientError> {
    let bytes = <[u8; SHIELDED_ADDRESS_LEN]>::try_from(bytes)
        .map_err(|_| ClientErrorKind::SenderLength { found: bytes.len() })?;
    Ok(ShieldedAddress::from_bytes(&bytes).map_err(ClientErrorKind::InvalidSender)?)
}
