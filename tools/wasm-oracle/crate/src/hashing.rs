//! W-03: hashing and field encoding.
//!
//! Seven of these nine entry points widen a Rust signature so a generator can
//! reach inputs the Rust type refuses: the six fixed-width byte arrays and the
//! `i64`. Each widening returns the rejection its signature implies, and each
//! carries its reasoning at the function, because a widening is a decision about
//! what Rust would have done rather than an observation of what it does.
//! `sha256_be` and `ciphertext_hash` already take `&[u8]` and widen nothing.

use solana_address::Address;
use wasm_bindgen::prelude::wasm_bindgen;
use zolana_interface::merge_utils;
use zolana_keypair::hash;
use zolana_transaction::instructions::transact::spp_proof_inputs;

use crate::{
    codec::{decode_exact, decode_hex, decode_i64, BAD_HEX, BAD_INTEGER},
    outcome::{err, err_boundary, hex, ok, ok_hex},
};

/// Widened from `hash_field(&[u8; 32])`. A 16-byte input is refused rather than
/// zero-padded: padding would put the suspected TypeScript defect inside the
/// oracle and the comparison would agree.
#[wasm_bindgen]
pub fn hash_field(value_hex: &str) -> String {
    match decode_exact::<32>(value_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(value) => match hash::hash_field(&value) {
            Ok(digest) => ok_hex(&digest),
            Err(error) => err(error),
        },
    }
}

/// Widened from `split_be_128(&[u8; 32])`, same reasoning as `hash_field`.
#[wasm_bindgen]
pub fn split_be_128(value_hex: &str) -> String {
    match decode_exact::<32>(value_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(value) => {
            let (low, high) = hash::split_be_128(&value);
            pair(&low, &high)
        }
    }
}

/// `sha256_be(&[u8])` already accepts any length, so nothing is widened here.
#[wasm_bindgen]
pub fn sha256_be(preimage_hex: &str) -> String {
    match decode_hex(preimage_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(preimage) => ok_hex(&hash::sha256_be(&preimage)),
    }
}

/// Widened from `pk_field_compressed(&[u8; 33])`.
#[wasm_bindgen]
pub fn pk_field_compressed(compressed_hex: &str) -> String {
    match decode_exact::<33>(compressed_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(compressed) => match merge_utils::pk_field_compressed(&compressed) {
            Ok(digest) => ok_hex(&digest),
            Err(error) => err(error),
        },
    }
}

/// Widened from `owner_pk_field_compressed(&[u8; 33])`.
#[wasm_bindgen]
pub fn owner_pk_field_compressed(compressed_hex: &str) -> String {
    match decode_exact::<33>(compressed_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(compressed) => match merge_utils::owner_pk_field_compressed(&compressed) {
            Ok(digest) => ok_hex(&digest),
            Err(error) => err(error),
        },
    }
}

/// Widened from `pack33(&[u8; 33])`.
#[wasm_bindgen]
pub fn pack33(bytes_hex: &str) -> String {
    match decode_exact::<33>(bytes_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(bytes) => {
            let (low, high) = merge_utils::pack33(&bytes);
            pair(&low, &high)
        }
    }
}

/// `ciphertext_hash(&[u8])` already accepts any length.
#[wasm_bindgen]
pub fn ciphertext_hash(ciphertext_hex: &str) -> String {
    match decode_hex(ciphertext_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(ciphertext) => match merge_utils::ciphertext_hash(&ciphertext) {
            Ok(digest) => ok_hex(&digest),
            Err(error) => err(error),
        },
    }
}

/// Widened from `asset_field(&Address)`. `Address` holds exactly 32 bytes, so a
/// shorter or longer input cannot reach the function.
#[wasm_bindgen]
pub fn asset_field(address_hex: &str) -> String {
    match decode_exact::<32>(address_hex) {
        Err(details) => err_boundary(BAD_HEX, details),
        Ok(address) => match spp_proof_inputs::asset_field(&Address::new_from_array(address)) {
            Ok(digest) => ok_hex(&digest),
            Err(error) => err(error),
        },
    }
}

/// Widened from `signed_to_field(value: i64)`. The decimal string carries the
/// full generator range, and anything outside `i64` is refused because the Rust
/// signature cannot hold it. Reducing modulo the field instead would reproduce
/// the suspected TypeScript behavior inside the oracle.
#[wasm_bindgen]
pub fn signed_to_field(value_dec: &str) -> String {
    match decode_i64(value_dec) {
        Err(details) => err_boundary(BAD_INTEGER, details),
        Ok(value) => ok_hex(&spp_proof_inputs::signed_to_field(value)),
    }
}

fn pair(low: &[u8; 32], high: &[u8; 32]) -> String {
    ok(serde_json::json!([hex(low), hex(high)]))
}
