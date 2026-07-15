use anyhow::Result;
use solana_address::Address;
use swap_program::instructions::shared::u64_right_align;
use swap_prover::TAKE_ENC_KDF_DOMAIN;
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, poseidon},
    merge::{merge_ciphertext_hash, symmetric_apply, MERGE_INFO},
};
use zolana_transaction::utxo::Blinding;

use crate::{err, shared::right_align_blinding};

fn take_shared_secret(order_utxo_blinding: &Blinding) -> Result<[u8; 32]> {
    let domain = u64_right_align(TAKE_ENC_KDF_DOMAIN);
    poseidon(&[&right_align_blinding(order_utxo_blinding), &domain]).map_err(err)
}

pub fn destination_ciphertext_with_hash(
    order_utxo_blinding: &Blinding,
    destination_mint: &Address,
    destination_amount: u64,
    destination_output_blinding: &Blinding,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut plaintext = Vec::with_capacity(8 + 32 + BLINDING_LEN);
    plaintext.extend_from_slice(&destination_amount.to_be_bytes());
    plaintext.extend_from_slice(&hash_field(destination_mint.as_array()).map_err(err)?);
    plaintext.extend_from_slice(destination_output_blinding);
    symmetric_apply(
        &take_shared_secret(order_utxo_blinding)?,
        MERGE_INFO,
        &mut plaintext,
    )
    .map_err(err)?;
    let ct_hash = merge_ciphertext_hash(&plaintext).map_err(err)?;
    Ok((plaintext, ct_hash))
}

pub fn decrypt_destination(
    order_utxo_blinding: &Blinding,
    ciphertext: &[u8],
) -> Result<([u8; 32], u64)> {
    let mut plaintext = ciphertext.to_vec();
    symmetric_apply(
        &take_shared_secret(order_utxo_blinding)?,
        MERGE_INFO,
        &mut plaintext,
    )
    .map_err(err)?;
    let amount_bytes: [u8; 8] = plaintext
        .get(0..8)
        .ok_or_else(|| err("take plaintext amount"))?
        .try_into()
        .map_err(err)?;
    let asset: [u8; 32] = plaintext
        .get(8..40)
        .ok_or_else(|| err("take plaintext asset"))?
        .try_into()
        .map_err(err)?;
    Ok((asset, u64::from_be_bytes(amount_bytes)))
}
