use anyhow::Result;
use solana_address::Address;
use swap_program::instructions::shared::u64_right_align;
use swap_prover::TAKE_ENC_KDF_DOMAIN;
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::{derivation::MERGE_INFO, hash::poseidon, symmetric_apply};
use zolana_transaction::utxo::Blinding;

use crate::{err, shared::right_align_blinding};

pub const DESTINATION_CIPHERTEXT_LEN: usize = 8 + 32 + 31;

fn take_shared_secret(order_utxo_blinding: &Blinding) -> Result<[u8; 32]> {
    let domain = u64_right_align(TAKE_ENC_KDF_DOMAIN);
    poseidon(&[&right_align_blinding(order_utxo_blinding), &domain]).map_err(err)
}

pub fn destination_ciphertext_with_hash(
    order_utxo_blinding: &Blinding,
    destination_mint: &Address,
    destination_amount: u64,
    destination_output_blinding: &Blinding,
) -> Result<([u8; DESTINATION_CIPHERTEXT_LEN], [u8; 32])> {
    // The take circuit packs the blinding as its low 31 bytes; keep that wire
    // layout (the blinding is a 32-byte field element with a zero top byte).
    let mut plaintext = [0u8; DESTINATION_CIPHERTEXT_LEN];
    plaintext[..8].copy_from_slice(&destination_amount.to_be_bytes());
    plaintext[8..40].copy_from_slice(&hash_bytes(destination_mint.as_array()).map_err(err)?);
    plaintext[40..].copy_from_slice(&destination_output_blinding[1..]);
    symmetric_apply(
        &take_shared_secret(order_utxo_blinding)?,
        MERGE_INFO,
        &mut plaintext,
    )
    .map_err(err)?;
    let ct_hash = hash_bytes(&plaintext).map_err(err)?;
    Ok((plaintext, ct_hash))
}

pub fn decrypt_destination(
    order_utxo_blinding: &Blinding,
    ciphertext: &[u8; DESTINATION_CIPHERTEXT_LEN],
) -> Result<([u8; 32], u64)> {
    let mut plaintext = *ciphertext;
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
