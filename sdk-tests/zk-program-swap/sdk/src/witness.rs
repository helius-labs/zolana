use anyhow::Result;
use solana_address::Address;
use swap_program::instructions::shared::{maker_address_fe, u64_to_field};
use swap_prover::{
    OrderTermsFieldElements, UtxoFieldElements, DESTINATION_BLINDING_DOMAIN, FILL_ENC_KDF_DOMAIN,
};
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, poseidon},
    merge::{merge_ciphertext_hash, symmetric_apply, MERGE_INFO},
    NullifierKey,
};
use zolana_transaction::utxo::{owner_utxo_hash, utxo_hash, Blinding};

use crate::{err, order::BlindingField};

pub fn escrow_owner_hash(escrow_authority: &[u8; 32]) -> Result<[u8; 32]> {
    let pk_field = hash_field(escrow_authority).map_err(err)?;
    let nullifier_pk = NullifierKey::from_secret([0u8; BLINDING_LEN])
        .pubkey()
        .map_err(err)?;
    poseidon(&[&pk_field, &nullifier_pk]).map_err(err)
}

pub struct PlainUtxo {
    pub owner_hash: [u8; 32],
    pub mint: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub data_hash: [u8; 32],
}

impl PlainUtxo {
    pub fn field_elements(&self) -> Result<UtxoFieldElements> {
        Ok(UtxoFieldElements::plain(
            self.owner_hash,
            hash_field(self.mint.as_array()).map_err(err)?,
            self.amount,
            self.blinding.to_field(),
            self.data_hash,
        ))
    }

    pub fn hash(&self) -> Result<[u8; 32]> {
        utxo_hash(
            self.mint,
            self.amount,
            &self.data_hash,
            &[0u8; 32],
            None,
            &owner_utxo_hash(&self.owner_hash, &self.blinding).map_err(err)?,
        )
        .map_err(err)
    }
}

pub fn order_data_hash(order: &OrderTermsFieldElements) -> Result<[u8; 32]> {
    let maker_address =
        maker_address_fe(&order.maker_owner_hash, &order.maker_viewing_pk).map_err(err)?;
    poseidon(&[
        &order.destination_asset,
        &u64_to_field(order.destination_amount),
        &maker_address,
        &u64_to_field(order.expiry),
        &order.taker_pk_fe,
        &u64_to_field(order.fill_mode),
    ])
    .map_err(err)
}

pub fn derive_destination_blinding(escrow_blinding: &Blinding) -> Result<Blinding> {
    let domain = u64_to_field(DESTINATION_BLINDING_DOMAIN);
    let derived = poseidon(&[&escrow_blinding.to_field(), &domain]).map_err(err)?;
    let mut blinding = [0u8; BLINDING_LEN];
    blinding.copy_from_slice(derived.get(1..32).ok_or_else(|| err("blinding tail"))?);
    Ok(blinding)
}

fn fill_shared_secret(escrow_blinding: &Blinding) -> Result<[u8; 32]> {
    let domain = u64_to_field(FILL_ENC_KDF_DOMAIN);
    poseidon(&[&escrow_blinding.to_field(), &domain]).map_err(err)
}

pub fn destination_ciphertext_with_hash(
    escrow_blinding: &Blinding,
    destination_mint: &Address,
    destination_amount: u64,
    destination_output_blinding: &Blinding,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut plaintext = Vec::with_capacity(8 + 32 + BLINDING_LEN);
    plaintext.extend_from_slice(&destination_amount.to_be_bytes());
    plaintext.extend_from_slice(&hash_field(destination_mint.as_array()).map_err(err)?);
    plaintext.extend_from_slice(destination_output_blinding);
    symmetric_apply(
        &fill_shared_secret(escrow_blinding)?,
        MERGE_INFO,
        &mut plaintext,
    )
    .map_err(err)?;
    let ct_hash = merge_ciphertext_hash(&plaintext).map_err(err)?;
    Ok((plaintext, ct_hash))
}

pub fn decrypt_destination(
    escrow_blinding: &Blinding,
    ciphertext: &[u8],
) -> Result<([u8; 32], u64)> {
    let mut plaintext = ciphertext.to_vec();
    symmetric_apply(
        &fill_shared_secret(escrow_blinding)?,
        MERGE_INFO,
        &mut plaintext,
    )
    .map_err(err)?;
    let amount_bytes: [u8; 8] = plaintext
        .get(0..8)
        .ok_or_else(|| err("fill plaintext amount"))?
        .try_into()
        .map_err(err)?;
    let asset: [u8; 32] = plaintext
        .get(8..40)
        .ok_or_else(|| err("fill plaintext asset"))?
        .try_into()
        .map_err(err)?;
    Ok((asset, u64::from_be_bytes(amount_bytes)))
}

#[cfg(test)]
mod tests {
    use swap_prover::{FILL_MODE_DERIVED, FILL_MODE_VERIFIABLE};
    use zolana_keypair::{CompressedShieldedAddress, P256Pubkey, ViewingKey};

    use super::*;

    fn sample_viewing_pk(seed: u8) -> P256Pubkey {
        ViewingKey::from_seed(&[seed; 32], b"order-terms-test")
            .unwrap()
            .pubkey()
    }

    #[test]
    fn compressed_address_hash_matches_program() {
        let owner_hash = [3u8; 32];
        let viewing_pubkey = sample_viewing_pk(42);
        let ours = CompressedShieldedAddress {
            owner_hash,
            viewing_pubkey,
        }
        .hash()
        .unwrap();
        let theirs = maker_address_fe(&owner_hash, viewing_pubkey.as_bytes()).unwrap();
        assert_eq!(ours, theirs);
    }

    fn sample_terms(fill_mode: u64) -> OrderTermsFieldElements {
        OrderTermsFieldElements {
            destination_asset: hash_field(&[2u8; 32]).expect("destination asset"),
            destination_amount: 250,
            maker_owner_hash: [7u8; 32],
            maker_viewing_pk: *sample_viewing_pk(9).as_bytes(),
            expiry: 1_700_000_000,
            taker_pk_fe: [11u8; 32],
            fill_mode,
        }
    }

    #[test]
    fn data_hash_binds_fill_mode() {
        let derived = order_data_hash(&sample_terms(FILL_MODE_DERIVED)).unwrap();
        let verifiable = order_data_hash(&sample_terms(FILL_MODE_VERIFIABLE)).unwrap();
        assert_ne!(
            derived, verifiable,
            "escrow dataHash must distinguish the authorized fill instruction, so an escrow created for one fill cannot be settled by the other"
        );
    }
}
