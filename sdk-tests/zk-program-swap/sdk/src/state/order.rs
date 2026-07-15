use anyhow::Result;
use solana_address::Address;
use swap_program::instructions::shared::u64_right_align;
use swap_prover::OrderTermsProofInput;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, poseidon},
    CompressedShieldedAddress, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::err;

pub trait DataHash {
    fn data_hash(&self) -> Result<[u8; 32]>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderTerms {
    pub destination_mint: Address,
    pub destination_amount: u64,

    pub destination: ShieldedAddress,
    pub taker: Address,

    pub expiry: u64,
    // With or without verifiable encryption.
    pub take_mode: u64,
}

#[derive(SchemaWrite, SchemaRead, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainTextData {
    pub destination_asset_id: u64,
    pub destination_amount: u64,
    pub expiry: u64,
    pub taker: Address,
    pub take_mode: u64,
}

/// The order UTXO's two representations: the output minted at create time and
/// the spend consumed at take/cancel time. Both share the order-authority PDA
/// as the ed25519 owner key and the zero-secret nullifier key -- the synthetic
/// shielded address that the swap program signs for via `invoke_signed` -- so
/// their utxo hashes are byte-identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderUtxo {
    pub terms: OrderTerms,
    pub blinding: Blinding,
    pub source_mint: Address,
    pub source_amount: u64,
    pub destination_asset_id: u64,
}

// All instructions: the order terms are private inputs to each circuit; the
// order utxo's data hash is computed over them.
impl OrderTerms {
    // The utxo itself commits source amount and mint.
    // The data hash constrains:
    // 1. the mint we want to swap into
    // 2. how many tokens of the mint we want to swap into
    // 3. which shielded pubkey the swap settlement will go to
    // 4. the order expiry
    // 5. the taker allowed to take
    // 6. the take_mode
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        OrderTermsProofInput::try_from(self)?.data_hash()
    }
}

// All instructions: the terms enter the circuits in this form.
impl TryFrom<&OrderTerms> for OrderTermsProofInput {
    type Error = anyhow::Error;

    fn try_from(terms: &OrderTerms) -> Result<Self> {
        Ok(Self {
            destination_asset: hash_field(terms.destination_mint.as_array()).map_err(err)?,
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            take_mode: terms.take_mode,
        })
    }
}

// All instructions: the proofs recompute this hash from the terms.
impl DataHash for OrderTermsProofInput {
    fn data_hash(&self) -> Result<[u8; 32]> {
        let maker_address = CompressedShieldedAddress {
            owner_hash: self.maker_owner_hash,
            viewing_pubkey: P256Pubkey::from_bytes(self.maker_viewing_pk).map_err(err)?,
        }
        .hash()
        .map_err(err)?;
        poseidon(&[
            &self.destination_asset,
            &u64_right_align(self.destination_amount),
            &maker_address,
            &u64_right_align(self.expiry),
            &self.taker_pk_fe,
            &u64_right_align(self.take_mode),
        ])
        .map_err(err)
    }
}

// All instructions: the taker pubkey as the `taker_pk_fe` terms field.
impl DataHash for Address {
    fn data_hash(&self) -> Result<[u8; 32]> {
        hash_field(self.as_array()).map_err(err)
    }
}

// make mints to the synthetic order owner; take,
// take_verifiable_encryption, and cancel spend from it.
impl OrderUtxo {
    fn pda_owner() -> PublicKey {
        PublicKey::from_ed25519(crate::order_authority_pda().as_array())
    }

    /// Constant nullifier key so that both counterparties can spend this utxo.
    fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }
}

// make: the taker-readable note payload encrypted into the order
// output slot; discover decodes it back into the terms.
impl OrderTerms {
    pub fn to_plaintext(&self, destination_asset_id: u64) -> PlainTextData {
        PlainTextData {
            destination_asset_id,
            destination_amount: self.destination_amount,
            expiry: self.expiry,
            taker: self.taker,
            take_mode: self.take_mode,
        }
    }
}

// make: serialized into the order note; discover: deserialized from
// it.
impl PlainTextData {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        wincode::serialize(self).map_err(err)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        wincode::deserialize_exact(bytes).map_err(err)
    }
}

// make: the order output; discover recomputes it to match the output
// slots fetched from the indexer.
impl OrderUtxo {
    /// The taker's viewing pubkey makes the order slot ciphertext
    /// readable by the taker; its `owner_hash` is a constant across orders.
    pub fn output_utxo(&self, taker_viewing_pubkey: P256Pubkey) -> Result<SppProofOutputUtxo> {
        let data_hash = self.terms.data_hash()?;
        let nullifier_pubkey = Self::nullifier_key().pubkey().map_err(err)?;
        let owner_address = ShieldedAddress {
            signing_pubkey: Self::pda_owner(),
            nullifier_pubkey,
            viewing_pubkey: taker_viewing_pubkey,
        };
        Ok(SppProofOutputUtxo {
            asset: self.source_mint,
            amount: self.source_amount,
            blinding: self.blinding,
            owner_address: Some(owner_address),
            ..Default::default()
        }
        .with_utxo_data(
            self.terms
                .to_plaintext(self.destination_asset_id)
                .serialize()?,
            data_hash,
        ))
    }
}

// take, take_verifiable_encryption, cancel: spend the order utxo and pay out the
// source funds (to the taker on take, back to the maker on cancel).
impl OrderUtxo {
    /// The order input spend: the opening (terms + blinding) is the full spend
    /// capability; the swap program signs for the PDA via `invoke_signed`.
    pub fn to_input_utxo(&self) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: Self::pda_owner(),
            asset: self.source_mint,
            amount: self.source_amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, Self::nullifier_key())
            .with_data_hash(self.terms.data_hash()?))
    }

    pub fn source_output(
        &self,
        recipient: ShieldedAddress,
        blinding: Blinding,
    ) -> SppProofOutputUtxo {
        SppProofOutputUtxo {
            asset: self.source_mint,
            amount: self.source_amount,
            blinding,
            owner_address: Some(recipient),
            ..Default::default()
        }
    }
}

// take, take_verifiable_encryption: pay out the maker's destination funds.
impl OrderUtxo {
    pub fn destination_output(
        &self,
        recipient: ShieldedAddress,
        blinding: Blinding,
    ) -> SppProofOutputUtxo {
        SppProofOutputUtxo {
            asset: self.terms.destination_mint,
            amount: self.terms.destination_amount,
            blinding,
            owner_address: Some(recipient),
            ..Default::default()
        }
    }
}

// take: the take circuit derives the destination blinding from the order utxo
// blinding, so the maker recomputes the payout from the opening instead of
// decrypting a ciphertext.
impl OrderUtxo {
    pub fn derived_destination_output(
        &self,
        recipient: ShieldedAddress,
    ) -> Result<SppProofOutputUtxo> {
        Ok(self.destination_output(recipient, self.derived_destination_blinding()?))
    }

    pub fn derived_destination_blinding(&self) -> Result<Blinding> {
        crate::instructions::take::derive_destination_blinding(&self.blinding)
    }
}

// take_verifiable_encryption: the maker-readable ciphertext of the destination
// payout; the proof checks it against the payout output.
impl OrderUtxo {
    pub fn destination_ciphertext(
        &self,
        destination_output: &SppProofOutputUtxo,
    ) -> Result<Vec<u8>> {
        Ok(
            crate::instructions::take_verifiable_encryption::destination_ciphertext_with_hash(
                &self.blinding,
                &self.terms.destination_mint,
                self.terms.destination_amount,
                &destination_output.blinding,
            )?
            .0,
        )
    }
}

#[cfg(test)]
mod tests {
    use swap_prover::{TAKE_MODE_DERIVED, TAKE_MODE_VERIFIABLE};
    use zolana_keypair::ViewingKey;

    use super::*;

    fn sample_viewing_pk(seed: u8) -> P256Pubkey {
        ViewingKey::from_seed(&[seed; 32], 0).unwrap().pubkey()
    }

    fn sample_terms(take_mode: u64) -> OrderTermsProofInput {
        OrderTermsProofInput {
            destination_asset: hash_field(&[2u8; 32]).expect("destination asset"),
            destination_amount: 250,
            maker_owner_hash: [7u8; 32],
            maker_viewing_pk: *sample_viewing_pk(9).as_bytes(),
            expiry: 1_700_000_000,
            taker_pk_fe: [11u8; 32],
            take_mode,
        }
    }

    #[test]
    fn data_hash_binds_take_mode() {
        let derived = sample_terms(TAKE_MODE_DERIVED).data_hash().unwrap();
        let verifiable = sample_terms(TAKE_MODE_VERIFIABLE).data_hash().unwrap();
        assert_ne!(
            derived, verifiable,
            "order dataHash must distinguish the authorized take instruction, so an order created for one take cannot be settled by the other"
        );
    }
}
