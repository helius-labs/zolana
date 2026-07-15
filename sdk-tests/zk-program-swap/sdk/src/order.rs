use anyhow::Result;
use solana_address::Address;
use swap_program::instructions::shared::u64_to_field;
use swap_prover::OrderTermsProofInput;
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::merge_utils::pack33;
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, poseidon},
    NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
pub use zolana_transaction::SOL_ASSET_ID;
use zolana_transaction::{
    instructions::{transact::OutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::err;

pub fn input_sum(inputs: &[SppProofInputUtxo], asset: &Address) -> i128 {
    inputs
        .iter()
        .filter(|spend| &spend.utxo.asset == asset)
        .map(|spend| i128::from(spend.utxo.amount))
        .sum()
}

pub fn escrow_owner_hash(escrow_authority: &[u8; 32]) -> Result<[u8; 32]> {
    let pk_field = hash_field(escrow_authority).map_err(err)?;
    let nullifier_pk = NullifierKey::from_secret([0u8; BLINDING_LEN])
        .pubkey()
        .map_err(err)?;
    poseidon(&[&pk_field, &nullifier_pk]).map_err(err)
}

pub fn maker_address_fe(owner_hash: &[u8; 32], viewing_pk: &[u8; 33]) -> Result<[u8; 32]> {
    let (lo, hi) = pack33(viewing_pk);
    poseidon(&[owner_hash, &lo, &hi]).map_err(err)
}

impl DataHash for OrderTermsProofInput {
    fn data_hash(&self) -> Result<[u8; 32]> {
        let maker_address = maker_address_fe(&self.maker_owner_hash, &self.maker_viewing_pk)?;
        poseidon(&[
            &self.destination_asset,
            &u64_to_field(self.destination_amount),
            &maker_address,
            &u64_to_field(self.expiry),
            &self.taker_pk_fe,
            &u64_to_field(self.fill_mode),
        ])
        .map_err(err)
    }
}

pub trait BlindingField {
    fn to_field(&self) -> [u8; 32];
}

impl BlindingField for Blinding {
    fn to_field(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[1..].copy_from_slice(self);
        out
    }
}

pub trait DataHash {
    fn data_hash(&self) -> Result<[u8; 32]>;
}

impl DataHash for Address {
    fn data_hash(&self) -> Result<[u8; 32]> {
        hash_field(self.as_array()).map_err(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderTerms {
    pub destination_mint: Address,
    pub destination_amount: u64,

    pub destination: ShieldedAddress,
    pub taker: Address,

    pub expiry: u64,
    // With or without verifiable encryption.
    pub fill_mode: u64,
}

impl OrderTerms {
    // The utxo itself commits source amount and mint.
    // The data hash constrains:
    // 1. the mint we want to swap into
    // 2. how many tokens of the mint we want to swap into
    // 3. which shielded pubkey the swap settlement will go to
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        self.field_elements()?.data_hash()
    }
    // TODO: implement From instead
    pub fn field_elements(&self) -> Result<OrderTermsProofInput> {
        Ok(OrderTermsProofInput {
            destination_asset: hash_field(self.destination_mint.as_array()).map_err(err)?,
            destination_amount: self.destination_amount,
            maker_owner_hash: self.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *self.destination.viewing_pubkey.as_bytes(),
            expiry: self.expiry,
            taker_pk_fe: self.taker.data_hash()?,
            fill_mode: self.fill_mode,
        })
    }

    pub fn to_plaintext(&self, destination_asset_id: u64) -> PlainTextData {
        PlainTextData {
            destination_asset_id,
            destination_amount: self.destination_amount,
            expiry: self.expiry,
            taker: self.taker,
            fill_mode: self.fill_mode,
        }
    }
}

#[derive(SchemaWrite, SchemaRead, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainTextData {
    pub destination_asset_id: u64,
    pub destination_amount: u64,
    pub expiry: u64,
    pub taker: Address,
    pub fill_mode: u64,
}

impl PlainTextData {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        wincode::serialize(self).map_err(err)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        wincode::deserialize_exact(bytes).map_err(err)
    }
}

/// The escrow UTXO's two representations: the output minted at create time and
/// the spend consumed at fill/cancel time. Both share the escrow-authority PDA
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

impl OrderUtxo {
    fn pda_owner() -> PublicKey {
        PublicKey::from_ed25519(crate::escrow_authority_pda().as_array())
    }

    /// Constant nullifier key so that both counter parties can spend this utxo.
    fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    /// The taker's viewing pubkey makes the escrow slot ciphertext
    /// readable by the taker; its `owner_hash` is a constant across
    /// orders and matches the prover's `escrow_owner_hash(pda)`.
    pub fn output_utxo(&self, taker_viewing_pubkey: P256Pubkey) -> Result<OutputUtxo> {
        let data_hash = self.terms.data_hash()?;
        let nullifier_pubkey = Self::nullifier_key().pubkey().map_err(err)?;
        let owner_address = ShieldedAddress {
            signing_pubkey: Self::pda_owner(),
            nullifier_pubkey,
            viewing_pubkey: taker_viewing_pubkey,
        };
        Ok(OutputUtxo {
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

    /// The escrow input spend: the opening (terms + blinding) is the full spend
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

    pub fn source_output(&self, recipient: ShieldedAddress, blinding: Blinding) -> OutputUtxo {
        Recipient {
            address: recipient,
            amount: self.source_amount,
            blinding,
            mint: self.source_mint,
        }
        .output()
    }

    pub fn destination_output(&self, recipient: ShieldedAddress, blinding: Blinding) -> OutputUtxo {
        Recipient {
            address: recipient,
            amount: self.terms.destination_amount,
            blinding,
            mint: self.terms.destination_mint,
        }
        .output()
    }

    /// The derived rail: the fill circuit derives the destination blinding from
    /// the escrow blinding, so the maker recomputes it from the opening without
    /// a ciphertext.
    pub fn derived_destination_output(&self, recipient: ShieldedAddress) -> Result<OutputUtxo> {
        Ok(self.destination_output(recipient, self.derived_destination_blinding()?))
    }

    pub fn derived_destination_blinding(&self) -> Result<Blinding> {
        crate::instructions::fill::derive_destination_blinding(&self.blinding)
    }

    pub fn destination_ciphertext(&self, destination_output: &OutputUtxo) -> Result<Vec<u8>> {
        Ok(
            crate::instructions::fill_verifiable_encryption::destination_ciphertext_with_hash(
                &self.blinding,
                &self.terms.destination_mint,
                self.terms.destination_amount,
                &destination_output.blinding,
            )?
            .0,
        )
    }
}

pub(crate) fn ensure_payout(
    label: &str,
    output: &OutputUtxo,
    mint: &Address,
    amount: u64,
) -> Result<ShieldedAddress> {
    let owner = output
        .owner_address
        .ok_or_else(|| err(format!("{label} owner address missing")))?;
    if &output.asset != mint {
        return Err(err(format!("{label} asset mismatch")));
    }
    if output.amount != amount {
        return Err(err(format!("{label} amount mismatch")));
    }
    if output.data_hash.is_some()
        || output.zone_data_hash.is_some()
        || output.zone_program_id.is_some()
    {
        return Err(err(format!(
            "{label} must not carry data or zone commitments"
        )));
    }
    Ok(owner)
}

// TODO: remove use OutputUtxo directly instead
#[derive(Clone, Copy, Debug)]
pub struct Recipient {
    pub address: ShieldedAddress,
    pub amount: u64,
    pub blinding: Blinding,
    pub mint: Address,
}

impl Recipient {
    pub fn output(&self) -> OutputUtxo {
        OutputUtxo {
            asset: self.mint,
            amount: self.amount,
            blinding: self.blinding,
            owner_address: Some(self.address),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use swap_prover::{FILL_MODE_DERIVED, FILL_MODE_VERIFIABLE};
    use zolana_keypair::{CompressedShieldedAddress, ViewingKey};

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

    fn sample_terms(fill_mode: u64) -> OrderTermsProofInput {
        OrderTermsProofInput {
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
        let derived = sample_terms(FILL_MODE_DERIVED).data_hash().unwrap();
        let verifiable = sample_terms(FILL_MODE_VERIFIABLE).data_hash().unwrap();
        assert_ne!(
            derived, verifiable,
            "escrow dataHash must distinguish the authorized fill instruction, so an escrow created for one fill cannot be settled by the other"
        );
    }
}
