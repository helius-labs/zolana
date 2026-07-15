use anyhow::Result;
use solana_address::Address;
use swap_prover::OrderTermsFieldElements;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::BLINDING_LEN, hash::hash_field, NullifierKey, P256Pubkey, PublicKey,
    ShieldedAddress,
};
pub use zolana_transaction::SOL_ASSET_ID;
use zolana_transaction::{
    instructions::{transact::OutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::err;

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
        crate::witness::order_data_hash(&self.field_elements()?)
    }

    pub fn field_elements(&self) -> Result<OrderTermsFieldElements> {
        Ok(OrderTermsFieldElements {
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
    pub fn output_utxo(&self, taker_viewing_pk: P256Pubkey) -> Result<OutputUtxo> {
        let data_hash = self.terms.data_hash()?;
        let nullifier_pubkey = Self::nullifier_key().pubkey().map_err(err)?;
        let owner_address = ShieldedAddress {
            signing_pubkey: Self::pda_owner(),
            nullifier_pubkey,
            viewing_pubkey: taker_viewing_pk,
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
        crate::witness::derive_destination_blinding(&self.blinding)
    }

    pub fn destination_ciphertext(&self, destination_output: &OutputUtxo) -> Result<Vec<u8>> {
        Ok(crate::witness::destination_ciphertext_with_hash(
            &self.blinding,
            &self.terms.destination_mint,
            self.terms.destination_amount,
            &destination_output.blinding,
        )?
        .0)
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

/// A fill/cancel payout: a UTXO owned by the recipient's shielded address.
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
