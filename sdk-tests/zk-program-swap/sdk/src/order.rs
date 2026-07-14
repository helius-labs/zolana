use anyhow::Result;
use solana_address::Address;
use swap_prover::order_terms::maker_address_fe;
use wincode::{SchemaRead, SchemaWrite};
use zolana_keypair::{
    constants::BLINDING_LEN, hash::hash_field, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
pub use zolana_transaction::SOL_ASSET_ID;
use zolana_transaction::{
    instructions::{transact::OutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data, SOL_MINT,
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

impl DataHash for ShieldedAddress {
    fn data_hash(&self) -> Result<[u8; 32]> {
        maker_address_fe(
            &self.owner_hash().map_err(err)?,
            self.viewing_pubkey.as_bytes(),
        )
        .map_err(err)
    }
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
        swap_prover::OrderTerms {
            destination_asset: self.destination_mint,
            destination_amount: self.destination_amount,
            destination: self.destination.data_hash()?,
            taker: self.taker.data_hash()?,
            expiry: self.expiry,
            fill_mode: self.fill_mode,
        }
        .data_hash()
        .map_err(err)
    }

    pub fn into_plaintext(&self, destination_asset_id: u64) -> PlainTextData {
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
                .into_plaintext(self.destination_asset_id)
                .serialize()?,
            data_hash,
        ))
    }

    /// The escrow input spend: the opening (terms + blinding) is the full spend
    /// capability; the swap program signs for the PDA via `invoke_signed`.
    pub fn into_input_utxo(&self) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: Self::pda_owner(),
            asset: self.source_mint,
            amount: self.source_amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, &Self::nullifier_key())
            .with_data_hash(self.terms.data_hash()?))
    }
}

/// Fixed blinding of the marker output. The marker is never spent and the state
/// tree is append-only (output hashes, unlike nullifiers, need not be unique), so a
/// deterministic zero blinding is safe and lets the market maker recognize the
/// marker by value without decrypting it.
pub const MARKER_BLINDING: Blinding = [0u8; BLINDING_LEN];

/// The marker output: a 0-value UTXO owned by the taker, minted in the create
/// transact as the taker's discovery identifier. Its ciphertext slot is
/// tagged with the taker's view tag so ordinary wallet sync finds the order;
/// the taker then decrypts the escrow slot for the opening. The asset is fixed
/// to `SOL_MINT`: the marker is 0-value, so its asset never enters balance
/// conservation, and a constant asset makes the marker fully deterministic from the
/// taker's address alone (independent of the order's source asset).
pub fn marker_output_utxo(taker_address: ShieldedAddress) -> OutputUtxo {
    OutputUtxo {
        asset: SOL_MINT,
        amount: 0,
        blinding: MARKER_BLINDING,
        owner_address: Some(taker_address),
        ..Default::default()
    }
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
