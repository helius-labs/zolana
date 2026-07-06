use anyhow::Result;
use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
use zolana_transaction::{
    instructions::{
        transact::{no_address_hashes, private_tx_hash, OutputUtxo},
        types::SpendUtxo,
    },
    utxo::{Blinding, Utxo},
    Data, SOL_MINT,
};

use crate::err;

pub const SOL_ASSET_ID: u64 = 1;

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

#[derive(Clone, Debug)]
pub struct OrderTerms {
    pub source_asset_id: u64,
    pub source_amount: u64,
    pub destination_asset_id: u64,
    pub destination_mint: Address,
    pub destination_amount: u64,
    pub maker_owner_hash: [u8; 32],
    pub maker_viewing_pk: [u8; 33],
    pub expiry: u64,
    pub taker_pk_fe: [u8; 32],
    pub fill_mode: u64,
}

impl OrderTerms {
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        swap_prover::OrderTerms {
            destination_asset: self.destination_mint,
            destination_amount: self.destination_amount,
            maker_owner_hash: self.maker_owner_hash,
            maker_viewing_pk: self.maker_viewing_pk,
            expiry: self.expiry,
            taker_pk_fe: self.taker_pk_fe,
            fill_mode: self.fill_mode,
        }
        .data_hash()
        .map_err(err)
    }

    pub fn utxo_data_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 + 8 + 32);
        out.extend_from_slice(&self.destination_asset_id.to_be_bytes());
        out.extend_from_slice(&self.destination_amount.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.taker_pk_fe);
        out
    }
}

/// The escrow UTXO's two representations: the output minted at create time and
/// the spend consumed at fill/cancel time. Both share the escrow-authority PDA
/// as the ed25519 owner key and the zero-secret nullifier key -- the synthetic
/// shielded address that the swap program signs for via `invoke_signed` -- so
/// their utxo hashes are byte-identical.
#[derive(Clone, Debug)]
pub struct Escrow {
    pub terms: OrderTerms,
    pub blinding: Blinding,
    pub source_mint: Address,
}

impl Escrow {
    fn pda_owner() -> PublicKey {
        PublicKey::from_ed25519(crate::escrow_authority_pda().as_array())
    }

    fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    /// The taker's viewing pubkey makes the escrow slot ciphertext
    /// readable by the taker; its `owner_hash` is a constant across
    /// orders and matches the prover's `escrow_owner_hash(pda)`.
    pub fn output(&self, taker_viewing_pk: P256Pubkey) -> Result<OutputUtxo> {
        let data_hash = self.terms.data_hash()?;
        let nullifier_pubkey = Self::nullifier_key().pubkey().map_err(err)?;
        let owner_address = ShieldedAddress {
            signing_pubkey: Self::pda_owner(),
            nullifier_pubkey,
            viewing_pubkey: taker_viewing_pk,
        };
        Ok(OutputUtxo {
            asset: self.source_mint,
            amount: self.terms.source_amount,
            blinding: self.blinding,
            owner_address: Some(owner_address),
            ..Default::default()
        }
        .with_utxo_data(self.terms.utxo_data_bytes(), data_hash))
    }

    /// The escrow input spend: the opening (terms + blinding) is the full spend
    /// capability; the swap program signs for the PDA via `invoke_signed`.
    pub fn spend(&self) -> Result<SpendUtxo> {
        let utxo = Utxo {
            owner: Self::pda_owner(),
            asset: self.source_mint,
            amount: self.terms.source_amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let mut spend = SpendUtxo::from_nullifier_key(utxo, &Self::nullifier_key());
        spend.data_hash = Some(self.terms.data_hash()?);
        Ok(spend)
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
pub fn marker_output(taker_address: ShieldedAddress) -> OutputUtxo {
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

pub fn sdk_private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    private_tx_hash(
        input_hashes,
        output_hashes,
        &no_address_hashes(input_hashes.len()),
        external_data_hash,
    )
    .map_err(err)
}
