use anyhow::Result;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_keypair::{
    constants::BLINDING_LEN, hash::owner_hash, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::err;

/// The pool's live destination-asset UTXO is owned by the per-pair
/// `pool_authority` PDA (seeds `[POOL_AUTHORITY_PDA_SEED, pair]`), the same
/// synthetic-owner trick `zk-program-swap`'s `order_authority_pda` uses: a
/// constant (zero-secret) nullifier key so the program can always sign for a
/// spend via `invoke_signed`, with no real private key involved.
pub struct PoolAuthority;

impl PoolAuthority {
    fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    fn signing_pubkey(pair: &Pubkey) -> PublicKey {
        PublicKey::from_ed25519(crate::pool_authority_pda(pair).as_array())
    }

    /// The owner-hash committed by every UTXO owned by `pool_authority` for
    /// this pair -- the `PoolIn.Owner`/`PoolOut.Owner` value every circuit
    /// binds the pool's live UTXO to.
    pub fn owner_hash(pair: &Pubkey) -> Result<[u8; 32]> {
        let nullifier_pubkey = Self::nullifier_key().pubkey().map_err(err)?;
        owner_hash(&Self::signing_pubkey(pair), &nullifier_pubkey).map_err(err)
    }

    pub fn shielded_address(pair: &Pubkey, viewing_pubkey: P256Pubkey) -> Result<ShieldedAddress> {
        Ok(ShieldedAddress {
            signing_pubkey: Self::signing_pubkey(pair),
            nullifier_pubkey: Self::nullifier_key().pubkey().map_err(err)?,
            viewing_pubkey,
        })
    }

    /// The pool's live UTXO as an input spend. Pool updates and settlement
    /// spend it; order opening and refund deliberately do not.
    pub fn to_input_utxo(
        pair: &Pubkey,
        asset: Address,
        amount: u64,
        blinding: Blinding,
    ) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: Self::signing_pubkey(pair),
            asset,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, Self::nullifier_key()))
    }

    /// The pool's newly recreated UTXO as an output. Every circuit asserts
    /// `PoolOut.DataHash == 0`, so this never carries a data commitment.
    pub fn output_utxo(
        pair: &Pubkey,
        asset: Address,
        amount: u64,
        blinding: Blinding,
        viewing_pubkey: P256Pubkey,
    ) -> Result<SppProofOutputUtxo> {
        Ok(SppProofOutputUtxo {
            asset,
            amount,
            blinding,
            owner_address: Some(Self::shielded_address(pair, viewing_pubkey)?),
            ..Default::default()
        })
    }
}
