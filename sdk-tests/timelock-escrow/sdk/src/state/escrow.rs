use anyhow::Result;
use solana_address::Address;
use timelock_escrow_program::instructions::shared::u64_right_align;
use timelock_escrow_prover::EscrowTermsProofInput;
use zolana_keypair::{
    constants::BLINDING_LEN, hash::poseidon, NullifierKey, PublicKey, ShieldedAddress,
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
pub struct EscrowTerms {
    pub creator: ShieldedAddress,
    pub unlock_timestamp: u64,
}

// escrow, withdraw: the escrow terms are private inputs to each circuit; the
// escrow utxo's data hash is computed over them.
impl EscrowTerms {
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        EscrowTermsProofInput::try_from(self)?.data_hash()
    }
}

// escrow, withdraw: the terms enter the circuits in this form.
impl TryFrom<&EscrowTerms> for EscrowTermsProofInput {
    type Error = anyhow::Error;

    fn try_from(terms: &EscrowTerms) -> Result<Self> {
        Ok(Self {
            owner_hash: terms.creator.owner_hash().map_err(err)?,
            unlock: terms.unlock_timestamp,
        })
    }
}

// escrow, withdraw: the proofs recompute this hash from the terms.
impl DataHash for EscrowTermsProofInput {
    fn data_hash(&self) -> Result<[u8; 32]> {
        poseidon(&[&self.owner_hash, &u64_right_align(self.unlock)]).map_err(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowUtxo {
    pub terms: EscrowTerms,
    pub blinding: Blinding,
    pub asset: Address,
    pub amount: u64,
}

// escrow mints to the synthetic escrow-authority owner; withdraw spends from
// it.
impl EscrowUtxo {
    fn pda_owner() -> PublicKey {
        PublicKey::from_ed25519(crate::escrow_authority_pda().as_array())
    }

    /// Constant nullifier key: the escrow-authority PDA is the sole
    /// authorized spender, enforced by the timelock escrow program's
    /// `invoke_signed`, not by nullifier-key secrecy.
    fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }
}

// escrow: the escrow output; withdraw recomputes it to match the escrow
// input it spends.
impl EscrowUtxo {
    pub fn output_utxo(&self) -> Result<SppProofOutputUtxo> {
        let data_hash = self.terms.data_hash()?;
        let nullifier_pubkey = Self::nullifier_key().pubkey().map_err(err)?;
        let owner_address = ShieldedAddress {
            signing_pubkey: Self::pda_owner(),
            nullifier_pubkey,
            viewing_pubkey: self.terms.creator.viewing_pubkey,
        };
        Ok(SppProofOutputUtxo {
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            owner_address: Some(owner_address),
            ..Default::default()
        }
        .with_utxo_data(Vec::new(), data_hash))
    }
}

// withdraw: spend the escrow utxo and pay out the source funds to the
// creator.
impl EscrowUtxo {
    /// The escrow input spend: the opening (terms + blinding) is the full
    /// spend capability; the timelock escrow program signs for the PDA via
    /// `invoke_signed`.
    pub fn to_input_utxo(&self) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: Self::pda_owner(),
            asset: self.asset,
            amount: self.amount,
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
            asset: self.asset,
            amount: self.amount,
            blinding,
            owner_address: Some(recipient),
            ..Default::default()
        }
    }
}
