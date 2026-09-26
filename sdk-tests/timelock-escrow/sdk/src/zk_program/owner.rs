use anyhow::{bail, Result};
use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
use zolana_program::compression::PdaOwner;
use zolana_transaction::{
    utxo::{Blinding, SppProofInputUtxo, Utxo},
    Data, Mint,
};

use crate::err;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramOwner {
    pda: Address,
}

impl ProgramOwner {
    pub fn new(pda: Address) -> Self {
        Self { pda }
    }

    pub fn find(seeds: &[&[u8]], program_id: &Address) -> Self {
        Self::new(Address::find_program_address(seeds, program_id).0)
    }

    pub fn pda(&self) -> &Address {
        &self.pda
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_pda(&self.pda)
    }

    pub fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    pub fn nullifier_pubkey() -> Result<[u8; 32]> {
        Self::nullifier_key().pubkey().map_err(err)
    }

    pub fn owner_tag(&self) -> [u8; 32] {
        self.pda.to_bytes()
    }

    pub fn owner_hash(&self) -> Result<[u8; 32]> {
        Ok(*PdaOwner::new(&self.pda).map_err(err)?.owner_hash())
    }

    pub fn address(&self, viewer: P256Pubkey) -> Result<ShieldedAddress> {
        Ok(ShieldedAddress::for_pda(
            &self.pda,
            Self::nullifier_pubkey()?,
            viewer,
        ))
    }

    pub fn plain_input(
        &self,
        asset: Mint,
        amount: u64,
        blinding: Blinding,
        tree_id: u16,
        leaf_index: u64,
    ) -> Result<SppProofInputUtxo> {
        self.input(
            Utxo {
                owner: self.public_key(),
                asset,
                amount,
                blinding,
                ring_program_id: None,
                data: Data::default(),
            },
            None,
            tree_id,
            leaf_index,
        )
    }

    pub(super) fn input(
        &self,
        utxo: Utxo,
        data_hash: Option<[u8; 32]>,
        tree_id: u16,
        leaf_index: u64,
    ) -> Result<SppProofInputUtxo> {
        if utxo.owner != self.public_key() {
            bail!("input is not owned by the program owner {}", self.pda);
        }
        let key = Self::nullifier_key();
        let nullifier_pubkey = key.pubkey().map_err(err)?;
        let utxo_hash = utxo
            .hash(
                &nullifier_pubkey,
                &data_hash.unwrap_or_default(),
                &[0u8; 32],
                tree_id,
            )
            .map_err(err)?;
        let nullifier = utxo.nullifier(&utxo_hash, &key).map_err(err)?;
        Ok(SppProofInputUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            data_hash,
            ring_data_hash: None,
            tree_id,
            leaf_index,
            cache_slot: None,
        })
    }
}
