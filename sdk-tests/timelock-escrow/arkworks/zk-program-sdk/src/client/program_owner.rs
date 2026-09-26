use solana_address::Address;
use solana_signature::Signature;
use zolana_keypair::{
    constants::BLINDING_LEN, hash::owner_hash, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress,
};
use zolana_transaction::{utxo::Utxo, SppProofOutputUtxo, WalletUtxo};

use crate::RelationError;

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

    pub fn nullifier_pubkey() -> Result<[u8; 32], RelationError> {
        Self::nullifier_key().pubkey().map_err(RelationError::input)
    }

    pub fn owner_tag(&self) -> [u8; 32] {
        self.pda.to_bytes()
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], RelationError> {
        owner_hash(&self.public_key(), &Self::nullifier_pubkey()?).map_err(RelationError::input)
    }

    pub fn address(&self, viewing_pubkey: P256Pubkey) -> Result<ShieldedAddress, RelationError> {
        Ok(ShieldedAddress::for_pda(
            &self.pda,
            Self::nullifier_pubkey()?,
            viewing_pubkey,
        ))
    }

    pub fn input(
        &self,
        output: &SppProofOutputUtxo,
        tree_id: u16,
        leaf_index: u64,
    ) -> Result<WalletUtxo, RelationError> {
        let key = Self::nullifier_key();
        let nullifier_pubkey = Self::nullifier_pubkey()?;
        let utxo = Utxo {
            owner: self.public_key(),
            asset: output.asset,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: None,
            data: output.data.clone(),
        };
        let utxo_hash = utxo
            .hash(
                &nullifier_pubkey,
                &output.data_hash.unwrap_or_default(),
                &[0u8; 32],
                tree_id,
            )
            .map_err(RelationError::input)?;
        if utxo_hash != output.hash(tree_id).map_err(RelationError::input)? {
            return Err(RelationError::Violated(
                "the output is not owned by the program",
            ));
        }
        Ok(WalletUtxo {
            nullifier: utxo
                .nullifier(&utxo_hash, &key)
                .map_err(RelationError::input)?,
            utxo,
            nullifier_pubkey,
            utxo_hash,
            data_hash: output.data_hash,
            ring_data_hash: None,
            tree_id,
            leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        })
    }
}
