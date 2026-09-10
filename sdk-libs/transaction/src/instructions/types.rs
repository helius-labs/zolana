use solana_address::Address;
use zolana_keypair::{
    constants::BLINDING_LEN, viewing_key::random_blinding, NullifierKey, PublicKey,
};

use crate::{
    data::Data,
    error::TransactionError,
    utxo::{ProofInputUtxo, Utxo},
};

#[derive(Clone)]
pub struct SppProofInputUtxo {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    /// Raw id of the tree this UTXO is spent from. It is hashed into the UTXO
    /// commitment, so it must match the tree the inclusion proof comes from.
    // TODO(tree-id): resolve the tree id from the tree account.
    pub tree_id: u16,
}

impl SppProofInputUtxo {
    pub fn new(utxo: Utxo, nullifier_key: impl AsRef<NullifierKey>) -> Self {
        Self {
            utxo,
            nullifier_key: nullifier_key.as_ref().clone(),
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
        }
    }

    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self
    }

    pub fn with_ring_data_hash(mut self, ring_data_hash: [u8; 32]) -> Self {
        self.ring_data_hash = Some(ring_data_hash);
        self
    }

    /// Places the spend in the tree with the raw id `tree_id`.
    #[must_use]
    pub fn in_tree(mut self, tree_id: u16) -> Self {
        self.tree_id = tree_id;
        self
    }

    pub fn new_dummy() -> Self {
        let utxo = Utxo {
            owner: PublicKey::zeroed(),
            asset: Address::default(),
            amount: 0,
            blinding: random_blinding(),
            ring_program_id: None,
            data: Data::default(),
        };
        Self {
            utxo,
            nullifier_key: NullifierKey::from_secret([0u8; BLINDING_LEN]),
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        ProofInputUtxo::try_from(self)?.hash()
    }

    pub fn nullifier(&self) -> Result<[u8; 32], TransactionError> {
        let utxo_hash = self.hash()?;
        Ok(self
            .nullifier_key
            .nullifier(&utxo_hash, &self.utxo.blinding)?)
    }
}

impl TryFrom<&SppProofInputUtxo> for ProofInputUtxo {
    type Error = TransactionError;

    // A dummy carries only its domain tag and blinding: the circuit classifies
    // slots by domain and requires every other dummy field to be zero.
    fn try_from(spend: &SppProofInputUtxo) -> Result<Self, Self::Error> {
        if spend.is_dummy() {
            return Ok(ProofInputUtxo::new_dummy(
                &spend.utxo.blinding,
                spend.tree_id,
            ));
        }
        let owner_hash =
            zolana_keypair::hash::owner_hash(&spend.utxo.owner, &spend.nullifier_key.pubkey()?)?;
        ProofInputUtxo::new(
            owner_hash,
            &spend.utxo.asset,
            spend.utxo.amount,
            &spend.utxo.blinding,
            spend.tree_id,
        )?
        .with_data_hash(spend.data_hash.unwrap_or_default())
        .with_ring(
            spend.ring_data_hash.unwrap_or_default(),
            &spend.utxo.ring_program_id,
        )
    }
}

pub struct InputUtxoContext {
    pub index: usize,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}
