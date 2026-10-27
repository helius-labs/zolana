use crate::{Field, UtxoOwner, CircuitError, hash_bytes, poseidon, require_eq};
use zolana_interface::{DUMMY_DOMAIN, UTXO_DOMAIN};

#[xark::input]
pub struct Utxo {
    pub domain: u16,
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub amount: u64,
    pub blinding: Field,
    pub data_hash: Field,
    pub ring_data_hash: Field,
    pub ring_program_id: Field,
    pub tree_id: u16,
    pub meta: UtxoMeta,
}

#[xark::input]
pub struct UtxoMeta {
    /// Carried from the SPP input; application authorization must not depend on it.
    pub nullifier: Field,
    pub latest_tree_id: u16,
    pub has_latest_tree_id: bool,
}
impl Default for UtxoMeta {
    fn default() -> Self { Self { nullifier: Field::zero(), latest_tree_id: 0, has_latest_tree_id: false } }
}

#[derive(Clone, Copy, Debug)]
pub struct SpentInput { pub hash: Field, pub meta: UtxoMeta }

impl Default for Utxo {
    fn default() -> Self {
        Self { domain: UTXO_DOMAIN, owner: UtxoOwner::default(), asset: [0; 32], amount: 0,
            blinding: Field::zero(), data_hash: Field::zero(), ring_data_hash: Field::zero(),
            ring_program_id: Field::zero(), tree_id: 0, meta: UtxoMeta::default() }
    }
}
impl Utxo {
    pub fn dummy() -> Self { Self { domain: DUMMY_DOMAIN, ..Self::default() } }
    pub fn hash(&self) -> Result<Field, CircuitError> {
        let (owner, asset) = if self.domain == DUMMY_DOMAIN { (Field::zero(), Field::zero()) }
            else { (self.owner.hash()?, hash_bytes(&self.asset)?) };
        self.hash_with(&owner, &asset)
    }
    pub fn hash_with(&self, owner_hash: &Field, asset_hash: &Field) -> Result<Field, CircuitError> {
        let ring = poseidon(&[self.ring_data_hash, self.ring_program_id])?;
        let owner = poseidon(&[*owner_hash, self.blinding])?;
        poseidon(&[Field::from(self.domain), Field::from(self.tree_id), *asset_hash,
            Field::from(self.amount), self.data_hash, ring, owner])
    }
    pub fn spent(&self, hash: Field) -> SpentInput { SpentInput { hash, meta: self.meta } }
    pub fn assert_default_ring(&self) -> Result<(), CircuitError> {
        require_eq(self.ring_data_hash, Field::zero());
        require_eq(self.ring_program_id, Field::zero());
        Ok(())
    }
}
impl crate::PaddedInput for Utxo { fn padding() -> Self { Self::dummy() } }
