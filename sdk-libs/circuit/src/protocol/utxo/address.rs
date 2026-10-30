use super::unique::{CreatedAddress, derive_address};
use crate::{CircuitError, Field, UtxoOwner, poseidon, require_eq};

#[must_use]
#[derive(Clone, Debug)]
pub struct NewAddress { pub created: CreatedAddress }
impl NewAddress {
    pub fn new(owner: &UtxoOwner, seed: &Field) -> Result<Self, CircuitError> {
        require_eq(owner.key().tag(), crate::owner::SOLANA_OWNER_TAG);
        require_eq(owner.nullifier_pk(), poseidon(&[Field::zero()])?);
        Ok(Self { created: CreatedAddress { owner: *owner, seed: *seed, address: derive_address(owner, seed)? } })
    }
    pub fn address(&self) -> Field { self.created.address }
}
