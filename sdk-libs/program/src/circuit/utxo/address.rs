use super::{derive_address, CreatedAddress};
use crate::{
    circuit::{constant, poseidon, zero, Assert, CircuitVar, UtxoOwner},
    CircuitError,
};

#[must_use]
#[derive(Clone, Debug)]
pub struct NewAddress {
    pub(crate) created: CreatedAddress,
}

impl NewAddress {
    /// Derives an address reservation independent of a state output.
    #[track_caller]
    pub fn new(owner: &UtxoOwner, seed: &CircuitVar) -> Result<Self, CircuitError> {
        owner.key().tag().assert_equal(
            &constant(u64::from(spr_hasher::primitives::SOLANA_OWNER_TAG)),
            "an address is owned by a Solana signer",
        )?;
        owner.nullifier_pk().assert_equal(
            &poseidon(&[zero()])?,
            "an address uses the zero nullifier key",
        )?;
        Ok(Self {
            created: CreatedAddress {
                owner: owner.clone(),
                seed: seed.clone(),
                address: derive_address(owner, seed)?,
            },
        })
    }

    pub fn address(&self) -> CircuitVar {
        self.created.address.clone()
    }
}
