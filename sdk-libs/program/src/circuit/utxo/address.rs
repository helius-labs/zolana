use super::{assert_address_owner, derive_address, CreatedAddress};
use crate::{
    circuit::{poseidon, zero, Assert, CircuitVar, UtxoOwner},
    CircuitError,
};

#[must_use]
#[derive(Clone, Debug)]
pub struct NewAddress {
    pub(crate) created: CreatedAddress,
}

impl NewAddress {
    /// Derives an address reservation independent of a state output. `owner`
    /// is the address's own preimage, so it carries the zero nullifier key the
    /// address hashes under. [`UniqueDataUtxo::new_init`] does not require
    /// this: its owner also owns the state UTXO, which commits the owner's
    /// own nullifier key.
    ///
    /// [`UniqueDataUtxo::new_init`]: crate::circuit::UniqueDataUtxo::new_init
    #[track_caller]
    pub fn new(owner: &UtxoOwner, seed: &CircuitVar) -> Result<Self, CircuitError> {
        assert_address_owner(owner)?;
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
