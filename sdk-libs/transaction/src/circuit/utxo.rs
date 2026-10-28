use spr_interface::DUMMY_DOMAIN;

use spr_keypair::circuit::UtxoOwner;
use spr_zk_dsl::{
    circuit::{constant, zero, Assert, Bool, CircuitType, CircuitVar, Uint},
    CircuitError,
};
use spr_zk_gadgets::{poseidon, HashBytes};

use super::SolanaAddress;

#[derive(Clone, Debug)]
pub struct Utxo {
    pub domain: CircuitVar,
    pub owner: UtxoOwner,
    pub asset: SolanaAddress,
    #[doc(hidden)]
    pub amount: Uint<64>,
    pub blinding: CircuitVar,
    pub data_hash: CircuitVar,
    pub ring_data_hash: CircuitVar,
    pub ring_program_id: CircuitVar,
    pub tree_id: CircuitVar,
    #[doc(hidden)]
    pub meta: UtxoMeta,
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct UtxoMeta {
    /// Client-supplied nullifier metadata, not derived or verified by this circuit.
    /// The first input is bound through transaction blinding; later nullifiers
    /// are bound by the SPP proof through the shared private transaction hash.
    /// Public only for the spr-program protocol circuits; application
    /// authorization must not depend on carried values.
    #[doc(hidden)]
    pub nullifier: CircuitVar,
    #[doc(hidden)]
    pub latest_tree_id: CircuitVar,
    #[doc(hidden)]
    pub has_latest_tree_id: Bool,
}

impl Default for UtxoMeta {
    fn default() -> Self {
        Self {
            nullifier: zero(),
            latest_tree_id: zero(),
            has_latest_tree_id: Bool::constant(false),
        }
    }
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct SpentInput {
    #[doc(hidden)]
    pub hash: CircuitVar,
    #[doc(hidden)]
    pub meta: UtxoMeta,
}

impl Default for Utxo {
    fn default() -> Self {
        Self {
            domain: zero(),
            owner: UtxoOwner::default(),
            asset: SolanaAddress::constant(&crate::SOL_MINT),
            amount: Uint::zero(),
            blinding: zero(),
            data_hash: zero(),
            ring_data_hash: zero(),
            ring_program_id: zero(),
            tree_id: zero(),
            meta: UtxoMeta::default(),
        }
    }
}

impl Utxo {
    pub fn dummy() -> Self {
        Self {
            domain: constant(u64::from(DUMMY_DOMAIN)),
            owner: UtxoOwner::dummy(),
            ..Self::default()
        }
    }

    /// The native commitment, with zero owner/asset hash fields for a dummy.
    #[track_caller]
    pub fn hash(&self) -> Result<CircuitVar, CircuitError> {
        let dummy = self.domain.is_equal(&constant(u64::from(DUMMY_DOMAIN)))?;
        let owner = dummy.select(&zero(), &self.owner.hash()?);
        let asset = dummy.select(&zero(), &self.asset.hash_bytes()?);
        self.hash_with(&owner, &asset)
    }

    #[doc(hidden)]
    pub fn spent(&self, hash: CircuitVar) -> SpentInput {
        SpentInput {
            hash,
            meta: self.meta.clone(),
        }
    }

    #[track_caller]
    #[doc(hidden)]
    pub fn hash_with(
        &self,
        owner_hash: &CircuitVar,
        asset_hash: &CircuitVar,
    ) -> Result<CircuitVar, CircuitError> {
        let ring = poseidon(&[self.ring_data_hash.clone(), self.ring_program_id.clone()])?;
        let owner = poseidon(&[owner_hash.clone(), self.blinding.clone()])?;
        poseidon(&[
            self.domain.clone(),
            self.tree_id.clone(),
            asset_hash.clone(),
            self.amount.var(),
            self.data_hash.clone(),
            ring,
            owner,
        ])
    }

    #[track_caller]
    #[doc(hidden)]
    pub fn assert_default_ring(&self) -> Result<(), CircuitError> {
        self.ring_data_hash
            .assert_equal(&zero(), "the utxo is in a ring")?;
        self.ring_program_id
            .assert_equal(&zero(), "the utxo is in a ring")
    }
}

impl CircuitType for Utxo {}
