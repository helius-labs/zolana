use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use super::transact::{TransactIxData, TransactIxDataRef, TransactProof};
use crate::verifying_keys::{AggregateCircuitId, Bsb22Commitment};

/// `aggregate_transact` instruction data.
///
/// Legs are ordinary `transact` payloads and keep the discriminator they would
/// carry alone, so a proof is valid both alone and inside a batch.
///
/// A leg's `proof` must be zero. It is not part of the statement, so a non-zero
/// value would be unconstrained instruction data.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct AggregateTransactIxData {
    pub circuit: AggregateCircuitId,
    /// Over the Poseidon chain of the leg public inputs.
    pub proof: TransactProof,
    /// Always present. Emulated arithmetic in the recursive verifier
    /// range-checks its limbs, which produces the commitment.
    pub bsb22_commitment: Bsb22Commitment,
    #[wincode(with = "containers::Vec<TransactIxData, FixIntLen<u8>>")]
    pub legs: Vec<TransactIxData>,
    /// Accounts each leg consumes, in leg order.
    ///
    /// The transact parser finds owner signers by scanning for the first
    /// non-signer, which is ambiguous once leg runs are concatenated. An
    /// explicit count gives each leg only its own accounts. A wrong count
    /// splits the list differently, which fails account validation or changes
    /// the leg hash, so it cannot be used to borrow another leg's accounts.
    #[wincode(with = "containers::Vec<u8, FixIntLen<u8>>")]
    pub leg_account_counts: Vec<u8>,
}

impl AggregateTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Mirrors the `transact` config so a leg reads byte for byte the way a solo
/// payload does.
type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Zero-copy view of [`AggregateTransactIxData`].
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct AggregateTransactIxDataRef<'a> {
    pub circuit: AggregateCircuitId,
    pub proof: TransactProof,
    pub bsb22_commitment: Bsb22Commitment,
    #[wincode(with = "containers::Vec<TransactIxDataRef<'a>, FixIntLen<u8>>")]
    pub legs: Vec<TransactIxDataRef<'a>>,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u8>>")]
    pub leg_account_counts: Vec<u8>,
}

impl<'a> AggregateTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        wincode::config::deserialize_exact(data, RefConfig::new())
    }
}

/// The only value a leg may carry.
pub const EMPTY_LEG_PROOF: TransactProof = TransactProof {
    a: [0u8; 32],
    b: [0u8; 64],
    c: [0u8; 32],
};

/// The only commitment a leg may carry.
pub const EMPTY_LEG_COMMITMENT: Bsb22Commitment = Bsb22Commitment {
    commitment: [0u8; 32],
    commitment_pok: [0u8; 32],
};
