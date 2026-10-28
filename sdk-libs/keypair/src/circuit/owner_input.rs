use borsh::{BorshDeserialize, BorshSerialize};
use spr_hasher::primitives::SOLANA_OWNER_TAG;
use spr_zk_dsl::CircuitError;

use super::OwnerCircuitErrorKind;
use crate::{Curve, PublicKey, ShieldedAddress};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
#[cfg_attr(feature = "tsify", derive(tsify::Tsify))]
pub struct UtxoOwner {
    pub tag: u8,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_helpers::bytes"))]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub key: [u8; 32],
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_helpers::bytes"))]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub nullifier_pk: [u8; 32],
}

impl TryFrom<(&PublicKey, [u8; 32])> for UtxoOwner {
    type Error = CircuitError;

    fn try_from(
        (signing_pubkey, nullifier_pk): (&PublicKey, [u8; 32]),
    ) -> Result<Self, CircuitError> {
        let tag = match signing_pubkey
            .curve()
            .map_err(OwnerCircuitErrorKind::InvalidOwner)?
        {
            Curve::Ed25519 | Curve::Pda => SOLANA_OWNER_TAG,
        };
        Ok(Self {
            tag,
            key: signing_pubkey
                .confidential_view_tag()
                .map_err(OwnerCircuitErrorKind::InvalidOwner)?,
            nullifier_pk,
        })
    }
}

impl TryFrom<&ShieldedAddress> for UtxoOwner {
    type Error = CircuitError;

    fn try_from(address: &ShieldedAddress) -> Result<Self, CircuitError> {
        Self::try_from((&address.signing_pubkey, address.nullifier_pubkey))
    }
}
