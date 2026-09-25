use borsh::{BorshDeserialize, BorshSerialize};
use zolana_hasher::primitives::{P256_OWNER_TAG, SOLANA_OWNER_TAG};
use zolana_keypair::{Curve, PublicKey, ShieldedAddress};

use crate::RelationError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Owner {
    pub tag: u8,
    pub key: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

impl TryFrom<(&PublicKey, [u8; 32])> for Owner {
    type Error = RelationError;

    fn try_from(
        (signing_pubkey, nullifier_pk): (&PublicKey, [u8; 32]),
    ) -> Result<Self, RelationError> {
        let tag = match signing_pubkey.curve().map_err(RelationError::input)? {
            Curve::Ed25519 | Curve::Pda => SOLANA_OWNER_TAG,
            Curve::P256 => P256_OWNER_TAG,
        };
        Ok(Self {
            tag,
            key: signing_pubkey
                .confidential_view_tag()
                .map_err(RelationError::input)?,
            nullifier_pk,
        })
    }
}

impl TryFrom<&ShieldedAddress> for Owner {
    type Error = RelationError;

    fn try_from(address: &ShieldedAddress) -> Result<Self, RelationError> {
        Self::try_from((&address.signing_pubkey, address.nullifier_pubkey))
    }
}
