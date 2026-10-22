//! Delivered ring output bodies of schemes 9 and 10, `asset_address ‖ u64be(amount)` under the
//! audit stream of a CRDS slot secret, mirrored by Go `custom_rings/circuits/base`.

use custom_ring_interface::{
    stream::{RingSecret, RingTag, SlotSecret},
    AUDIT_STREAM_INFO, RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use zolana_instruction::RingOutputBlinding;
use zolana_keypair::{symmetric_apply_audit, PublicKey, X25519Keypair, X25519Pubkey};

use crate::{asset::Mint, data::Data, error::TransactionError, utxo::Utxo};

/// The opening a delivered body carries, its recipient rebuilds the rest of the note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveredBody {
    /// All zero for SOL.
    pub asset_address: Address,
    pub amount: u64,
}

impl RingDeliveredBody {
    /// One slot secret keys one body, the secret binds the slot and the first nullifier.
    pub fn seal(
        &self,
        slot_secret: &SlotSecret,
    ) -> Result<[u8; RING_DELIVERED_BODY_LEN], TransactionError> {
        let mut body = [0u8; RING_DELIVERED_BODY_LEN];
        let (asset, amount) = body.split_at_mut(32);
        asset.copy_from_slice(self.asset_address.as_array());
        amount.copy_from_slice(&self.amount.to_be_bytes());
        symmetric_apply_audit(slot_secret.as_bytes(), AUDIT_STREAM_INFO, &mut body)?;
        Ok(body)
    }

    /// The cipher is unauthenticated, only the rebuilt commitment tells a body of another key.
    pub fn open(
        body: &[u8; RING_DELIVERED_BODY_LEN],
        slot_secret: &SlotSecret,
    ) -> Result<Self, TransactionError> {
        let mut plaintext = *body;
        symmetric_apply_audit(slot_secret.as_bytes(), AUDIT_STREAM_INFO, &mut plaintext)?;
        let (asset, amount) = plaintext.split_at(32);
        Ok(Self {
            asset_address: Address::new_from_array(core::array::from_fn(|i| asset[i])),
            amount: u64::from_be_bytes(core::array::from_fn(|i| amount[i])),
        })
    }
}

/// Where a delivered ring output sits, the values its blinding binds beside its slot secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliverySlot {
    pub ring: Address,
    pub first_nullifier: [u8; 32],
    pub output_index: u32,
    /// The published tag on an anonymous ring, `None` on a confidential one.
    pub tag: Option<RingTag>,
}

/// A delivered output opened to the note its published commitment binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeliveredUtxo {
    /// The mint id is unresolved, an asset registry resolves `utxo.asset.asset`.
    pub utxo: Utxo,
    pub utxo_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingUtxoOwner<'a> {
    pub signing_pubkey: &'a PublicKey,
    pub nullifier_pubkey: &'a [u8; 32],
}

impl RingDeliverySlot {
    /// CRRA over the tag on an anonymous ring, so an anchor reads the tag back from the blinding.
    pub fn ring_secret(&self, slot_secret: &SlotSecret) -> Result<RingSecret, TransactionError> {
        Ok(match &self.tag {
            Some(tag) => RingSecret::anonymous(slot_secret, tag)?,
            None => RingSecret::confidential(slot_secret)?,
        })
    }

    /// `Poseidon(TXRB, n0, ring_secret, i)`, the blinding SPP's ring rails check.
    pub fn blinding(&self, slot_secret: &SlotSecret) -> Result<[u8; 32], TransactionError> {
        Ok(RingOutputBlinding {
            first_nullifier: self.first_nullifier,
            ring_secret: *self.ring_secret(slot_secret)?.as_bytes(),
            output_index: self.output_index,
        }
        .derive()?)
    }

    /// `None` when the body under `slot_secret` rebuilds another commitment, a tag collision or
    /// another recipient's output.
    pub fn open(
        &self,
        opening: RingDeliveryOpening<'_>,
    ) -> Result<Option<RingDeliveredUtxo>, TransactionError> {
        let body = RingDeliveredBody::open(opening.body, opening.slot_secret)?;
        let utxo = Utxo {
            owner: *opening.owner.signing_pubkey,
            asset: Mint::new(body.asset_address, 0),
            amount: body.amount,
            blinding: self.blinding(opening.slot_secret)?,
            ring_program_id: Some(self.ring),
            data: Data::default(),
        };
        let utxo_hash = utxo.hash(
            opening.owner.nullifier_pubkey,
            &[0; 32],
            &[0; 32],
            opening.tree_id,
        )?;
        Ok((utxo_hash == *opening.commitment).then_some(RingDeliveredUtxo { utxo, utxo_hash }))
    }
}

/// One published delivered body and the secret its recipient agreed for it.
#[derive(Clone, Copy)]
pub struct RingDeliveryOpening<'a> {
    pub body: &'a [u8; RING_DELIVERED_BODY_LEN],
    pub slot_secret: &'a SlotSecret,
    pub owner: RingUtxoOwner<'a>,
    /// The published commitment and the tree it was appended to.
    pub commitment: &'a [u8; 32],
    pub tree_id: u16,
}

/// False for a low-order transaction key, every clamped secret refuses the same keys.
pub fn is_contributory(tx_viewing_pk: &X25519Pubkey) -> bool {
    X25519Keypair::from_bytes(&[0; 32])
        .ecdh(tx_viewing_pk)
        .is_ok()
}
