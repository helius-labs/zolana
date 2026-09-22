use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::{shielded::ShieldedAddress, Curve, PublicKey};

use super::{ConfidentialTransaction, Recipient};
use crate::{error::TransactionError, utxo::SppProofInputUtxo, Mint, WalletUtxo};

impl ConfidentialTransaction {
    /// Create a transaction in a custom ring. Normal transfers, change and
    /// padding outputs use this ring; [`Self::new`] uses the default ring.
    /// Each output receives its ring when added. Use [`Self::transfer_with_ring`]
    /// to send an output to a different custom ring or to the default ring.
    ///
    /// The sender's key curve determines ownership handling. P-256 senders
    /// require a custom ring that verifies their ownership proof.
    pub fn new_with_ring(
        inputs: Vec<WalletUtxo>,
        payer: Address,
        ring_program_id: Address,
    ) -> Result<Self, TransactionError> {
        let mut transaction = Self::new(inputs, payer)?;
        transaction.ring_program_id = Some(ring_program_id);
        Ok(transaction)
    }

    pub fn requires_p256_owner(&self) -> Result<bool, TransactionError> {
        for input in &self.inputs {
            if input.utxo.owner.is_zero() {
                continue;
            }
            if input.utxo.owner.curve()? == Curve::P256 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Transfer to an explicitly selected ring: `Some(address)` selects a custom
    /// ring, and `None` selects the default ring.
    ///
    /// This sets only this output's ring. Normal transfers, change and padding
    /// continue to use the transaction's ring, selected by [`Self::new`] or
    /// [`Self::new_with_ring`]. Existing outputs keep their assigned rings.
    pub fn transfer_with_ring(
        &mut self,
        recipient: &ShieldedAddress,
        asset: Mint,
        amount: u64,
        ring_program_id: Option<Address>,
    ) -> Result<&mut Self, TransactionError> {
        self.internal_add_output_utxo(Recipient {
            address: *recipient,
            asset,
            amount,
            ring_program_id,
        })
    }
}

pub(in crate::instructions::transact) fn sender_owner_tag(
    owner_pubkey: &PublicKey,
    payer: &Address,
    allow_p256_sender: bool,
) -> Result<(OwnerTag, [u8; 32]), TransactionError> {
    let resolved = owner_pubkey.confidential_view_tag()?;
    let tag = match owner_pubkey.curve()? {
        Curve::P256 if allow_p256_sender => OwnerTag::Inline(resolved),
        Curve::P256 => return Err(TransactionError::P256TransactUnsupported),
        Curve::Ed25519 | Curve::Pda => {
            if resolved == payer.to_bytes() {
                OwnerTag::Account(0)
            } else {
                OwnerTag::Inline(resolved)
            }
        }
    };
    Ok((tag, resolved))
}

pub fn inputs_require_p256(inputs: &[SppProofInputUtxo]) -> Result<bool, TransactionError> {
    for input_utxo in inputs {
        if input_utxo.is_dummy() {
            continue;
        }
        if input_utxo.utxo.owner.curve()? == Curve::P256 {
            return Ok(true);
        }
    }
    Ok(false)
}
