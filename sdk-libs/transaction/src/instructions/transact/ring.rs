use solana_address::Address;
use spr_interface::instruction::instruction_data::transact::OwnerTag;
use spr_keypair::{shielded::ShieldedAddress, PublicKey};

use super::{ConfidentialTransaction, Recipient};
use crate::{error::TransactionError, Mint, WalletUtxo};

impl ConfidentialTransaction {
    /// Create a transaction in a custom ring. Normal transfers, change and
    /// padding outputs use this ring; [`Self::new`] uses the default ring.
    /// Each output receives its ring when added. Use [`Self::transfer_with_ring`]
    /// to send an output to a different custom ring or to the default ring.
    pub fn new_with_ring(
        inputs: Vec<WalletUtxo>,
        payer: Address,
        ring_program_id: Address,
    ) -> Result<Self, TransactionError> {
        let mut transaction = Self::new(inputs, payer)?;
        transaction.ring_program_id = Some(ring_program_id);
        Ok(transaction)
    }

    /// Like [`new_with_ring`](Self::new_with_ring), but pads unused slots with
    /// compact padding, as [`new_compact`](Self::new_compact) does.
    pub fn new_compact_with_ring(
        inputs: Vec<WalletUtxo>,
        payer: Address,
        ring_program_id: Address,
    ) -> Result<Self, TransactionError> {
        let mut transaction = Self::new_compact(inputs, payer)?;
        transaction.ring_program_id = Some(ring_program_id);
        Ok(transaction)
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
) -> Result<(OwnerTag, [u8; 32]), TransactionError> {
    let resolved = owner_pubkey.confidential_view_tag()?;
    let tag = if resolved == payer.to_bytes() {
        OwnerTag::Account(0)
    } else {
        OwnerTag::Inline(resolved)
    };
    Ok((tag, resolved))
}
