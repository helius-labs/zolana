use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};

use crate::{error::TreeError, TreeAccount};

/// The highest `fee_per_nullifier` a tree accepts: 0.001 SOL. Spends pay the
/// tree's current rate, which the payer does not sign, so the cap bounds what a
/// fee authority can charge a payer above the rate it reviewed. An at-cost
/// schedule charges about 108 lamports per nullifier.
pub const MAX_FEE_PER_NULLIFIER: u64 = 1_000_000;

#[repr(C)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Pod, Zeroable, BorshSerialize, BorshDeserialize,
)]
pub struct TreeFeeSchedule {
    pub fee_per_nullifier: u64,
    pub append_reimbursement: u64,
    pub close_reimbursement: u64,
}

impl TreeFeeSchedule {
    /// The one check every stored schedule passes, at creation and on update.
    pub fn validate(&self) -> Result<(), TreeError> {
        if self.fee_per_nullifier > MAX_FEE_PER_NULLIFIER {
            return Err(TreeError::FeeTooHigh);
        }
        Ok(())
    }

    pub fn at_cost(
        zkp_batch_size: u64,
        append_reimbursement: u64,
        close_reimbursement: u64,
    ) -> Option<Self> {
        let per_batch = zkp_batch_size
            .checked_mul(close_reimbursement)?
            .checked_add(append_reimbursement)?;
        let fee_per_nullifier = per_batch
            .checked_div(zkp_batch_size)?
            .checked_add(u64::from(!per_batch.is_multiple_of(zkp_batch_size)))?;
        Some(Self {
            fee_per_nullifier,
            append_reimbursement,
            close_reimbursement,
        })
    }
}

impl TreeAccount<'_> {
    pub fn fees(&self) -> TreeFeeSchedule {
        self.layout().fees
    }

    pub fn fee_balance(&self) -> u64 {
        self.layout().fee_balance
    }

    pub fn set_fee_schedule(&mut self, fees: TreeFeeSchedule) -> Result<(), TreeError> {
        fees.validate()?;
        self.layout_mut().fees = fees;
        Ok(())
    }

    pub fn credit_insertion_fee(&mut self, inserted: u64) -> Result<u64, TreeError> {
        let layout = self.layout_mut();
        let fee = layout
            .fees
            .fee_per_nullifier
            .checked_mul(inserted)
            .ok_or(TreeError::FeeOverflow)?;
        layout.fee_balance = layout
            .fee_balance
            .checked_add(fee)
            .ok_or(TreeError::FeeOverflow)?;
        Ok(fee)
    }

    pub fn live_nullifier_pdas(&self) -> u64 {
        self.layout().live_nullifier_pdas
    }

    /// Count nullifier PDAs created for `queued` nullifiers.
    pub fn record_nullifier_pdas_created(&mut self, queued: u64) {
        let layout = self.layout_mut();
        layout.live_nullifier_pdas = layout.live_nullifier_pdas.saturating_add(queued);
    }

    /// Count nullifier PDAs closed back into the tree.
    pub fn record_nullifier_pdas_closed(&mut self, closed: u64) {
        let layout = self.layout_mut();
        layout.live_nullifier_pdas = layout.live_nullifier_pdas.saturating_sub(closed);
    }

    pub fn take_append_reimbursement(&mut self, num_update: u32) -> u64 {
        let rate = self.layout().fees.append_reimbursement;
        self.take_reimbursement(rate, u64::from(num_update))
    }

    pub fn take_close_reimbursement(&mut self, closed: u64) -> u64 {
        let rate = self.layout().fees.close_reimbursement;
        self.take_reimbursement(rate, closed)
    }

    fn take_reimbursement(&mut self, rate: u64, count: u64) -> u64 {
        let owed = rate.saturating_mul(count);
        let layout = self.layout_mut();
        let paid = owed.min(layout.fee_balance);
        layout.fee_balance -= paid;
        paid
    }
}
