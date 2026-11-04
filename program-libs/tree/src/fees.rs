use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};

use crate::{error::TreeError, TreeAccount};

/// The highest `fee_per_tree` a tree accepts: 0.001 SOL. Every transaction
/// pays the rate in effect at execution, which the payer does not sign, so the
/// cap bounds what a fee authority can charge a payer above the rate it
/// reviewed.
pub const MAX_FEE_PER_TREE: u64 = 1_000_000;

#[repr(C)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Pod, Zeroable, BorshSerialize, BorshDeserialize,
)]
pub struct TreeFeeSchedule {
    /// Flat fee the payer of a transact or merge pays once to every tree the
    /// instruction writes, credited to the fee balance.
    pub fee_per_tree: u64,
    pub append_reimbursement: u64,
    pub close_reimbursement: u64,
}

impl TreeFeeSchedule {
    /// The one check every stored schedule passes, at creation and on update.
    pub fn validate(&self) -> Result<(), TreeError> {
        if self.fee_per_tree > MAX_FEE_PER_TREE {
            return Err(TreeError::FeeTooHigh);
        }
        Ok(())
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

    /// Credit one `fee_per_tree` to the fee balance and return it: the amount
    /// the caller collects from the payer.
    pub fn credit_tree_fee(&mut self) -> Result<u64, TreeError> {
        let layout = self.layout_mut();
        let fee = layout.fees.fee_per_tree;
        layout.fee_balance = layout
            .fee_balance
            .checked_add(fee)
            .ok_or(TreeError::FeeOverflow)?;
        Ok(fee)
    }

    /// The fee balance the open nullifier PDAs may still draw: one close each,
    /// and one append per zkp batch they span. Every queued nullifier not yet
    /// appended still has its PDA open, so the open PDAs bound the appends.
    pub fn fee_balance_reserve(&self) -> u64 {
        let layout = self.layout();
        let live = layout.live_nullifier_pdas;
        let appends = match layout.nullifier.zkp_batch_size {
            0 => live,
            zkp_batch_size => live.div_ceil(zkp_batch_size),
        };
        live.saturating_mul(layout.fees.close_reimbursement)
            .saturating_add(appends.saturating_mul(layout.fees.append_reimbursement))
    }

    /// Lower the fee balance to [`Self::fee_balance_reserve`] and return what
    /// it released. A balance at or below the reserve releases nothing.
    pub fn release_fee_surplus(&mut self) -> u64 {
        let reserve = self.fee_balance_reserve();
        let layout = self.layout_mut();
        let surplus = layout.fee_balance.saturating_sub(reserve);
        layout.fee_balance -= surplus;
        surplus
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
