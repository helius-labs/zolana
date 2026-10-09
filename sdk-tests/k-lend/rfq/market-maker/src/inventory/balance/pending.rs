use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use solana_address::Address;
use solana_signature::Signature;

use k_lend_rfq_sdk::swap::SwapError;

use super::reservations::Reservations;
use crate::{
    config::TargetRange,
    error::MakerError,
    transactions::steps::{OperationId, StepId},
};

pub struct PendingBalance {
    pub reservations: Arc<Reservations>,
    queued: Mutex<HashMap<Address, u64>>,
    incoming: Mutex<HashMap<StepId, (Address, u64)>>,
    fills: Mutex<FillFlows>,
    next_operation: AtomicU64,
    rebalances: Mutex<Vec<Signature>>,
}

#[derive(Clone, Copy)]
pub struct Inflow {
    pub asset: Address,
    pub amount: u64,
    pub utxo_hash: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct Outflow {
    pub asset: Address,
    pub amount: u64,
}

pub struct FillRanges {
    pub inflow: Option<TargetRange>,
    pub outflow: Option<TargetRange>,
}

#[derive(Default)]
struct FillFlows {
    inflows: HashMap<OperationId, Inflow>,
    outflows: HashMap<OperationId, Outflow>,
}

impl FillFlows {
    fn net_balance(&mut self, reservations: &Reservations, asset: &Address) -> u64 {
        self.inflows
            .retain(|_, inflow| reservations.get(&inflow.utxo_hash).is_none());
        let incoming: u64 = self
            .inflows
            .values()
            .filter(|inflow| inflow.asset == *asset)
            .map(|inflow| inflow.amount)
            .sum();
        let outgoing: u64 = self
            .outflows
            .values()
            .filter(|outflow| outflow.asset == *asset)
            .map(|outflow| outflow.amount)
            .sum();
        reservations
            .balance(asset)
            .saturating_add(incoming)
            .saturating_sub(outgoing)
    }
}

pub fn range_check(
    asset: Address,
    balance: u64,
    amount: u64,
    incoming: bool,
    range: Option<TargetRange>,
) -> Result<(), SwapError> {
    let Some(range) = range else {
        return Ok(());
    };
    let (balance_after, outside) = if incoming {
        let after = balance.saturating_add(amount);
        (after, after > range.max)
    } else {
        let after = balance.saturating_sub(amount);
        (after, after < range.min)
    };
    if outside {
        return Err(SwapError::OutsideTargetRange {
            asset,
            balance_after,
            min: range.min,
            max: range.max,
        });
    }
    Ok(())
}

impl PendingBalance {
    pub fn new(reservations: Arc<Reservations>) -> Self {
        Self {
            reservations,
            queued: Mutex::new(HashMap::new()),
            incoming: Mutex::new(HashMap::new()),
            fills: Mutex::new(FillFlows::default()),
            next_operation: AtomicU64::new(0),
            rebalances: Mutex::new(Vec::new()),
        }
    }

    pub fn queue(&self, asset: Address, amount: u64) -> Result<(), MakerError> {
        let incoming = self.incoming(&asset);
        let mut queued = self.queued.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = queued.entry(asset).or_default();
        let available = self
            .reservations
            .unreserved_balance(&asset)
            .saturating_add(incoming)
            .saturating_sub(*entry);
        if available < amount {
            return Err(MakerError::InsufficientBalance {
                asset,
                available,
                requested: amount,
            });
        }
        *entry = entry.saturating_add(amount);
        Ok(())
    }

    pub fn unqueue(&self, asset: Address, amount: u64) {
        let mut queued = self.queued.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = queued.get_mut(&asset) {
            *entry = entry.saturating_sub(amount);
        }
    }

    pub fn queue_fill(
        &self,
        operation: OperationId,
        inflow: Inflow,
        outflow: Outflow,
        ranges: FillRanges,
    ) -> Result<(), MakerError> {
        let mut fills = self.fills.lock().unwrap_or_else(PoisonError::into_inner);
        let out_balance = fills.net_balance(&self.reservations, &outflow.asset);
        range_check(
            outflow.asset,
            out_balance,
            outflow.amount,
            false,
            ranges.outflow,
        )?;
        let in_balance = fills.net_balance(&self.reservations, &inflow.asset);
        range_check(inflow.asset, in_balance, inflow.amount, true, ranges.inflow)?;
        fills.inflows.insert(operation, inflow);
        fills.outflows.insert(operation, outflow);
        Ok(())
    }

    pub fn finish_fill(&self, operation: OperationId) {
        self.fills
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .outflows
            .remove(&operation);
    }

    pub fn drop_fill(&self, operation: OperationId) {
        let mut fills = self.fills.lock().unwrap_or_else(PoisonError::into_inner);
        fills.outflows.remove(&operation);
        fills.inflows.remove(&operation);
    }

    pub fn expect(&self, step: StepId, asset: Address, amount: u64) {
        self.incoming
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(step, (asset, amount));
    }

    pub fn settle(&self, step: StepId) {
        self.incoming
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&step);
    }

    pub fn net_balance(&self, asset: &Address) -> u64 {
        self.fills
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .net_balance(&self.reservations, asset)
    }

    pub fn next_operation(&self) -> OperationId {
        self.next_operation.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_rebalance(&self, signature: Signature) {
        self.rebalances
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(signature);
    }

    pub fn rebalances(&self) -> Vec<Signature> {
        self.rebalances
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn incoming(&self, asset: &Address) -> u64 {
        self.incoming
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|(incoming, _)| incoming == asset)
            .map(|(_, amount)| *amount)
            .sum()
    }
}
