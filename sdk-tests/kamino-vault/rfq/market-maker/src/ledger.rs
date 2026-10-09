use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use solana_address::Address;
use solana_signature::Signature;

use super::{error::MakerError, step::StepId, tracker::UtxoTracker};

pub struct Ledger {
    pub tracker: Arc<UtxoTracker>,
    queued: Mutex<HashMap<Address, u64>>,
    incoming: Mutex<HashMap<StepId, (Address, u64)>>,
    outflows: Mutex<HashMap<StepId, (Address, u64)>>,
    inflows: Mutex<HashMap<StepId, Inflow>>,
    next_operation: AtomicU64,
    rebalances: Mutex<Vec<Signature>>,
}

#[derive(Clone, Copy)]
pub struct Inflow {
    pub asset: Address,
    pub amount: u64,
    pub utxo_hash: [u8; 32],
}

impl Ledger {
    pub fn new(tracker: Arc<UtxoTracker>) -> Self {
        Self {
            tracker,
            queued: Mutex::new(HashMap::new()),
            incoming: Mutex::new(HashMap::new()),
            outflows: Mutex::new(HashMap::new()),
            inflows: Mutex::new(HashMap::new()),
            next_operation: AtomicU64::new(0),
            rebalances: Mutex::new(Vec::new()),
        }
    }

    pub fn queue(&self, asset: Address, amount: u64) -> Result<(), MakerError> {
        let incoming = self.incoming(&asset);
        let mut queued = self.queued.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = queued.entry(asset).or_default();
        let available = self
            .tracker
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
        self.outflows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&step);
    }

    pub fn discard(&self, step: StepId) {
        self.settle(step);
        self.inflows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&step);
    }

    pub fn expect_fill(&self, step: StepId, outflow: (Address, u64), inflow: Inflow) {
        self.outflows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(step, outflow);
        self.inflows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(step, inflow);
    }

    pub fn net_balance(&self, asset: &Address) -> u64 {
        let mut inflows = self.inflows.lock().unwrap_or_else(PoisonError::into_inner);
        inflows.retain(|_, inflow| self.tracker.get(&inflow.utxo_hash).is_none());
        let incoming: u64 = inflows
            .values()
            .filter(|inflow| inflow.asset == *asset)
            .map(|inflow| inflow.amount)
            .sum();
        let outgoing: u64 = self
            .outflows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|(outflow, _)| outflow == asset)
            .map(|(_, amount)| *amount)
            .sum();
        self.tracker
            .balance(asset)
            .saturating_add(incoming)
            .saturating_sub(outgoing)
    }

    pub fn next_operation(&self) -> u64 {
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
