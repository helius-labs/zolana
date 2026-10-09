use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use solana_address::Address;

use super::{error::MakerError, tracker::UtxoTracker};

pub struct Ledger {
    pub tracker: Arc<UtxoTracker>,
    queued: Mutex<HashMap<Address, u64>>,
}

impl Ledger {
    pub fn new(tracker: Arc<UtxoTracker>) -> Self {
        Self {
            tracker,
            queued: Mutex::new(HashMap::new()),
        }
    }

    pub fn queue(&self, asset: Address, amount: u64) -> Result<(), MakerError> {
        let mut queued = self.queued.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = queued.entry(asset).or_default();
        let available = self
            .tracker
            .unreserved_balance(&asset)
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
}
