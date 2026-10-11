use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use solana_address::Address;
use solana_signature::Signature;
use zolana_transaction::WalletUtxo;

use k_lend_rfq_sdk::swap::SwapError;

use super::reservations::{Reservations, TrackedUtxo};
use crate::{
    config::TargetRange,
    error::MakerError,
    transactions::steps::{OperationId, StepId},
};

#[cfg(test)]
mod tests;

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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserInput {
    pub tree: Address,
    pub nullifier: [u8; 32],
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
    user_inputs: HashMap<UserInput, OperationId>,
}

impl FillFlows {
    fn net_balance(&mut self, reservations: &Reservations, asset: &Address) -> u64 {
        self.inflows
            .retain(|_, inflow| !reservations.has_received(&inflow.utxo_hash));
        let incoming: u64 = self
            .inflows
            .values()
            .filter(|inflow| inflow.asset == *asset)
            .fold(0u64, |amount, inflow| amount.saturating_add(inflow.amount));
        let outgoing: u64 = self
            .outflows
            .values()
            .filter(|outflow| outflow.asset == *asset)
            .fold(0u64, |amount, outflow| {
                amount.saturating_add(outflow.amount)
            });
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
        user_inputs: &[UserInput],
    ) -> Result<(), MakerError> {
        let mut fills = self.fills.lock().unwrap_or_else(PoisonError::into_inner);
        let mut unique = HashSet::new();
        for input in user_inputs {
            if fills.user_inputs.contains_key(input) || !unique.insert(*input) {
                return Err(SwapError::DuplicateFill {
                    nullifier: input.nullifier,
                }
                .into());
            }
            if self.reservations.is_spent(&input.nullifier) {
                return Err(SwapError::UserInputSpent {
                    nullifier: input.nullifier,
                }
                .into());
            }
        }
        self.reservations.snapshot(|reservations| {
            let out_balance = fills.net_balance(reservations, &outflow.asset);
            range_check(
                outflow.asset,
                out_balance,
                outflow.amount,
                false,
                ranges.outflow,
            )?;
            let in_balance = fills.net_balance(reservations, &inflow.asset);
            range_check(inflow.asset, in_balance, inflow.amount, true, ranges.inflow)
        })?;
        fills.inflows.insert(operation, inflow);
        fills.outflows.insert(operation, outflow);
        fills
            .user_inputs
            .extend(user_inputs.iter().map(|input| (*input, operation)));
        Ok(())
    }

    pub fn finish_fill(
        &self,
        operation: Option<OperationId>,
        inputs: &[[u8; 32]],
        outputs: Vec<WalletUtxo>,
    ) {
        let mut fills = self.fills.lock().unwrap_or_else(PoisonError::into_inner);
        self.reservations.remove_spent(inputs);
        for wallet in outputs {
            self.reservations.insert(TrackedUtxo {
                wallet,
                leaf_index: None,
            });
        }
        let Some(operation) = operation else {
            return;
        };
        fills.outflows.remove(&operation);
        fills.inflows.remove(&operation);
        let spent: Vec<_> = fills
            .user_inputs
            .iter()
            .filter(|(_, holder)| **holder == operation)
            .map(|(input, _)| input.nullifier)
            .collect();
        self.reservations.remove_spent_nullifiers(spent);
        fills.user_inputs.retain(|_, holder| *holder != operation);
    }

    pub fn drop_fill(&self, operation: OperationId) {
        let mut fills = self.fills.lock().unwrap_or_else(PoisonError::into_inner);
        fills.outflows.remove(&operation);
        fills.inflows.remove(&operation);
        fills.user_inputs.retain(|_, holder| *holder != operation);
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
        let mut fills = self.fills.lock().unwrap_or_else(PoisonError::into_inner);
        self.reservations
            .snapshot(|reservations| fills.net_balance(reservations, asset))
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
