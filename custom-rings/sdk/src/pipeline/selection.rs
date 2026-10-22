//! The fewest UTXOs of one tree whose assembled transfer fits one transaction.

use std::collections::BTreeSet;

use solana_address::Address;
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient, Shape, SPP_SUPPORTED_SHAPES};
use zolana_transaction::{select_spend_where, TransactionError, WalletUtxo};

use super::{Rail, RingTransfer};
use crate::{projection::retry_projection_lag, RingError};

pub(super) struct Funding<'u> {
    pub utxos: &'u [WalletUtxo],
    pub asset: Address,
    pub amount: u64,
    pub max_inputs: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Candidate {
    pub utxos: Vec<WalletUtxo>,
    pub change: bool,
}

/// The payments' total, refused when zero or past a u64.
pub(super) fn payment_total(amounts: impl IntoIterator<Item = u64>) -> Result<u64, RingError> {
    match amounts
        .into_iter()
        .try_fold(0u64, u64::checked_add)
        .ok_or(RingError::OutflowOverflow)?
    {
        0 => Err(TransactionError::ZeroSpendAmount.into()),
        total => Ok(total),
    }
}

/// The most inputs a keyed shape takes beside `payments` outputs.
pub(super) fn widest(payments: usize, keyed: impl Fn(Shape) -> bool) -> Option<usize> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.n_outputs() >= payments && keyed(*shape))
        .map(|shape| shape.n_inputs())
        .max()
}

impl Funding<'_> {
    /// One per tree, the fewest UTXOs first, then the least change.
    pub fn candidates(&self, keep: impl Fn(&WalletUtxo) -> bool) -> Vec<Candidate> {
        let trees: BTreeSet<u16> = self.utxos.iter().map(|utxo| utxo.tree_id).collect();
        let mut ranked: Vec<_> = trees
            .into_iter()
            .filter_map(|tree| {
                let utxos = select_spend_where(
                    self.utxos,
                    self.asset,
                    self.amount,
                    self.max_inputs,
                    |utxo| utxo.tree_id == tree && keep(utxo),
                )
                .ok()?;
                let total: u128 = utxos.iter().map(|utxo| u128::from(utxo.utxo.amount)).sum();
                let change = total > u128::from(self.amount);
                Some(((utxos.len(), total, tree), Candidate { utxos, change }))
            })
            .collect();
        ranked.sort_unstable_by_key(|(order, _)| *order);
        ranked.into_iter().map(|(_, candidate)| candidate).collect()
    }
}

impl Candidate {
    /// The cheapest keyed shape holding the inputs, `payments` and any change.
    pub fn shape(&self, payments: usize, keyed: impl Fn(Shape) -> bool) -> Option<Shape> {
        let outputs = payments + usize::from(self.change);
        SPP_SUPPORTED_SHAPES.into_iter().find(|shape| {
            shape.n_inputs() >= self.utxos.len() && shape.n_outputs() >= outputs && keyed(*shape)
        })
    }
}

/// `None` without an attempt, else the first that assembles or the first refusal.
pub(super) async fn first_fit<R: Rail, P: AsyncRpc, I: AsyncIndexer>(
    attempts: Vec<Result<RingTransfer<R>, RingError>>,
    client: &AsyncZolanaClient<P, I>,
) -> Result<Option<RingTransfer<R>>, RingError> {
    let mut first_refusal = None;
    for attempt in attempts {
        let refusal = match attempt {
            Ok(transfer) => match retry_projection_lag(|| transfer.assemble(client)).await {
                Ok(_) => return Ok(Some(transfer)),
                Err(error) => error,
            },
            Err(error) => error,
        };
        match refusal {
            RingError::TransactionTooLarge { .. }
            | RingError::TooManyAddresses { .. }
            | RingError::ShapeUnkeyed { .. }
            | RingError::DefaultRingSpendTooWide { .. } => {
                first_refusal.get_or_insert(refusal);
            }
            error => return Err(error),
        }
    }
    first_refusal.map_or(Ok(None), Err)
}
