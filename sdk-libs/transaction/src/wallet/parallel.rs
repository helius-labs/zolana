//! The rayon fan-out strategy for [`Wallet::sync_parallel`].
//!
//! There is no second scan here. The scan lives once in [`super::sync`], generic
//! over [`ProbeFanout`]; this module supplies the strategy that spreads the
//! per-counterparty tag probes across a thread pool, plus the entry points that
//! select it. A wallet with many known counterparties spends most of a scan
//! deriving and looking up their tag streams, which is pure work and the only
//! part worth parallelizing -- decoding mutates the scan context and stays
//! serial under both strategies.

use rayon::prelude::*;

use super::{
    state::{SyncReport, Wallet},
    sync::ProbeFanout,
};
use crate::{
    error::TransactionError, instructions::transact::ShieldedTransaction, SyncWalletAuthority,
    WalletSyncMaterial,
};

pub(super) struct RayonProbe;

impl ProbeFanout for RayonProbe {
    fn probe_each<T, R>(
        items: &[T],
        probe: impl Fn(&T) -> Result<R, TransactionError> + Send + Sync,
    ) -> Result<Vec<R>, TransactionError>
    where
        T: Send + Sync,
        R: Send,
    {
        items.par_iter().map(probe).collect()
    }
}

impl Wallet {
    /// [`Wallet::sync`] with the per-counterparty tag probes spread across
    /// rayon's pool. Same scan, same results.
    pub fn sync_parallel<A: SyncWalletAuthority + ?Sized>(
        &mut self,
        authority: &A,
        transactions: &[ShieldedTransaction],
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        let material = authority.sync_material()?;
        self.sync_parallel_with_material(&material, transactions, synced_at, window)
    }

    pub fn sync_parallel_with_material(
        &mut self,
        material: &WalletSyncMaterial,
        transactions: &[ShieldedTransaction],
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.scan::<RayonProbe>(material, transactions, synced_at, window)
    }
}
