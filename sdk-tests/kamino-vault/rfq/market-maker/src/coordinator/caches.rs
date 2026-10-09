use solana_address::Address;

use super::{lifecycle::Retry, Coordinator};
use crate::{
    cache_pool::ChainClock,
    error::MakerError,
    step::{Step, StepId, StepKind, StepState},
    watcher::CacheUpdate,
};

impl Coordinator {
    pub(super) fn publish_caches(&self) {
        let addresses = self.pool.addresses();
        self.watched.send_if_modified(|watched| {
            let changed = *watched != addresses;
            if changed {
                *watched = addresses;
            }
            changed
        });
    }

    pub(super) async fn on_cache_update(&mut self, update: CacheUpdate) {
        if update.exists {
            self.pool.mark_exists(&update.cache);
        }
        let Some(cache) = self.pool.get(&update.cache) else {
            return;
        };
        if !cache.exists || update.context_slot < cache.confirmed_through {
            return;
        }
        let stale: Vec<[u8; 32]> = self
            .ledger
            .tracker
            .expected_contents(&update.cache)
            .into_iter()
            .filter(|(index, expected)| {
                update.utxo_hashes.get(usize::from(*index)) != Some(expected)
            })
            .map(|(_, expected)| expected)
            .collect();
        for hash in stale {
            tracing::warn!(cache = %update.cache, "cache slot does not hold its tracked utxo");
            self.ledger.tracker.set_cache_slot(&hash, None);
            let reader = self
                .ledger
                .tracker
                .reserved_by(&hash)
                .filter(|step| self.is_unsent(*step));
            if let Some(step) = reader {
                self.abort(step, MakerError::CacheSlotChanged, Retry::Requeue)
                    .await;
            }
        }
    }

    pub(super) async fn maintain_caches(&mut self) {
        match ChainClock::fetch(self.rpc.as_ref()).await {
            Ok(clock) => self.pool.set_clock(clock),
            Err(error) => tracing::warn!(%error, "clock refresh failed"),
        }
        for cache in self.pool.retire_expiring() {
            self.ledger.tracker.clear_cache(&cache);
        }
        for cache in self.pool.expired() {
            self.close_expired(cache).await;
        }
        self.publish_caches();
        self.send_ready();
    }

    async fn close_expired(&mut self, cache: Address) {
        let unsent: Vec<StepId> = self
            .steps
            .in_flight()
            .filter(|step| step.state.is_unsent() && step.uses_cache(&cache))
            .map(|step| step.id)
            .collect();
        for step in unsent {
            self.abort(step, MakerError::CacheExpired, Retry::Requeue)
                .await;
        }
        let busy = self
            .steps
            .in_flight()
            .any(|step| step.uses_cache(&cache) || step.kind == StepKind::CloseCache(cache));
        if busy {
            return;
        }
        if !self.pool.get(&cache).is_some_and(|entry| entry.exists) {
            self.pool.remove(&cache);
            return;
        }
        let id = self.steps.next_id();
        let mut step = Step::new(id, StepKind::CloseCache(cache), None);
        step.instruction = Some(self.pool.close_instruction(&cache));
        step.state = StepState::Proven;
        self.steps.insert(step);
    }

    fn is_unsent(&self, id: StepId) -> bool {
        self.steps
            .get(id)
            .is_some_and(|step| step.state.is_unsent())
    }
}
