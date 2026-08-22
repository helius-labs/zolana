use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, Instant},
};

use solana_address::Address;
use zolana_ring_client::ReaderKey;

use crate::error::RingRpcError;

pub(crate) const MAX_CONCURRENT_READS: usize = 32;
pub(crate) const MAX_READS_PER_SECOND: usize = 256;

pub(crate) struct RequestRate(Mutex<RequestWindow>);

struct RequestWindow {
    started_at: Instant,
    accepted: usize,
}

impl Default for RequestRate {
    fn default() -> Self {
        Self(Mutex::new(RequestWindow {
            started_at: Instant::now(),
            accepted: 0,
        }))
    }
}

impl RequestRate {
    pub(crate) fn accept(&self, now: Instant) -> Result<(), RingRpcError> {
        let mut window = self.0.lock().map_err(|_| RingRpcError::StateUnavailable)?;
        if now.duration_since(window.started_at) >= Duration::from_secs(1) {
            window.started_at = now;
            window.accepted = 0;
        }
        if window.accepted >= MAX_READS_PER_SECOND {
            return Err(RingRpcError::Busy);
        }
        window.accepted += 1;
        Ok(())
    }
}

pub(crate) struct ReaderPermit<'a> {
    active: &'a Mutex<HashSet<(Address, ReaderKey)>>,
    key: (Address, ReaderKey),
}

impl<'a> ReaderPermit<'a> {
    pub(crate) fn acquire(
        active: &'a Mutex<HashSet<(Address, ReaderKey)>>,
        key: (Address, ReaderKey),
    ) -> Result<Self, RingRpcError> {
        let mut readers = active.lock().map_err(|_| RingRpcError::StateUnavailable)?;
        if !readers.insert(key) {
            return Err(RingRpcError::Busy);
        }
        Ok(Self { active, key })
    }
}

impl Drop for ReaderPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut readers) = self.active.lock() {
            readers.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rate_recovers_after_its_window() {
        let rate = RequestRate::default();
        let now = Instant::now();
        for _ in 0..MAX_READS_PER_SECOND {
            rate.accept(now).expect("accepted request");
        }
        assert!(matches!(rate.accept(now), Err(RingRpcError::Busy)));
        rate.accept(now + Duration::from_secs(1))
            .expect("new window");
    }
}
