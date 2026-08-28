use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, Instant},
};

use solana_address::Address;
use zolana_ring_client::ReaderKey;

use crate::error::RingRpcError;

pub(crate) const MAX_CONCURRENT_READS: usize = 32;
pub(crate) const MAX_CONCURRENT_AUTHENTICATIONS: usize = 32;
pub(crate) const MAX_CONCURRENT_DEPOSIT_SCANS: usize = 4;
pub(crate) const MAX_REQUEST_UNITS_PER_SECOND: usize = 256;

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicRequest {
    Standard,
    DepositScan { signatures: usize },
}

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
    pub(crate) fn accept(&self, now: Instant, request: PublicRequest) -> Result<(), RingRpcError> {
        let mut window = self.0.lock().map_err(|_| RingRpcError::StateUnavailable)?;
        if now.duration_since(window.started_at) >= Duration::from_secs(1) {
            window.started_at = now;
            window.accepted = 0;
        }
        let units = match request {
            PublicRequest::Standard => 1,
            PublicRequest::DepositScan { signatures } => signatures.saturating_add(1),
        };
        if units == 0 || units > MAX_REQUEST_UNITS_PER_SECOND.saturating_sub(window.accepted) {
            return Err(RingRpcError::Busy);
        }
        window.accepted += units;
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
    use solana_keypair::Keypair;
    use solana_signer::Signer;

    use super::*;

    fn reader(byte: u8) -> ReaderKey {
        ReaderKey::ed25519(Keypair::new_from_array([byte; 32]).pubkey()).expect("reader key")
    }

    /// One read at a time per reader and ring, released as soon as the page
    /// finishes.
    #[test]
    fn a_reader_holds_one_permit_per_ring_at_a_time() {
        let active = Mutex::new(HashSet::new());
        let ring = Address::new_from_array([1; 32]);
        let other = Address::new_from_array([2; 32]);
        let permit = ReaderPermit::acquire(&active, (ring, reader(7))).expect("first read");

        assert!(matches!(
            ReaderPermit::acquire(&active, (ring, reader(7))),
            Err(RingRpcError::Busy)
        ));
        let concurrent = [
            ReaderPermit::acquire(&active, (other, reader(7))).expect("another ring"),
            ReaderPermit::acquire(&active, (ring, reader(8))).expect("another reader"),
        ];

        drop(permit);
        drop(concurrent);
        ReaderPermit::acquire(&active, (ring, reader(7))).expect("released permit");
    }

    #[test]
    fn request_rate_recovers_after_its_window() {
        let rate = RequestRate::default();
        let now = Instant::now();
        for _ in 0..MAX_REQUEST_UNITS_PER_SECOND {
            rate.accept(now, PublicRequest::Standard)
                .expect("accepted request");
        }
        assert!(matches!(
            rate.accept(now, PublicRequest::Standard),
            Err(RingRpcError::Busy)
        ));
        rate.accept(now + Duration::from_secs(1), PublicRequest::Standard)
            .expect("new window");
    }

    #[test]
    fn deposit_scans_charge_the_sol_call_and_signature_lookups() {
        let rate = RequestRate::default();
        let now = Instant::now();
        rate.accept(
            now,
            PublicRequest::DepositScan {
                signatures: MAX_REQUEST_UNITS_PER_SECOND - 2,
            },
        )
        .expect("scan");
        rate.accept(now, PublicRequest::Standard)
            .expect("remaining unit");
        assert!(matches!(
            rate.accept(now, PublicRequest::DepositScan { signatures: 1 }),
            Err(RingRpcError::Busy)
        ));
    }
}
