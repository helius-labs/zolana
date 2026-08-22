use std::{collections::HashMap, sync::Mutex};

use solana_address::Address;

use crate::authorize::{Unauthorized, READ_SKEW};

const MAX_REPLAY_ENTRIES: usize = 65_536;

#[derive(Default)]
pub(crate) struct ReplayGuard(Mutex<HashMap<Address, HashMap<[u8; 32], u64>>>);

#[must_use]
pub(crate) struct ReplayCheck {
    pub(crate) ring: Address,
    pub(crate) nonce: [u8; 32],
    pub(crate) timestamp: u64,
    pub(crate) now: u64,
}

impl ReplayGuard {
    /// The nonce set only. `authorize` owns the skew rule and hands the same
    /// clock reading here for the eviction window.
    pub(crate) fn accept(&self, check: ReplayCheck) -> Result<(), Unauthorized> {
        let mut rings = self.0.lock().map_err(|_| Unauthorized::Replay)?;
        let accepted = rings.entry(check.ring).or_default();
        accepted.retain(|_, timestamp| check.now.abs_diff(*timestamp) <= READ_SKEW.as_secs());
        if accepted.len() >= MAX_REPLAY_ENTRIES {
            return Err(Unauthorized::Replay);
        }
        if accepted.insert(check.nonce, check.timestamp).is_some() {
            return Err(Unauthorized::Replay);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RING: Address = Address::new_from_array([1; 32]);

    fn check(ring: Address, nonce: u8, timestamp: u64, now: u64) -> ReplayCheck {
        ReplayCheck {
            ring,
            nonce: [nonce; 32],
            timestamp,
            now,
        }
    }

    /// A nonce is reusable only once it falls outside the window, where the
    /// skew rule already refuses its timestamp.
    #[test]
    fn a_nonce_leaves_the_set_when_it_leaves_the_skew_window() {
        let guard = ReplayGuard::default();
        let skew = READ_SKEW.as_secs();
        guard
            .accept(check(RING, 7, 1_000, 1_000))
            .expect("first use");

        for now in [1_000, 1_000 + skew] {
            assert!(matches!(
                guard.accept(check(RING, 7, 1_000, now)),
                Err(Unauthorized::Replay)
            ));
        }
        guard
            .accept(check(RING, 7, 1_000, 1_000 + skew + 1))
            .expect("evicted nonce");
    }

    /// Nonces are counted per ring, so one reader cannot burn another ring's
    /// budget.
    #[test]
    fn the_nonce_set_is_scoped_to_one_ring() {
        let guard = ReplayGuard::default();
        let other = Address::new_from_array([2; 32]);
        guard
            .accept(check(RING, 7, 1_000, 1_000))
            .expect("first ring");
        guard
            .accept(check(other, 7, 1_000, 1_000))
            .expect("second ring");
    }

    /// The entry cap bounds live nonces, not the ring, so eviction reopens a
    /// full set instead of locking the ring out forever.
    #[test]
    fn a_full_nonce_set_reopens_once_its_entries_expire() {
        let guard = ReplayGuard::default();
        let now = 1_000;
        {
            let mut rings = guard.0.lock().expect("nonce set");
            let accepted = rings.entry(RING).or_default();
            for index in 0..MAX_REPLAY_ENTRIES {
                let mut nonce = [0u8; 32];
                nonce[..8].copy_from_slice(&(index as u64).to_le_bytes());
                accepted.insert(nonce, now);
            }
        }

        assert!(matches!(
            guard.accept(check(RING, 0xff, now, now)),
            Err(Unauthorized::Replay)
        ));
        let later = now + READ_SKEW.as_secs() + 1;
        guard
            .accept(check(RING, 0xff, later, later))
            .expect("expired entries evicted");
    }
}
