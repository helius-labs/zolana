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
    pub(crate) fn accept(&self, check: ReplayCheck) -> Result<(), Unauthorized> {
        if check.now.abs_diff(check.timestamp) > READ_SKEW.as_secs() {
            return Err(Unauthorized::StaleTimestamp);
        }
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
