use std::{thread::sleep, time::Duration};

use crate::error::ClientError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexerPollConfig {
    pub num_retries: u32,
    pub delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for IndexerPollConfig {
    fn default() -> Self {
        Self {
            num_retries: 10,
            delay_ms: 400,
            max_delay_ms: 8_000,
        }
    }
}

impl IndexerPollConfig {
    pub fn new(num_retries: u32, delay_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            num_retries,
            delay_ms,
            max_delay_ms,
        }
    }

    pub fn backoff(&self) -> impl Iterator<Item = Duration> + '_ {
        let mut delay = self.delay_ms;
        (0..self.num_retries).map(move |_| {
            let current = Duration::from_millis(delay);
            delay = delay.saturating_mul(2).min(self.max_delay_ms);
            current
        })
    }

    /// Poll `request` on this config's backoff schedule until `accept` matches
    /// a response, returning that response. Transient request errors are
    /// retried, not propagated; when the schedule is exhausted the poll fails
    /// with [`ClientError::PollTimedOut`] carrying the last transient error.
    pub fn poll_until<T>(
        &self,
        mut request: impl FnMut() -> Result<T, ClientError>,
        mut accept: impl FnMut(&T) -> bool,
    ) -> Result<T, ClientError> {
        let mut last_error = None;
        for delay in std::iter::once(Duration::ZERO).chain(self.backoff()) {
            if !delay.is_zero() {
                sleep(delay);
            }
            match request() {
                Ok(response) if accept(&response) => return Ok(response),
                Ok(_) => {}
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        Err(ClientError::PollTimedOut {
            attempts: self.num_retries.saturating_add(1),
            last_error,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IndexerRpcConfig {
    pub wait_for_indexer: bool,
    pub poll: IndexerPollConfig,
}

impl IndexerRpcConfig {
    pub fn wait() -> Self {
        Self {
            wait_for_indexer: true,
            poll: IndexerPollConfig::default(),
        }
    }
}
