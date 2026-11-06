use std::{thread::sleep, time::Duration};

use crate::{error::ClientError, indexer::is_transient_indexer_error};

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
    /// a response, returning that response. A transient indexer failure
    /// ([`ClientError::IndexerUnavailable`]) is retried and any other error is
    /// returned at once. An exhausted schedule fails with
    /// [`ClientError::PollTimedOut`], carrying the final attempt's error when
    /// that attempt failed: a failure the indexer answered after is not
    /// blamed for the timeout.
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
                Ok(_) => last_error = None,
                Err(error) if is_transient_indexer_error(&error) => {
                    last_error = Some(error.to_string())
                }
                Err(error) => return Err(error),
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
    pub poll: IndexerPollConfig,
    /// Slot the indexer must have persisted before its answer is accepted.
    /// `None` accepts whatever the indexer currently has.
    pub require_slot: Option<u64>,
}

impl IndexerRpcConfig {
    /// Require the indexer to have persisted `slot` before answering.
    pub fn at_slot(slot: u64) -> Self {
        Self {
            poll: IndexerPollConfig::default(),
            require_slot: Some(slot),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `poll_until` over `script`, one entry per attempt, accepting `true`.
    fn poll(script: Vec<Result<bool, ClientError>>) -> (Result<bool, ClientError>, usize) {
        let mut script = script.into_iter();
        let mut calls = 0;
        let result = IndexerPollConfig::new(1, 0, 0).poll_until(
            || {
                calls += 1;
                script.next().expect("scripted attempt")
            },
            |accepted| *accepted,
        );
        (result, calls)
    }

    fn unavailable() -> Result<bool, ClientError> {
        Err(ClientError::IndexerUnavailable("Internal error".into()))
    }

    #[test]
    fn a_transient_failure_is_retried() {
        let (result, calls) = poll(vec![unavailable(), Ok(true)]);
        assert!(result.unwrap());
        assert_eq!(calls, 2);
    }

    #[test]
    fn a_permanent_failure_ends_the_poll_at_once() {
        let (result, calls) = poll(vec![Err(ClientError::Indexer("bad tag".into())), Ok(true)]);
        assert!(matches!(result, Err(ClientError::Indexer(_))), "{result:?}");
        assert_eq!(calls, 1);
    }

    /// The timeout carries the final attempt's failure, never one the
    /// indexer answered after.
    #[test]
    fn an_exhausted_poll_carries_the_final_attempts_failure() {
        let (result, _) = poll(vec![Ok(false), unavailable()]);
        let Err(ClientError::PollTimedOut {
            attempts: 2,
            last_error: Some(last_error),
        }) = result
        else {
            panic!("expected PollTimedOut, got {result:?}");
        };
        assert!(last_error.contains("Internal error"), "{last_error}");

        let (result, _) = poll(vec![unavailable(), Ok(false)]);
        assert!(
            matches!(
                result,
                Err(ClientError::PollTimedOut {
                    attempts: 2,
                    last_error: None
                })
            ),
            "{result:?}"
        );
    }
}
