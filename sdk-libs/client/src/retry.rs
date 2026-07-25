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
        let mut delay = self.delay_ms.min(self.max_delay_ms);
        (0..self.num_retries).map(move |_| {
            let current = Duration::from_millis(delay);
            delay = delay.saturating_mul(2).min(self.max_delay_ms);
            current
        })
    }

    pub fn attempts(&self) -> u64 {
        u64::from(self.num_retries) + 1
    }

    /// Polls an idempotent request until `accept` matches a response.
    ///
    /// Retryable errors are classified by [`ClientError::retry_cause`].
    /// Other errors are returned immediately.
    pub fn poll_until<T>(
        &self,
        request: impl FnMut() -> Result<T, ClientError>,
        accept: impl FnMut(&T) -> bool,
    ) -> Result<T, ClientError> {
        self.poll_until_with_sleep(request, accept, sleep)
    }

    fn poll_until_with_sleep<T>(
        &self,
        mut request: impl FnMut() -> Result<T, ClientError>,
        mut accept: impl FnMut(&T) -> bool,
        mut sleep_for: impl FnMut(Duration),
    ) -> Result<T, ClientError> {
        let mut last_cause = None;
        for delay in std::iter::once(Duration::ZERO).chain(self.backoff()) {
            if !delay.is_zero() {
                sleep_for(delay);
            }
            match request() {
                Ok(response) if accept(&response) => return Ok(response),
                Ok(_) => {}
                Err(error) => match error.retry_cause() {
                    Some(cause) => last_cause = Some(cause),
                    None => return Err(error),
                },
            }
        }
        Err(ClientError::PollTimedOut {
            attempts: self.attempts(),
            last_cause,
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::error::RetryErrorCause;

    #[test]
    fn backoff_caps_the_first_delay_and_doubles_from_the_cap() {
        let config = IndexerPollConfig::new(3, 20, 5);
        assert_eq!(
            config.backoff().collect::<Vec<_>>(),
            vec![
                Duration::from_millis(5),
                Duration::from_millis(5),
                Duration::from_millis(5)
            ]
        );
    }

    #[test]
    fn zero_delay_does_not_call_the_sleeper() {
        let config = IndexerPollConfig::new(2, 0, 0);
        let mut requests = 0;
        let sleeps = RefCell::new(Vec::new());
        let error = config
            .poll_until_with_sleep(
                || {
                    requests += 1;
                    Ok::<_, ClientError>(false)
                },
                |accepted| *accepted,
                |delay| sleeps.borrow_mut().push(delay),
            )
            .expect_err("poll must time out");

        assert_eq!(requests, 3);
        assert!(sleeps.borrow().is_empty());
        assert!(matches!(
            error,
            ClientError::PollTimedOut {
                attempts: 3,
                last_cause: None
            }
        ));
    }

    #[test]
    fn retryable_errors_record_a_structured_safe_cause() {
        let config = IndexerPollConfig::new(1, 4, 4);
        let sleeps = RefCell::new(Vec::new());
        let error = config
            .poll_until_with_sleep(
                || Err::<(), _>(ClientError::Indexer("private response".into())),
                |_| false,
                |delay| sleeps.borrow_mut().push(delay),
            )
            .expect_err("poll must time out");

        assert_eq!(*sleeps.borrow(), vec![Duration::from_millis(4)]);
        assert!(matches!(
            error,
            ClientError::PollTimedOut {
                attempts: 2,
                last_cause: Some(RetryErrorCause::Indexer)
            }
        ));
        assert!(!error.to_string().contains("private response"));
    }

    #[test]
    fn non_retryable_errors_stop_immediately() {
        let config = IndexerPollConfig::new(5, 1, 1);
        let mut requests = 0;
        let error = config
            .poll_until_with_sleep(
                || {
                    requests += 1;
                    Err::<(), _>(ClientError::MissingOutput)
                },
                |_| false,
                |_| panic!("fatal error must not sleep"),
            )
            .expect_err("request must fail");

        assert_eq!(requests, 1);
        assert!(matches!(error, ClientError::MissingOutput));
    }

    #[test]
    fn attempt_count_is_exact_at_the_u32_boundary() {
        assert_eq!(
            IndexerPollConfig::new(u32::MAX, 0, 0).attempts(),
            u64::from(u32::MAX) + 1
        );
    }
}
