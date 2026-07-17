use std::time::Duration;

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
