use std::time::Duration;

pub(crate) const DEFAULT_RPC_PORT: u16 = 8899;
pub(crate) const DEFAULT_PROVER_PORT: u16 = 3001;
pub(crate) const DEFAULT_LIMIT_LEDGER_SIZE: u64 = 10_000;
pub(crate) const DEFAULT_GOSSIP_HOST: &str = "127.0.0.1";
pub(crate) const DEFAULT_LOG_DIR: &str = "test-ledger";

pub(crate) const READINESS_TIMEOUT: Duration = Duration::from_secs(180);
pub(crate) const TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(3);
