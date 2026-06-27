use std::time::Duration;

pub(crate) const DEFAULT_RPC_PORT: u16 = 8899;
pub(crate) const DEFAULT_PROVER_PORT: u16 = 3001;
/// Prover Prometheus metrics server default. Offset in lockstep with
/// `DEFAULT_PROVER_PORT` so concurrent clones do not collide on it.
pub(crate) const DEFAULT_METRICS_PORT: u16 = 9998;
pub(crate) const DEFAULT_PHOTON_PORT: u16 = 8784;
pub(crate) const DEFAULT_LIMIT_LEDGER_SIZE: u64 = 10_000;
pub(crate) const DEFAULT_GOSSIP_HOST: &str = "127.0.0.1";
pub(crate) const DEFAULT_LOG_DIR: &str = "test-ledger";

pub(crate) const READINESS_TIMEOUT: Duration = Duration::from_secs(180);
pub(crate) const TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(3);

// A service that responds once may still stall right after startup, so readiness
// must hold for this many consecutive one-second polls before we treat it as up.
pub(crate) const READINESS_STABLE_CHECKS: u32 = 3;
pub(crate) const PROVER_READINESS_STABLE_CHECKS: u32 = 5;
