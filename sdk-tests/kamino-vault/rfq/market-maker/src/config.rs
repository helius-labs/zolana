use std::time::Duration;

use zolana_client::Shape;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherConfig {
    Polling { interval: Duration },
    Websocket { url: String },
}

#[derive(Clone, Debug)]
pub struct MakerConfig {
    pub tree_id: u16,
    pub fee_bps: u64,
    pub base_lanes: usize,
    pub max_lanes: usize,
    pub min_lane_value: u64,
    pub idle_delay: Option<Duration>,
    pub base_provers: usize,
    pub max_provers: usize,
    pub quote_ttl: Duration,
    pub maker_leg: Shape,
    pub cache_lifetime: Duration,
    pub cache_rotation_margin: Duration,
    pub status_interval: Duration,
    pub sync_interval: Duration,
    pub watcher: WatcherConfig,
}

impl MakerConfig {
    pub fn new(tree_id: u16, fee_bps: u64) -> Self {
        Self {
            tree_id,
            fee_bps,
            base_lanes: 1,
            max_lanes: 16,
            min_lane_value: 1_000_000,
            idle_delay: None,
            base_provers: 4,
            max_provers: 16,
            quote_ttl: Duration::from_secs(60),
            maker_leg: Shape::IN2_OUT4,
            cache_lifetime: Duration::from_secs(24 * 60 * 60),
            cache_rotation_margin: Duration::from_secs(10 * 60),
            status_interval: Duration::from_millis(400),
            sync_interval: Duration::from_millis(1_000),
            watcher: WatcherConfig::Polling {
                interval: Duration::from_millis(400),
            },
        }
    }
}
