use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

pub fn get_current_system_time_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis(),
        Err(e) => {
            warn!("SystemTime went backwards: {}", e);
            0
        }
    }
}
