use std::time::{Duration, Instant};

/// The tick after `scheduled` that is still ahead of `now`, and how many ticks were skipped to reach it.
pub fn next_tick(scheduled: Instant, now: Instant, interval: Duration) -> (Instant, u32) {
    let next = scheduled + interval;
    if next > now {
        return (next, 0);
    }
    let late = now.duration_since(next);
    let skipped = (late.as_nanos() / interval.as_nanos().max(1)) as u32 + 1;
    (next + interval * skipped, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn a_quick_attempt_keeps_the_cadence() {
        let start = Instant::now();
        let (next, skipped) = next_tick(start, start + Duration::from_secs(5), MINUTE);
        assert_eq!(next, start + MINUTE);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn a_slow_attempt_skips_the_tick_it_overran() {
        let start = Instant::now();
        let (next, skipped) = next_tick(start, start + Duration::from_secs(70), MINUTE);
        assert_eq!(next, start + 2 * MINUTE);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn an_attempt_ending_on_a_tick_skips_it() {
        let start = Instant::now();
        let (next, skipped) = next_tick(start, start + MINUTE, MINUTE);
        assert_eq!(next, start + 2 * MINUTE);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn a_long_stall_skips_every_missed_tick_and_stays_aligned() {
        let start = Instant::now();
        let now = start + Duration::from_secs(250);
        let (next, skipped) = next_tick(start, now, MINUTE);
        assert_eq!(next, start + 5 * MINUTE);
        assert_eq!(skipped, 4);
        assert!(next > now);
    }
}
