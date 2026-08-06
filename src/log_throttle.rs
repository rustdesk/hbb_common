use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Collapses a log site whose call rate is set by someone else — a peer's message rate, or a
/// retry loop — into at most one line per interval.
///
/// Debug output is written to the log file, so a site that fires per received packet lets a
/// peer decide how much a machine writes to disk. Dropping the line entirely instead would
/// hide real faults, so keep one line per interval and carry the count of everything
/// suppressed since the last one.
///
/// Declare one per site (they do not share counts):
///
/// ```ignore
/// static DROPPED_ICE: LogThrottle = LogThrottle::new(Duration::from_secs(60));
///
/// if let Some(n) = DROPPED_ICE.due() {
///     log::debug!("dropped {n} ICE candidate(s) with no route");
/// }
/// ```
pub struct LogThrottle {
    interval: Duration,
    state: Mutex<ThrottleState>,
}

struct ThrottleState {
    suppressed: u64,
    last: Option<Instant>,
}

impl LogThrottle {
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(ThrottleState {
                suppressed: 0,
                last: None,
            }),
        }
    }

    /// Record one occurrence. Returns the number of occurrences to report (including this one)
    /// when a line is due, or `None` while still inside the interval.
    ///
    /// The first occurrence after a quiet period always reports, so an isolated fault is not
    /// delayed by the interval.
    pub fn due(&self) -> Option<u64> {
        let Ok(mut state) = self.state.lock() else {
            // A poisoned mutex means another thread panicked mid-update; the count is not worth
            // propagating that, and staying silent is better than logging per call.
            return None;
        };
        state.suppressed += 1;
        let due = state
            .last
            .map_or(true, |last| last.elapsed() >= self.interval);
        if !due {
            return None;
        }
        state.last = Some(Instant::now());
        Some(std::mem::replace(&mut state.suppressed, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_reports_immediately() {
        let t = LogThrottle::new(Duration::from_secs(60));
        assert_eq!(t.due(), Some(1));
    }

    #[test]
    fn calls_inside_the_interval_are_counted_not_reported() {
        let t = LogThrottle::new(Duration::from_secs(60));
        assert_eq!(t.due(), Some(1));
        for _ in 0..100 {
            assert_eq!(t.due(), None);
        }
    }

    #[test]
    fn the_next_due_line_carries_everything_suppressed() {
        let t = LogThrottle::new(Duration::ZERO);
        assert_eq!(t.due(), Some(1));
        // A zero interval is always due, so each call reports exactly itself.
        assert_eq!(t.due(), Some(1));

        let t = LogThrottle::new(Duration::from_millis(30));
        assert_eq!(t.due(), Some(1));
        assert_eq!(t.due(), None);
        assert_eq!(t.due(), None);
        std::thread::sleep(Duration::from_millis(40));
        // The two suppressed calls plus this one.
        assert_eq!(t.due(), Some(3));
    }
}
