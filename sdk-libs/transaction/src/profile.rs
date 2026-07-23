//! Opt-in wall-time profiling for wallet reconciliation.
//!
//! Mirrors the client SDK profiler so demo/setup paths can see decode-phase
//! costs without a shared crate. Inactive unless [`begin_profile`] is called.

use std::{cell::RefCell, time::Instant};

thread_local! {
    static PROFILE: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub struct ProfileGuard {
    previous: Option<String>,
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        PROFILE.with(|cell| {
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

pub fn begin_profile(op: impl Into<String>) -> ProfileGuard {
    let previous = PROFILE.with(|cell| cell.borrow().clone());
    PROFILE.with(|cell| {
        *cell.borrow_mut() = Some(op.into());
    });
    ProfileGuard { previous }
}

pub fn profile_active() -> bool {
    PROFILE.with(|cell| cell.borrow().is_some())
}

pub fn profile_span<T>(step: &str, f: impl FnOnce() -> T) -> T {
    if !profile_active() {
        return f();
    }
    let started = Instant::now();
    let value = f();
    profile_log(step, started.elapsed().as_millis(), &[]);
    value
}

pub fn profile_log(step: &str, elapsed_ms: u128, extras: &[(&str, &str)]) {
    PROFILE.with(|cell| {
        let borrow = cell.borrow();
        let Some(op) = borrow.as_ref() else {
            return;
        };
        let mut line = format!("bench {op} {step}={elapsed_ms}ms");
        for (key, value) in extras {
            let safe = value.replace([' ', '\n', '\t'], "_");
            line.push_str(&format!(" {key}={safe}"));
        }
        println!("{line}");
    });
}

pub fn profile_count(step: &str, count: u128, extras: &[(&str, &str)]) {
    PROFILE.with(|cell| {
        let borrow = cell.borrow();
        let Some(op) = borrow.as_ref() else {
            return;
        };
        let mut line = format!("bench {op} {step}={count}");
        for (key, value) in extras {
            let safe = value.replace([' ', '\n', '\t'], "_");
            line.push_str(&format!(" {key}={safe}"));
        }
        println!("{line}");
    });
}
