//! Opt-in wall-time profiling for hot SDK paths.
//!
//! Inactive by default so normal SDK users and non-profiled demo flows stay
//! silent. Demo setup/onramp arm this via [`begin_profile`]; parallel workers
//! must capture [`ProfileSnapshot`] and re-arm with [`install_profile`] because
//! thread-locals do not cross `thread::scope` spawns.

use std::{cell::RefCell, time::Instant};

thread_local! {
    static PROFILE: RefCell<Option<ProfileState>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug)]
struct ProfileState {
    op: String,
    wallet: Option<String>,
}

/// Captured profile labels safe to move across threads.
#[derive(Clone, Debug)]
pub struct ProfileSnapshot {
    pub op: String,
    pub wallet: Option<String>,
}

/// RAII guard that clears the profile context on drop.
pub struct ProfileGuard {
    previous: Option<ProfileState>,
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        PROFILE.with(|cell| {
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

/// Arm profiling for `op` on the current thread. Nested calls restore the prior
/// context when the guard drops.
pub fn begin_profile(op: impl Into<String>) -> ProfileGuard {
    let previous = PROFILE.with(|cell| cell.borrow().clone());
    PROFILE.with(|cell| {
        *cell.borrow_mut() = Some(ProfileState {
            op: op.into(),
            wallet: previous.as_ref().and_then(|p| p.wallet.clone()),
        });
    });
    ProfileGuard { previous }
}

/// Install a snapshot captured from another thread (parallel sync workers).
pub fn install_profile(snapshot: ProfileSnapshot) -> ProfileGuard {
    let previous = PROFILE.with(|cell| cell.borrow().clone());
    PROFILE.with(|cell| {
        *cell.borrow_mut() = Some(ProfileState {
            op: snapshot.op,
            wallet: snapshot.wallet,
        });
    });
    ProfileGuard { previous }
}

/// Snapshot of the active profile context, if any.
pub fn snapshot_profile() -> Option<ProfileSnapshot> {
    PROFILE.with(|cell| {
        cell.borrow().as_ref().map(|state| ProfileSnapshot {
            op: state.op.clone(),
            wallet: state.wallet.clone(),
        })
    })
}

/// True when profiling is armed on this thread.
pub fn profile_active() -> bool {
    PROFILE.with(|cell| cell.borrow().is_some())
}

/// Temporarily set the wallet label for nested spans.
pub fn with_wallet_label<T>(wallet: impl Into<String>, f: impl FnOnce() -> T) -> T {
    let wallet = wallet.into();
    let previous = PROFILE.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if let Some(state) = borrow.as_mut() {
            let prev = state.wallet.clone();
            state.wallet = Some(wallet);
            prev
        } else {
            None
        }
    });
    let value = f();
    PROFILE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.wallet = previous;
        }
    });
    value
}

/// Time `f` and emit a profile line when active.
pub fn profile_span<T>(step: &str, f: impl FnOnce() -> T) -> T {
    if !profile_active() {
        return f();
    }
    let started = Instant::now();
    let value = f();
    profile_log(step, started.elapsed().as_millis(), &[]);
    value
}

/// Time a fallible `f` and emit a profile line when active.
pub fn profile_try<T, E: std::fmt::Display>(
    step: &str,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    if !profile_active() {
        return f();
    }
    let started = Instant::now();
    let result = f();
    let ms = started.elapsed().as_millis();
    match &result {
        Ok(_) => profile_log(step, ms, &[]),
        Err(error) => profile_log(step, ms, &[("error", &error.to_string())]),
    }
    result
}

/// Emit a structured profile line. No-op when profiling is inactive.
pub fn profile_log(step: &str, elapsed_ms: u128, extras: &[(&str, &str)]) {
    PROFILE.with(|cell| {
        let borrow = cell.borrow();
        let Some(state) = borrow.as_ref() else {
            return;
        };
        let mut line = format!("bench {} {}={}ms", state.op, step, elapsed_ms);
        if let Some(wallet) = &state.wallet {
            line.push_str(&format!(" wallet={wallet}"));
        }
        for (key, value) in extras {
            // Keep values single-token for easy grepping.
            let safe = value.replace([' ', '\n', '\t'], "_");
            line.push_str(&format!(" {key}={safe}"));
        }
        println!("{line}");
    });
}

/// Emit a count-style profile line (not milliseconds).
pub fn profile_count(step: &str, count: u128, extras: &[(&str, &str)]) {
    PROFILE.with(|cell| {
        let borrow = cell.borrow();
        let Some(state) = borrow.as_ref() else {
            return;
        };
        let mut line = format!("bench {} {}={count}", state.op, step);
        if let Some(wallet) = &state.wallet {
            line.push_str(&format!(" wallet={wallet}"));
        }
        for (key, value) in extras {
            let safe = value.replace([' ', '\n', '\t'], "_");
            line.push_str(&format!(" {key}={safe}"));
        }
        println!("{line}");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_by_default() {
        assert!(!profile_active());
        assert!(snapshot_profile().is_none());
        let value = profile_span("noop", || 7);
        assert_eq!(value, 7);
    }

    #[test]
    fn begin_profile_arms_and_restores() {
        assert!(!profile_active());
        {
            let _guard = begin_profile("setup");
            assert!(profile_active());
            let snap = snapshot_profile().expect("armed");
            assert_eq!(snap.op, "setup");
            with_wallet_label("c-default", || {
                let snap = snapshot_profile().expect("wallet");
                assert_eq!(snap.wallet.as_deref(), Some("c-default"));
            });
            let snap = snapshot_profile().expect("restored wallet");
            assert!(snap.wallet.is_none());
        }
        assert!(!profile_active());
    }

    #[test]
    fn install_profile_crosses_threads() {
        let snap = {
            let _guard = begin_profile("onramp");
            with_wallet_label("house", || snapshot_profile().expect("snap"))
        };
        assert!(!profile_active());
        let _guard = install_profile(snap);
        assert!(profile_active());
        let restored = snapshot_profile().expect("installed");
        assert_eq!(restored.op, "onramp");
        assert_eq!(restored.wallet.as_deref(), Some("house"));
    }
}
