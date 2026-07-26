//! Shared write gate for Rust→TypeScript drift oracles.
//!
//! Check mode compares the rendered oracle to the committed file and fails
//! without writing. Update mode (`ZOLANA_UPDATE_TS_ORACLES`) is the only path that
//! may rewrite the baseline.

use std::path::Path;

/// Assert that `path` already holds `rendered`. When the update env is set,
/// rewrite the file and succeed; otherwise leave the worktree untouched and
/// panic so a stale baseline stays visible across repeated check runs.
pub(crate) fn assert_oracle_current(path: &Path, rendered: &str) {
    let current = std::fs::read_to_string(path).unwrap_or_default();
    if current == rendered {
        return;
    }
    if std::env::var_os("ZOLANA_UPDATE_TS_ORACLES").is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create oracle dir");
        }
        std::fs::write(path, rendered).expect("write oracle");
        return;
    }
    panic!(
        "{} is stale; rerun with ZOLANA_UPDATE_TS_ORACLES=1 to update it",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::assert_oracle_current;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    // `std::env::set_var` is process-global; serialize the env-mutating cases.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn scratch_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("zolana-oracle-{label}-{nanos}.json"))
    }

    #[test]
    fn check_mode_leaves_a_stale_baseline_untouched() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // SAFETY: single-threaded under ENV_LOCK for the duration of the test.
        unsafe {
            std::env::remove_var("ZOLANA_UPDATE_TS_ORACLES");
        }
        let path = scratch_path("stale");
        fs::write(&path, "baseline\n").expect("seed baseline");

        let result = std::panic::catch_unwind(|| {
            assert_oracle_current(&path, "drifted\n");
        });
        assert!(result.is_err(), "stale baseline must fail in check mode");
        assert_eq!(
            fs::read_to_string(&path).expect("reread"),
            "baseline\n",
            "check mode must not overwrite the baseline"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn update_mode_rewrites_a_stale_baseline() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // SAFETY: single-threaded under ENV_LOCK for the duration of the test.
        unsafe {
            std::env::set_var("ZOLANA_UPDATE_TS_ORACLES", "1");
        }
        let path = scratch_path("update");
        fs::write(&path, "baseline\n").expect("seed baseline");

        assert_oracle_current(&path, "updated\n");
        assert_eq!(fs::read_to_string(&path).expect("reread"), "updated\n");

        unsafe {
            std::env::remove_var("ZOLANA_UPDATE_TS_ORACLES");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn matching_baseline_is_a_no_op() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var("ZOLANA_UPDATE_TS_ORACLES");
        }
        let path = scratch_path("match");
        fs::write(&path, "same\n").expect("seed baseline");
        assert_oracle_current(&path, "same\n");
        assert_eq!(fs::read_to_string(&path).expect("reread"), "same\n");
        let _ = fs::remove_file(&path);
    }
}
