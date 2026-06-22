use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use solana_pubkey::Pubkey;

use crate::cli_config::config_dir;
use crate::process::{signal_pid, wait_for_process_exit};

pub(crate) struct MergeServicePidGuard {
    path: PathBuf,
}

impl MergeServicePidGuard {
    pub(crate) fn acquire(owner: &Pubkey) -> Result<Self> {
        let path = pid_path(owner);
        if let Some(stale) = read_pid(&path)? {
            if pid_alive(stale) && pid_is_merge_service(stale) {
                bail!(
                    "merge service already running for {owner} (pid {stale}); run `zolana wallet merge-service stop` first"
                );
            }
            let _ = fs::remove_file(&path);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&path, format!("{}\n", std::process::id()))
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MergeServicePidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn pid_path(owner: &Pubkey) -> PathBuf {
    config_dir()
        .join("merge-service")
        .join(format!("{owner}.pid"))
}

pub(crate) fn read_pid(path: &Path) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let pid = raw.trim().parse::<u32>().with_context(|| {
        format!(
            "invalid pid in merge-service pid file {}: {raw:?}",
            path.display()
        )
    })?;
    Ok(Some(pid))
}

pub(crate) fn stop_merge_service(owner: &Pubkey) -> Result<bool> {
    let path = pid_path(owner);
    let Some(pid) = read_pid(&path)? else {
        return Ok(false);
    };
    if pid_alive(pid) && pid_is_merge_service(pid) {
        signal_pid(&pid.to_string(), "-TERM");
        let _ = wait_for_process_exit(|| !pid_alive(pid));
        if pid_alive(pid) {
            signal_pid(&pid.to_string(), "-KILL");
            let _ = wait_for_process_exit(|| !pid_alive(pid));
        }
    }
    let _ = fs::remove_file(&path);
    Ok(true)
}

pub(crate) fn merge_service_running(owner: &Pubkey) -> Result<bool> {
    let path = pid_path(owner);
    let Some(pid) = read_pid(&path)? else {
        return Ok(false);
    };
    if pid_alive(pid) && pid_is_merge_service(pid) {
        return Ok(true);
    }
    let _ = fs::remove_file(&path);
    Ok(false)
}

fn pid_alive(pid: u32) -> bool {
    let pid = pid.to_string();
    Command::new("kill")
        .args(["-0", &pid])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn pid_is_merge_service(pid: u32) -> bool {
    let pid = pid.to_string();
    let Ok(output) = Command::new("ps")
        .args(["-p", &pid, "-o", "command="])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let command = String::from_utf8_lossy(&output.stdout);
    command.contains("merge-service") && command.contains("run-loop")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static PID_DIR_LOCK: Mutex<()> = Mutex::new(());

    fn temp_pid_path() -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "zolana-merge-pid-{}-{stamp}.pid",
            std::process::id()
        ))
    }

    #[test]
    fn read_pid_returns_none_for_missing_file() {
        let path = temp_pid_path();
        assert_eq!(read_pid(&path).unwrap(), None);
    }

    #[test]
    fn guard_removes_pid_file_on_drop() {
        let _lock = PID_DIR_LOCK.lock().unwrap();
        let path = temp_pid_path();
        {
            let guard = MergeServicePidGuard { path: path.clone() };
            fs::write(&guard.path, format!("{}\n", std::process::id())).unwrap();
            assert!(guard.path.exists());
        }
        assert!(!path.exists());
    }
}
