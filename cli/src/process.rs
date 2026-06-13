use std::{
    env,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};

use crate::config::TERMINATION_GRACE_PERIOD;

pub(crate) fn spawn_service(
    binary: &Path,
    args: &[String],
    log_name: &str,
    log_dir: &str,
) -> Result<Child> {
    std::fs::create_dir_all(log_dir)
        .with_context(|| format!("failed to create log directory {log_dir}"))?;
    let log_path = Path::new(log_dir).join(format!("{log_name}.log"));
    println!("Writing {log_name} logs to {}", log_path.display());
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to spawn {}", binary.display()))
}

pub(crate) fn remove_launchd_validators() {
    if !cfg!(target_os = "macos") {
        return;
    }

    for label in ["com.zolana.localnet", "com.zolana.localnet-proofless"] {
        let _ = Command::new("launchctl")
            .args(["remove", label])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub(crate) fn stop_name(name: &str) {
    let _ = signal_name(name, "-TERM");
    if wait_for_process_exit(|| !process_name_exists(name)) {
        return;
    }
    let _ = signal_name(name, "-KILL");
}

pub(crate) fn stop_port(port: u16) {
    let output = Command::new("lsof").arg(format!("-ti:{port}")).output();
    let Ok(output) = output else {
        return;
    };

    for pid in String::from_utf8_lossy(&output.stdout).lines() {
        let pid = pid.trim();
        if !pid.is_empty() {
            stop_pid(pid);
        }
    }
}

pub(crate) fn find_binary(
    env_vars: &[&str],
    repo_relative_candidates: &[&str],
    path_candidates: &[&str],
) -> Result<PathBuf> {
    for env_var in env_vars {
        if let Ok(value) = env::var(env_var) {
            let value = value.trim();
            if !value.is_empty() {
                let path = PathBuf::from(value);
                if path.is_file() {
                    return Ok(path);
                }
                bail!(
                    "{env_var} points to {}, but that file does not exist",
                    path.display()
                );
            }
        }
    }

    if let Ok(root) = project_root() {
        for candidate in repo_relative_candidates {
            let path = root.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    for candidate in path_candidates {
        if let Some(path) = find_in_path(candidate) {
            return Ok(path);
        }
    }

    let hints = env_vars
        .iter()
        .chain(path_candidates.iter())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    bail!("failed to find required binary ({hints})")
}

pub(crate) fn project_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse --show-toplevel")?;
    if !output.status.success() {
        bail!("git rev-parse --show-toplevel failed");
    }
    let root = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(PathBuf::from(root))
}

pub(crate) fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))
}

pub(crate) fn path_string_with_trailing_separator(path: &Path) -> Result<String> {
    let mut value = path_string(path)?;
    if !value.ends_with(std::path::MAIN_SEPARATOR) {
        value.push(std::path::MAIN_SEPARATOR);
    }
    Ok(value)
}

fn signal_name(name: &str, signal: &str) -> bool {
    Command::new("pkill")
        .args([signal, "-x", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn process_name_exists(name: &str) -> bool {
    Command::new("pgrep")
        .args(["-x", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn stop_pid(pid: &str) {
    let _ = signal_pid(pid, "-TERM");
    if wait_for_process_exit(|| !pid_exists(pid)) {
        return;
    }
    let _ = signal_pid(pid, "-KILL");
}

fn signal_pid(pid: &str, signal: &str) -> bool {
    Command::new("kill")
        .args([signal, pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn pid_exists(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_process_exit<F>(mut exited: F) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < TERMINATION_GRACE_PERIOD {
        if exited() {
            return true;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
    exited()
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}
