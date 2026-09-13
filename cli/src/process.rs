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
    // 1. Keep scoped logs and Photon data inside the task directory.
    let scope = process_scope()?;
    let scoped_log_dir = scope.as_ref().map(|scope| scope.join("logs"));
    let log_dir = scoped_log_dir
        .as_ref()
        .map(|path| path.to_string_lossy())
        .unwrap_or_else(|| log_dir.into());
    std::fs::create_dir_all(log_dir.as_ref())
        .with_context(|| format!("failed to create log directory {log_dir}"))?;
    let log_path = Path::new(log_dir.as_ref()).join(format!("{log_name}.log"));
    println!("Writing {log_name} logs to {}", log_path.display());
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    let mut command = Command::new(binary);
    if let Some(scope) = scope.as_ref().filter(|_| log_name == "photon") {
        let temporary = scope.join(format!("photon-data-{}", std::process::id()));
        if std::fs::symlink_metadata(&temporary)
            .is_ok_and(|metadata| !metadata.file_type().is_dir())
        {
            bail!("scoped Photon database path is not a directory");
        }
        std::fs::create_dir_all(&temporary).context("create scoped Photon database directory")?;
        command
            .env("TMPDIR", &temporary)
            .env("TEMP", &temporary)
            .env("TMP", &temporary);
    }
    // 2. Record the spawned identity before returning process ownership.
    let mut child = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to spawn {}", binary.display()))?;
    if let Some(scope) = scope {
        if let Err(error) = record_owned_process(&scope, log_name, child.id()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    Ok(child)
}

pub(crate) fn remove_launchd_validators() {
    if env::var_os("ZOLANA_PROCESS_SCOPE_DIR").is_some() {
        return;
    }
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
    match process_scope() {
        Ok(Some(scope)) => {
            stop_owned_receipt(&scope.join(format!("{name}.owner")));
            return;
        }
        Err(error) => {
            eprintln!("refusing unscoped stop ({error:#})");
            return;
        }
        Ok(None) => {}
    }
    let _ = signal_name(name, "-TERM");
    if wait_for_process_exit(|| !process_name_exists(name)) {
        return;
    }
    let _ = signal_name(name, "-KILL");
}

pub(crate) fn stop_port(port: u16) {
    let scope = match process_scope() {
        Ok(scope) => scope,
        Err(error) => {
            eprintln!("refusing unscoped stop ({error:#})");
            return;
        }
    };
    let output = Command::new("lsof").arg(format!("-ti:{port}")).output();
    let Ok(output) = output else {
        return;
    };

    for pid in String::from_utf8_lossy(&output.stdout).lines() {
        let pid = pid.trim();
        if !pid.is_empty() {
            match &scope {
                Some(scope) => stop_owned_pid(scope, pid),
                None => stop_pid(pid),
            }
        }
    }
}

/// Scoped stops require matching process receipts.
pub(crate) fn process_scope() -> Result<Option<PathBuf>> {
    let Some(scope) = env::var_os("ZOLANA_PROCESS_SCOPE_DIR") else {
        return Ok(None);
    };
    let scope = PathBuf::from(scope);
    if !scope.is_absolute()
        || !scope.is_dir()
        || scope.parent().is_none()
        || std::fs::symlink_metadata(&scope)?.file_type().is_symlink()
    {
        bail!("ZOLANA_PROCESS_SCOPE_DIR must name an existing absolute task directory");
    }
    Ok(Some(scope))
}

/// Foreign listeners must remain running.
pub(crate) fn require_scoped_port_available(port: u16) -> Result<()> {
    if process_scope()?.is_some() {
        std::net::TcpListener::bind(("127.0.0.1", port)).with_context(|| {
            format!("port {port} is occupied outside the stopped task services")
        })?;
    }
    Ok(())
}

fn process_identity(pid: &str) -> Option<String> {
    if !pid.parse::<u32>().is_ok_and(|pid| pid > 1) {
        return None;
    }
    let output = Command::new("ps")
        .args(["-p", pid, "-o", "lstart=", "-o", "command="])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let identity = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !identity.is_empty()).then_some(identity)
}

fn record_owned_process(scope: &Path, name: &str, pid: u32) -> Result<()> {
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        bail!("invalid scoped service name");
    }
    let path = scope.join(format!("{name}.owner"));
    if std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        bail!("scoped service receipt is not a regular file");
    }
    if owned_receipt(&path)
        .is_some_and(|(pid, identity)| process_identity(&pid).as_deref() == Some(identity.as_str()))
    {
        bail!("task-owned {name} is still running");
    }
    let pid = pid.to_string();
    let identity =
        process_identity(&pid).context("spawned service exited before ownership was recorded")?;
    std::fs::write(path, format!("{pid}\n{identity}\n")).context("record task-owned service")
}

fn owned_receipt(path: &Path) -> Option<(String, String)> {
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    let receipt = std::fs::read_to_string(path).ok()?;
    let (pid, identity) = receipt.trim_end().split_once('\n')?;
    if !pid.parse::<u32>().is_ok_and(|pid| pid > 1) || identity.is_empty() {
        return None;
    }
    Some((pid.to_owned(), identity.to_owned()))
}

fn stop_owned_receipt(path: &Path) {
    // 1. Match the receipt against the live process identity.
    let Some((pid, identity)) = owned_receipt(path) else {
        return;
    };
    if process_identity(&pid).as_deref() != Some(identity.as_str()) {
        return;
    }
    // 2. Escalate only while the same process identity remains alive.
    let _ = signal_pid(&pid, "-TERM");
    if !wait_for_process_exit(|| process_identity(&pid).as_deref() != Some(identity.as_str()))
        && process_identity(&pid).as_deref() == Some(identity.as_str())
    {
        let _ = signal_pid(&pid, "-KILL");
    }
}

fn stop_owned_pid(scope: &Path, target: &str) {
    let Ok(entries) = std::fs::read_dir(scope) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "owner")
            && owned_receipt(&path).is_some_and(|(pid, _)| pid == target)
        {
            stop_owned_receipt(&path);
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

#[cfg(test)]
mod scope_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn directory() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "zolana-process-scope-{}-{unique}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn a_reused_pid_receipt_cannot_stop_an_unrelated_process() {
        let scope = directory();
        let receipt = scope.join("probe.owner");
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        std::fs::write(&receipt, format!("{pid}\nnot this process identity\n")).unwrap();
        stop_owned_receipt(&receipt);
        assert!(child.try_wait().unwrap().is_none());
        record_owned_process(&scope, "probe", pid).unwrap();
        assert!(record_owned_process(&scope, "probe", pid).is_err());
        stop_owned_receipt(&receipt);
        child.wait().unwrap();
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_dir(scope).unwrap();
    }

    #[test]
    fn invalid_pid_receipts_never_reach_process_signals() {
        let scope = directory();
        let receipt = scope.join("probe.owner");
        for pid in ["0", "1", "-1", "42 -TERM", ""] {
            std::fs::write(&receipt, format!("{pid}\nidentity\n")).unwrap();
            assert!(owned_receipt(&receipt).is_none());
        }
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_dir(scope).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_supply_or_receive_service_ownership() {
        let scope = directory();
        let target = scope.join("foreign");
        let receipt = scope.join("probe.owner");
        std::fs::write(&target, "42\nidentity\n").unwrap();
        std::os::unix::fs::symlink(&target, &receipt).unwrap();
        assert!(owned_receipt(&receipt).is_none());
        assert!(record_owned_process(&scope, "probe", std::process::id()).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "42\nidentity\n");
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(scope).unwrap();
    }
}
