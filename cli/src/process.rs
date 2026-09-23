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

pub(crate) const PROCESS_SCOPE_ENV: &str = "ZOLANA_PROCESS_SCOPE_DIR";
const RECEIPT_EXTENSION: &str = "owner";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Service {
    Surfpool,
    Validator,
    Photon,
    Prover,
}

impl Service {
    pub(crate) const fn log_name(self) -> &'static str {
        match self {
            Self::Surfpool => "surfpool",
            Self::Validator => "solana-test-validator",
            Self::Photon => "photon",
            Self::Prover => "prover-server",
        }
    }
}

struct OwnedReceipt {
    pid: String,
    identity: String,
}

pub(crate) fn spawn_service(
    binary: &Path,
    args: &[String],
    envs: &[(&str, &Path)],
    service: Service,
    log_dir: &str,
) -> Result<Child> {
    let scope = process_scope()?;
    let log_dir = service_log_dir(scope.as_deref(), log_dir);
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;
    let log_name = service.log_name();
    let log_path = log_dir.join(format!("{log_name}.log"));
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
    command.envs(envs.iter().copied());
    if let Some(scope) = scope.as_ref().filter(|_| service == Service::Photon) {
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
    let mut child = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to spawn {}", binary.display()))?;
    if let Some(scope) = scope {
        // 1. A scoped child without an ownership receipt must not survive
        // startup.
        if let Err(error) = record_owned_process(&scope, log_name, child.id()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    Ok(child)
}

fn service_log_dir(scope: Option<&Path>, log_dir: &str) -> PathBuf {
    scope.map_or_else(|| PathBuf::from(log_dir), |scope| scope.join("logs"))
}

/// The last `lines` lines a service started by [`spawn_service`] logged. A
/// service that exits early says why only there, so errors about it quote this.
pub(crate) fn log_tail(log_dir: &str, service: Service, lines: usize) -> String {
    let scope = match process_scope() {
        Ok(scope) => scope,
        Err(error) => {
            return format!(
                "could not locate the {} log ({error:#})",
                service.log_name()
            )
        }
    };
    let path =
        service_log_dir(scope.as_deref(), log_dir).join(format!("{}.log", service.log_name()));
    match std::fs::read_to_string(&path) {
        Ok(log) => {
            let skip = log.lines().count().saturating_sub(lines);
            let tail: Vec<&str> = log.lines().skip(skip).collect();
            format!("last lines of {}:\n{}", path.display(), tail.join("\n"))
        }
        Err(error) => format!("could not read {}: {error}", path.display()),
    }
}

pub(crate) fn remove_launchd_validators() {
    if !matches!(process_scope(), Ok(None)) {
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

/// Stop the process listening on `port`. Processes merely connected to it, such
/// as a test's RPC client or Photon polling the validator, are not the service
/// and keep running.
pub(crate) fn stop_port(port: u16) {
    let Some(scope) = stop_scope() else {
        return;
    };
    let output = Command::new("lsof")
        .args(["-t", "-i", &format!("TCP:{port}"), "-s", "TCP:LISTEN"])
        .output();
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

pub(crate) fn process_scope() -> Result<Option<PathBuf>> {
    let Some(scope) = env::var_os(PROCESS_SCOPE_ENV) else {
        return Ok(None);
    };
    let scope = PathBuf::from(scope);
    if !scope.is_absolute()
        || !scope.is_dir()
        || scope.parent().is_none()
        || std::fs::symlink_metadata(&scope)?.file_type().is_symlink()
    {
        bail!("{PROCESS_SCOPE_ENV} must name an existing absolute task directory");
    }
    Ok(Some(scope))
}

/// An invalid scope refuses the stop, never an unscoped fallback.
fn stop_scope() -> Option<Option<PathBuf>> {
    match process_scope() {
        Ok(scope) => Some(scope),
        Err(error) => {
            eprintln!("refusing unscoped stop ({error:#})");
            None
        }
    }
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

fn valid_pid(pid: &str) -> bool {
    pid.parse::<u32>().is_ok_and(|pid| pid > 1)
}

fn receipt_path(scope: &Path, name: &str) -> PathBuf {
    scope.join(name).with_extension(RECEIPT_EXTENSION)
}

fn process_identity(pid: &str) -> Option<String> {
    if !valid_pid(pid) {
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
    let path = receipt_path(scope, name);
    if std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        bail!("scoped service receipt is not a regular file");
    }
    if OwnedReceipt::read(&path).is_some_and(|receipt| receipt.alive()) {
        bail!("task-owned {name} is still running");
    }
    let pid = pid.to_string();
    let identity =
        process_identity(&pid).context("spawned service exited before ownership was recorded")?;
    std::fs::write(path, format!("{pid}\n{identity}\n")).context("record task-owned service")
}

impl OwnedReceipt {
    fn read(path: &Path) -> Option<Self> {
        if !std::fs::symlink_metadata(path).ok()?.file_type().is_file() {
            return None;
        }
        let receipt = std::fs::read_to_string(path).ok()?;
        let (pid, identity) = receipt.trim_end().split_once('\n')?;
        if !valid_pid(pid) || identity.is_empty() {
            return None;
        }
        Some(Self {
            pid: pid.to_owned(),
            identity: identity.to_owned(),
        })
    }

    /// A reused pid with another identity is another process.
    fn alive(&self) -> bool {
        process_identity(&self.pid).as_deref() == Some(self.identity.as_str())
    }
}

fn stop_owned_receipt(path: &Path) {
    // 1. Only a receipt matching the live process may authorize a signal.
    let Some(receipt) = OwnedReceipt::read(path) else {
        return;
    };
    if !receipt.alive() {
        return;
    }
    let _ = signal_pid(&receipt.pid, "-TERM");
    // 2. Escalation requires the same process identity after the grace period.
    if !wait_for_process_exit(|| !receipt.alive()) && receipt.alive() {
        let _ = signal_pid(&receipt.pid, "-KILL");
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
            .is_some_and(|extension| extension == RECEIPT_EXTENSION)
            && OwnedReceipt::read(&path).is_some_and(|receipt| receipt.pid == target)
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
            assert!(OwnedReceipt::read(&receipt).is_none());
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
        assert!(OwnedReceipt::read(&receipt).is_none());
        assert!(record_owned_process(&scope, "probe", std::process::id()).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "42\nidentity\n");
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(scope).unwrap();
    }
}
