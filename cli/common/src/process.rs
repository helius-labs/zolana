use std::{
    env,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context, Result};

pub const PROCESS_SCOPE_ENV: &str = "ZOLANA_PROCESS_SCOPE_DIR";
pub const TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(100);
const RECEIPT_EXTENSION: &str = "owner";

pub fn process_scope() -> Result<Option<PathBuf>> {
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

/// A child without an ownership receipt must not survive startup.
pub fn spawn_owned(scope: &Path, name: &str, command: &mut Command) -> Result<Child> {
    let mut child = command.spawn().with_context(|| {
        format!(
            "failed to spawn {}",
            command.get_program().to_string_lossy()
        )
    })?;
    if let Err(error) = record_owned_process(scope, name, child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(child)
}

/// Signals only listeners a receipt in `scope` names, and fails while another holds the port.
pub fn stop_owned_listener(scope: &Path, port: u16) -> Result<()> {
    for pid in listening_pids(port) {
        stop_owned_pid(scope, &pid);
    }
    // A stopped service keeps its socket until its last thread exits.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    ensure!(
        wait_until(TERMINATION_GRACE_PERIOD, POLL, || !answers(addr)),
        "port {port} is held by a process this cli did not start"
    );
    Ok(())
}

/// Processes merely connected to `port` are not its service.
pub fn listening_pids(port: u16) -> Vec<String> {
    Command::new("lsof")
        .args(["-t", "-i", &format!("TCP:{port}"), "-s", "TCP:LISTEN"])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub fn stop_owned_pid(scope: &Path, target: &str) {
    let Ok(entries) = std::fs::read_dir(scope) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path
            .extension()
            .is_some_and(|extension| extension == RECEIPT_EXTENSION)
            && OwnedReceipt::read(&path).is_some_and(|receipt| receipt.pid == target)
        {
            stop_owned_receipt(&path);
        }
    }
}

pub fn stop_pid(pid: &str) {
    let _ = signal_pid(pid, "-TERM");
    if !wait_until(TERMINATION_GRACE_PERIOD, POLL, || !signal_pid(pid, "-0")) {
        let _ = signal_pid(pid, "-KILL");
    }
}

pub fn answers(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, POLL).is_ok()
}

/// Checks once more after `timeout`, so a slow last poll still counts.
pub fn wait_until(timeout: Duration, poll: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if ready() {
            return true;
        }
        thread::sleep(poll);
    }
    ready()
}

struct OwnedReceipt {
    pid: String,
    identity: String,
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

fn record_owned_process(scope: &Path, name: &str, pid: u32) -> Result<()> {
    ensure!(
        name.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
        "invalid scoped service name"
    );
    let path = scope.join(name).with_extension(RECEIPT_EXTENSION);
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

/// Escalation needs the same identity after the grace period.
fn stop_owned_receipt(path: &Path) {
    let Some(receipt) = OwnedReceipt::read(path).filter(OwnedReceipt::alive) else {
        return;
    };
    let _ = signal_pid(&receipt.pid, "-TERM");
    if !wait_until(TERMINATION_GRACE_PERIOD, POLL, || !receipt.alive()) && receipt.alive() {
        let _ = signal_pid(&receipt.pid, "-KILL");
    }
}

fn valid_pid(pid: &str) -> bool {
    pid.parse::<u32>().is_ok_and(|pid| pid > 1)
}

fn signal_pid(pid: &str, signal: &str) -> bool {
    Command::new("kill")
        .args([signal, pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn process_identity(pid: &str) -> Option<String> {
    valid_pid(pid).then(|| os_process_identity(pid)).flatten()
}

/// The start tick from /proc is set at fork and survives exec, so a reused pid
/// starts later. The command line is unusable, exec may not have written it yet.
#[cfg(target_os = "linux")]
fn os_process_identity(pid: &str) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    live_start_ticks(&stat).map(str::to_owned)
}

/// Field 22, `None` for a zombie. The parenthesized name may hold spaces and parentheses.
#[cfg(any(target_os = "linux", test))]
fn live_start_ticks(stat: &str) -> Option<&str> {
    let (_, fields) = stat.rsplit_once(')')?;
    let mut fields = fields.split_whitespace();
    if matches!(fields.next()?, "Z" | "X" | "x") {
        return None;
    }
    fields.nth(18)
}

/// macOS `ps` reads the start time from the kernel as an absolute time.
#[cfg(not(target_os = "linux"))]
fn os_process_identity(pid: &str) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", pid, "-o", "lstart=", "-o", "command="])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let identity = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !identity.is_empty()).then_some(identity)
}

#[cfg(test)]
mod tests;
