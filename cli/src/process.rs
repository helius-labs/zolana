use std::{
    env,
    ffi::OsStr,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
pub(crate) use zolana_cli_common::process::process_scope;
use zolana_cli_common::process::{listening_pids, spawn_owned, stop_owned_pid, stop_pid};

use crate::{config::TERMINATION_GRACE_PERIOD, http::wait_for_port_closed};

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

pub(crate) fn spawn_service(
    binary: &Path,
    args: &[String],
    envs: &[(&str, &OsStr)],
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
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    match scope {
        Some(scope) => spawn_owned(&scope, log_name, &mut command),
        None => command
            .spawn()
            .with_context(|| format!("failed to spawn {}", binary.display())),
    }
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
    // An invalid scope refuses the stop, never an unscoped fallback.
    match process_scope() {
        Ok(Some(scope)) => listening_pids(port)
            .iter()
            .for_each(|pid| stop_owned_pid(&scope, pid)),
        Ok(None) => listening_pids(port).iter().for_each(|pid| stop_pid(pid)),
        Err(error) => eprintln!("refusing unscoped stop ({error:#})"),
    }
}

/// Foreign listeners must remain running.
pub(crate) fn require_scoped_port_available(port: u16) -> Result<()> {
    if process_scope()?.is_some() {
        let occupied = || format!("port {port} is occupied outside the stopped task services");
        // A stopped service keeps its socket until its last thread exits.
        wait_for_port_closed(port, TERMINATION_GRACE_PERIOD).with_context(occupied)?;
        std::net::TcpListener::bind(("127.0.0.1", port)).with_context(occupied)?;
    }
    Ok(())
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

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}
