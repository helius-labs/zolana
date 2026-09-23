//! PATH holds only empty stand-in binaries: nothing spawns and no local service is stopped.

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Sandbox {
    dir: PathBuf,
    rpc_port: u16,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        fs::create_dir_all(&dir).expect("create the sandbox");
        for binary in ["surfpool", "solana-test-validator"] {
            fs::write(dir.join(binary), "").expect("write a stand-in binary");
        }
        // `dev start` waits for its RPC port to be free.
        let rpc_port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("reserve a free port")
            .port();
        Self { dir, rpc_port }
    }

    fn dev_start(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_zolana"))
            .args(["dev", "start", "--local", "--rpc-port"])
            .arg(self.rpc_port.to_string())
            .arg("--log-dir")
            .arg(self.dir.join("logs"))
            .args(args)
            .env("PATH", &self.dir)
            .env("SURFPOOL_BIN", self.dir.join("surfpool"))
            .output()
            .expect("run zolana")
    }

    fn surfpool_args(&self, args: &[&str]) -> Vec<String> {
        let output = self.dev_start(args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let prefix = format!(
            "Starting surfpool: {} ",
            self.dir.join("surfpool").display()
        );
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("no surfpool command line in {stdout}"))
            .split(' ')
            .map(str::to_string)
            .collect()
    }
}

#[test]
fn forwards_the_slot_time_to_surfpool() {
    let sandbox = Sandbox::new("forwards_the_slot_time_to_surfpool");
    let rpc_port = sandbox.rpc_port.to_string();
    let ws_port = sandbox.rpc_port.saturating_add(1).to_string();
    let expected = [
        "start",
        "--offline",
        "--no-tui",
        "--no-deploy",
        "--no-studio",
        "--port",
        &rpc_port,
        "--host",
        "127.0.0.1",
        "--ws-port",
        &ws_port,
        "--slot-time",
        "50",
    ];
    assert_eq!(sandbox.surfpool_args(&["--slot-time", "50"]), expected);
}

/// surfpool's own WebSocket default is a fixed 8900.
#[test]
fn binds_the_surfpool_websocket_above_the_rpc_port() {
    let sandbox = Sandbox::new("binds_the_surfpool_websocket_above_the_rpc_port");
    let ws_port = sandbox.rpc_port.saturating_add(1).to_string();
    let actual = sandbox.surfpool_args(&[]);
    assert!(
        actual
            .windows(2)
            .any(|args| args == ["--ws-port", ws_port.as_str()]),
        "{actual:?}"
    );
}

#[test]
fn rejects_the_slot_time_with_solana_test_validator() {
    let sandbox = Sandbox::new("rejects_the_slot_time_with_solana_test_validator");
    let output = sandbox.dev_start(&["--no-use-surfpool", "--slot-time", "50"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("--slot-time is only supported with surfpool"),
        "{stderr}"
    );
}
