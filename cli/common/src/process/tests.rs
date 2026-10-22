use std::{
    net::TcpListener,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;

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
fn start_ticks_count_fields_from_the_last_parenthesis() {
    let stat = "4242 (sleep (x) 1) S 1 4242 4242 0 -1 4194304 90 0 0 0 0 0 0 0 20 0 1 0 987654 5779456 190";
    assert_eq!(live_start_ticks(stat), Some("987654"));
    let zombie = stat.replacen(") S ", ") Z ", 1);
    assert_eq!(live_start_ticks(&zombie), None);
    assert_eq!(live_start_ticks("no parenthesis here"), None);
}

#[test]
fn a_live_process_keeps_one_identity() {
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = child.id().to_string();
    let first = process_identity(&pid).expect("a live process has an identity");
    for _ in 0..50 {
        assert_eq!(process_identity(&pid).as_deref(), Some(first.as_str()));
    }
    child.kill().unwrap();
    child.wait().unwrap();
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
    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn an_owned_child_is_stopped_by_its_pid() {
    let scope = directory();
    let mut child = spawn_owned(&scope, "probe", Command::new("sleep").arg("30")).unwrap();
    stop_owned_pid(&scope, &(child.id() + 1).to_string());
    assert!(child.try_wait().unwrap().is_none());
    stop_owned_pid(&scope, &child.id().to_string());
    child.wait().unwrap();
    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn invalid_pid_receipts_never_reach_process_signals() {
    let scope = directory();
    let receipt = scope.join("probe.owner");
    for pid in ["0", "1", "-1", "42 -TERM", ""] {
        std::fs::write(&receipt, format!("{pid}\nidentity\n")).unwrap();
        assert!(OwnedReceipt::read(&receipt).is_none());
    }
    std::fs::remove_dir_all(scope).unwrap();
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
    std::fs::remove_dir_all(scope).unwrap();
}

/// The listener is this test process, which has no receipt.
#[test]
fn a_foreign_listener_is_left_running_and_reported() {
    let scope = directory();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let error = stop_owned_listener(&scope, port).expect_err("foreign listener");
    assert_eq!(
        error.to_string(),
        format!("port {port} is held by a process this cli did not start")
    );
    drop(listener);
    stop_owned_listener(&scope, port).expect("free port");
    std::fs::remove_dir_all(scope).unwrap();
}
