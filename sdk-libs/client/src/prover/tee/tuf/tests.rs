use std::{
    io::{BufRead, BufReader},
    net::{TcpListener, TcpStream},
    sync::{atomic::AtomicUsize, Mutex},
    thread,
};

use super::*;

#[derive(Deserialize)]
struct Vector {
    bootstrap_root: String,
    repositories: BTreeMap<String, BTreeMap<String, String>>,
    fractional_valid_until: u64,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!(
        "../../../../../../test-vectors/tee_tuf_repository.json"
    ))
    .unwrap()
}

struct Server {
    address: std::net::SocketAddr,
    state: Arc<ServerState>,
    thread: Option<thread::JoinHandle<()>>,
}

struct ServerState {
    files: Mutex<BTreeMap<String, String>>,
    requests: AtomicUsize,
    headers: Mutex<Vec<String>>,
    hold: AtomicBool,
    redirect: AtomicBool,
    stop: AtomicBool,
}

impl Server {
    fn new(case: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(ServerState {
            files: Mutex::new(vector().repositories.remove(case).unwrap()),
            requests: AtomicUsize::new(0),
            headers: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
            redirect: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let thread = thread::spawn({
            let state = Arc::clone(&state);
            move || {
                while !state.stop.load(Ordering::Acquire) {
                    let (mut socket, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => panic!("test listener failed: {error}"),
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(&mut socket);
                    let mut header = String::new();
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() || line.is_empty() {
                            break;
                        }
                        header.push_str(&line);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let path = header
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/')
                        .to_owned();
                    state.headers.lock().unwrap().push(header);
                    state.requests.fetch_add(1, Ordering::SeqCst);
                    while state.hold.load(Ordering::Acquire) && !state.stop.load(Ordering::Acquire)
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    if state.redirect.load(Ordering::Acquire) {
                        let _ = socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: /unexpected-redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        continue;
                    }
                    let files = state.files.lock().unwrap();
                    let (status, body) = files
                        .get(&path)
                        .map(|value| (200, value.as_str()))
                        .unwrap_or((404, ""));
                    let _ = write!(socket, "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                }
            }
        });
        Self {
            address,
            state,
            thread: Some(thread),
        }
    }

    fn options(&self, cache: &Path) -> TufTeePolicyOptions {
        TufTeePolicyOptions {
            network: "fixture".into(),
            root_json: vector().bootstrap_root,
            metadata_url: Url::parse(&format!("http://{}/metadata/", self.address)).unwrap(),
            targets_url: Url::parse(&format!("http://{}/targets/", self.address)).unwrap(),
            cache_directory: cache.to_owned(),
            refresh_interval: None,
        }
    }

    fn source(&self, cache: &Path) -> Arc<TeePolicySource> {
        tuf_tee_policy(self.options(cache)).unwrap()
    }
    fn set_case(&self, case: &str) {
        *self.state.files.lock().unwrap() = vector().repositories.remove(case).unwrap();
    }
    fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        self.state.hold.store(false, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn namespace(cache: &Path) -> PathBuf {
    fs::read_dir(cache).unwrap().next().unwrap().unwrap().path()
}

#[tokio::test]
async fn reference_verification_accepts_shared_fixture_and_persistent_updates() {
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    let source = server.source(cache.path());
    let fleet = source.resolve().await.unwrap();
    assert_eq!(fleet.revision(), 1);
    assert_eq!(fleet.deployments().len(), 3);
    assert_eq!(server.requests(), 5);
    source.resolve().await.unwrap();
    assert_eq!(server.requests(), 5);
    server.set_case("v2");
    assert_eq!(
        server
            .source(cache.path())
            .resolve()
            .await
            .unwrap()
            .revision(),
        2
    );
    server.set_case("rotated");
    assert_eq!(
        server
            .source(cache.path())
            .resolve()
            .await
            .unwrap()
            .revision(),
        2
    );
    let root: Signed<Root> =
        serde_json::from_slice(&fs::read(namespace(cache.path()).join("root.json")).unwrap())
            .unwrap();
    assert_eq!(root.signed.version.get(), 2);
    assert!(server
        .state
        .headers
        .lock()
        .unwrap()
        .iter()
        .all(
            |header| !header.to_ascii_lowercase().contains("authorization:")
                && !header.to_ascii_lowercase().contains("api-key")
        ));
}

#[tokio::test]
async fn same_shared_repositories_reject_bad_signatures_hashes_expiry_and_rotation() {
    for case in [
        "bad_signature",
        "hash_mismatch",
        "weak_hash",
        "expired",
        "rotation_old_only",
        "rotation_new_only",
    ] {
        let server = Server::new(case);
        let cache = tempfile::tempdir().unwrap();
        let result = server.source(cache.path()).resolve().await;
        assert!(result.is_err(), "unexpected acceptance of {case}");
        assert!(!namespace(cache.path()).join(FLOOR).exists());
    }
}

#[tokio::test]
async fn policy_floor_survives_restarts_and_higher_metadata_versions() {
    let server = Server::new("v2");
    let cache = tempfile::tempdir().unwrap();
    server.source(cache.path()).resolve().await.unwrap();
    server.set_case("rollback");
    assert!(matches!(
        server.source(cache.path()).resolve().await,
        Err(TeeError::PolicyRollback)
    ));
    let floor: Floor =
        serde_json::from_slice(&fs::read(namespace(cache.path()).join(FLOOR)).unwrap()).unwrap();
    assert_eq!(floor.revision, 2);
    server.set_case("v1");
    assert!(server.source(cache.path()).resolve().await.is_err());
}

#[tokio::test]
async fn changed_policy_bytes_under_same_revision_are_rejected_after_restart() {
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    server.source(cache.path()).resolve().await.unwrap();
    server.set_case("substitution");
    assert!(matches!(
        server.source(cache.path()).resolve().await,
        Err(TeeError::PolicyRollback)
    ));
}

#[tokio::test]
async fn fractional_authentication_expiry_is_never_rounded_up() {
    let server = Server::new("fractional");
    let cache = tempfile::tempdir().unwrap();
    let fleet = server.source(cache.path()).resolve().await.unwrap();
    assert_eq!(fleet.expires_at(), vector().fractional_valid_until);
}

#[tokio::test]
async fn cache_damage_fails_before_network_instead_of_resetting_trust() {
    for name in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
        FLOOR,
        STATE,
        "latest_known_time.json",
    ] {
        let server = Server::new("v1");
        let cache = tempfile::tempdir().unwrap();
        server.source(cache.path()).resolve().await.unwrap();
        let before = server.requests();
        fs::remove_file(namespace(cache.path()).join(name)).unwrap();
        assert!(
            matches!(
                server.source(cache.path()).resolve().await,
                Err(TeeError::PolicyStorage)
            ),
            "missing {name}"
        );
        assert_eq!(server.requests(), before);
    }
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    server.source(cache.path()).resolve().await.unwrap();
    let before = server.requests();
    fs::write(namespace(cache.path()).join("timestamp.json"), b"{").unwrap();
    assert!(matches!(
        server.source(cache.path()).resolve().await,
        Err(TeeError::PolicyStorage)
    ));
    assert_eq!(server.requests(), before);
}

#[tokio::test]
async fn independent_sources_serialize_over_the_same_local_cache() {
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    let first = server.source(cache.path());
    let second = server.source(cache.path());
    let (first, second) = tokio::join!(first.resolve(), second.resolve());
    assert_eq!(first.unwrap().revision(), 1);
    assert_eq!(second.unwrap().revision(), 1);
    assert_eq!(inventory(&namespace(cache.path())).unwrap().len(), 6);
}

#[tokio::test]
async fn cancellation_closes_network_and_releases_lock_after_storage_finishes() {
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    server.state.hold.store(true, Ordering::Release);
    let source = server.source(cache.path());
    let owner = tokio::spawn(async move { source.resolve().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.requests() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(namespace(cache.path()).join("lock"))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => tokio::time::sleep(Duration::from_millis(1)).await,
                Err(_) => panic!("cannot inspect cache lock"),
            }
        }
    })
    .await
    .unwrap();
    // The HTTP server is still holding the original response: the client cancelled it.
    assert!(server.state.hold.load(Ordering::Acquire));
    assert!(inventory(&namespace(cache.path())).is_ok());
    drop(lock);
    server.state.hold.store(false, Ordering::Release);
    assert_eq!(
        server
            .source(cache.path())
            .resolve()
            .await
            .unwrap()
            .revision(),
        1
    );
}

#[tokio::test]
async fn redirects_and_oversized_metadata_never_reach_a_second_endpoint() {
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    server.state.redirect.store(true, Ordering::Release);
    assert!(server.source(cache.path()).resolve().await.is_err());
    assert_eq!(server.requests(), 1);
    server.state.redirect.store(false, Ordering::Release);
    server.state.files.lock().unwrap().insert(
        "metadata/2.root.json".into(),
        " ".repeat(MAX_ROOT_BYTES + 1),
    );
    assert!(server.source(cache.path()).resolve().await.is_err());
    assert_eq!(server.requests(), 2);
}

#[tokio::test]
async fn wrong_network_is_rejected_and_unsafe_urls_fail_before_http() {
    let server = Server::new("v1");
    let cache = tempfile::tempdir().unwrap();
    for url in [
        "http://policies.example/",
        "https://user:password@policies.example/",
        "https://policies.example/?api-key=secret",
        "https://policies.example/#fragment",
    ] {
        let mut options = server.options(cache.path());
        options.metadata_url = Url::parse(url).unwrap();
        assert!(tuf_tee_policy(options).is_err());
    }
    assert_eq!(server.requests(), 0);
    let mut options = server.options(cache.path());
    options.network = "mainnet".into();
    assert!(tuf_tee_policy(options).unwrap().resolve().await.is_err());
}

#[cfg(unix)]
#[test]
fn os_lock_is_shared_with_other_processes_and_released_on_process_exit() {
    use std::process::{Command, Stdio};
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("lock");
    let mut child = Command::new("python3").arg("-c").arg("import fcntl,sys,time; f=open(sys.argv[1],'w'); fcntl.flock(f,fcntl.LOCK_EX); print('locked',flush=True); sys.stdin.buffer.read(1)")
        .arg(&path).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "locked");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let blocked = matches!(lock.try_lock(), Err(TryLockError::WouldBlock));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(blocked);
    assert!(lock.try_lock().is_ok());
}
