//! Static TUF repositories with explicitly bootstrapped trust and local rollback state.

mod json;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::{
    schema::{Root, Signed},
    IntoVec, Limits, RepositoryLoader, TargetName, Transport, TransportError, TransportErrorKind,
    TransportStream,
};
use url::{Host, Url};

use super::{
    source::{LOAD_TIMEOUT, MAX_POLICY_BYTES},
    TeeError, TeeFleetPolicy, TeePolicyDocument, TeePolicyLoader, TeePolicySource,
};

const MAX_METADATA_BYTES: usize = 2 << 20;
const MAX_ROOT_BYTES: usize = 512_000;
const STATE: &str = "cache-state.json";
const FLOOR: &str = "fleet-floor.json";
const CACHE_FILES: [&str; 6] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
    "latest_known_time.json",
    FLOOR,
];

/// Node and Rust caches have different formats; each uses a separate namespace.
pub struct TufTeePolicyOptions {
    pub network: String,
    /// Reviewed root metadata obtained independently of this repository's serving endpoint.
    pub root_json: String,
    pub metadata_url: Url,
    pub targets_url: Url,
    /// Absolute path on trusted local storage, never a network filesystem.
    pub cache_directory: PathBuf,
    pub refresh_interval: Option<Duration>,
}

/// Resolve policies from a static repository without inheriting prover credentials or proxies.
pub fn tuf_tee_policy(mut options: TufTeePolicyOptions) -> Result<Arc<TeePolicySource>, TeeError> {
    let network = options.network.as_bytes();
    if network.is_empty()
        || network.len() > 128
        || !network[0].is_ascii_alphanumeric()
        || !network
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || options.root_json.len() > MAX_ROOT_BYTES
        || !options.cache_directory.is_absolute()
    {
        return Err(invalid());
    }
    options.metadata_url = repository_url(options.metadata_url)?;
    options.targets_url = repository_url(options.targets_url)?;
    json::metadata(options.root_json.as_bytes(), "root")?;
    let root: Signed<Root> = serde_json::from_str(&options.root_json).map_err(|_| invalid())?;
    root.signed.verify_role(&root).map_err(|_| invalid())?;
    let namespace = serde_json::to_vec(&(
        &options.network,
        options.metadata_url.as_str(),
        options.targets_url.as_str(),
        &options.root_json,
    ))
    .map_err(|_| invalid())?;
    let directory = options
        .cache_directory
        .join(format!("rust-tuf-{}", digest(&namespace)));
    let interval = options.refresh_interval.unwrap_or(Duration::from_secs(60));
    let network = options.network.clone();
    let loader = Loader {
        config: Arc::new(Config { options, directory }),
    };
    Ok(Arc::new(
        TeePolicySource::new(network, loader).with_refresh_interval(interval)?,
    ))
}

struct Config {
    options: TufTeePolicyOptions,
    directory: PathBuf,
}

struct Loader {
    config: Arc<Config>,
}

#[async_trait]
impl TeePolicyLoader for Loader {
    async fn load(&self) -> Result<TeePolicyDocument, TeeError> {
        let control = Arc::new(Control {
            cancelled: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
            deadline: Instant::now() + LOAD_TIMEOUT,
        });
        let _cancel = CancelOnDrop(Arc::clone(&control));
        let config = Arc::clone(&self.config);
        // The worker owns the OS lock, and drains its private runtime's filesystem
        // operations before releasing it. Dropping this caller cancels network I/O
        // without abandoning a pending trusted-metadata write behind an unlocked cache.
        tokio::task::spawn_blocking(move || worker(config, control))
            .await
            .map_err(|_| TeeError::PolicyUnavailable)?
    }
}

fn worker(config: Arc<Config>, control: Arc<Control>) -> Result<TeePolicyDocument, TeeError> {
    create_directory(&config.directory)?;
    let _lock = acquire_lock(&config.directory, &control)?;
    preflight(&config)?;
    control.check()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| TeeError::PolicyUnavailable)?;
    let result = runtime.block_on(refresh(&config, Arc::clone(&control)));
    // Runtime drop waits for its blocking filesystem operations, including error paths.
    drop(runtime);
    seal(&config.directory)?;
    control.check()?;
    result
}

async fn refresh(config: &Config, control: Arc<Control>) -> Result<TeePolicyDocument, TeeError> {
    let root = local_bytes(&config.directory.join("root.json"), MAX_ROOT_BYTES)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(LOAD_TIMEOUT)
        .build()
        .map_err(|_| TeeError::PolicyRepository)?;
    let transport = PolicyTransport {
        client,
        metadata: config.options.metadata_url.clone(),
        targets: config.options.targets_url.clone(),
        network: config.options.network.clone(),
        control: Arc::clone(&control),
    };
    let repository = RepositoryLoader::new(
        &root,
        config.options.metadata_url.clone(),
        config.options.targets_url.clone(),
    )
    .datastore(&config.directory)
    .transport(transport)
    .limits(Limits {
        max_root_size: MAX_ROOT_BYTES as u64,
        max_targets_size: MAX_METADATA_BYTES as u64,
        max_timestamp_size: 16_384,
        max_snapshot_size: MAX_METADATA_BYTES as u64,
        max_root_updates: 32,
    })
    .load()
    .await
    .map_err(|_| TeeError::PolicyRepository)?;
    control.check()?;
    if repository.targets().signed.delegations.is_some() {
        return Err(TeeError::PolicyRepository);
    }
    let name =
        TargetName::new(format!("{}/fleet.json", config.options.network)).map_err(|_| invalid())?;
    let info = repository
        .targets()
        .signed
        .targets
        .get(&name)
        .ok_or(TeeError::PolicyRepository)?;
    // This is the publisher's SHA-256 profile. Never accept empty, weak or ignored hashes.
    if info.length == 0
        || info.length > MAX_POLICY_BYTES as u64
        || info.hashes.sha256.as_ref().len() != 32
        || !info.hashes._extra.is_empty()
    {
        return Err(TeeError::PolicyRepository);
    }
    let stream = repository
        .read_target(&name)
        .await
        .map_err(|_| TeeError::PolicyRepository)?
        .ok_or(TeeError::PolicyRepository)?;
    // Do not inspect any target bytes until the stream's final hash/length check succeeds.
    let bytes = stream
        .into_vec()
        .await
        .map_err(|_| TeeError::PolicyRepository)?;
    control.check()?;
    let policy_json = String::from_utf8(bytes).map_err(|_| TeeError::PolicyRepository)?;
    let fleet = TeeFleetPolicy::from_json(&policy_json, &config.options.network)
        .map_err(|_| TeeError::PolicyRepository)?;
    let expiries = [
        repository.root().signed.expires,
        repository.timestamp().signed.expires,
        repository.snapshot().signed.expires,
        repository.targets().signed.expires,
    ];
    let valid_until = expiries
        .into_iter()
        .map(|expiry| u64::try_from(expiry.as_second()).map_err(|_| TeeError::PolicyExpired))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or(TeeError::PolicyExpired)?
        .min(fleet.expires_at());
    if super::source::now_secs()? >= valid_until {
        return Err(TeeError::PolicyExpired);
    }
    let floor_path = config.directory.join(FLOOR);
    let sha256 = digest(policy_json.as_bytes());
    if let Some(bytes) = optional_bytes(&floor_path, 1024)? {
        let previous: Floor =
            serde_json::from_slice(&bytes).map_err(|_| TeeError::PolicyStorage)?;
        if fleet.revision() < previous.revision
            || (fleet.revision() == previous.revision && sha256 != previous.sha256)
        {
            return Err(TeeError::PolicyRollback);
        }
    }
    control.check()?;
    atomic_json(
        &floor_path,
        &Floor {
            revision: fleet.revision(),
            sha256,
        },
    )?;
    Ok(TeePolicyDocument {
        policy_json,
        valid_until,
    })
}

#[derive(Clone)]
struct PolicyTransport {
    client: reqwest::Client,
    metadata: Url,
    targets: Url,
    network: String,
    control: Arc<Control>,
}

impl fmt::Debug for PolicyTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TEE policy transport")
    }
}

#[async_trait]
impl Transport for PolicyTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        // tough 0.24 treats any fetch() error during a root probe as "no next
        // root". Only an actual 403/404 may take that path; deliver other
        // failures through the stream so the update aborts instead.
        match self.bytes(url).await {
            Ok(bytes) => Ok(Box::pin(stream::iter([Ok(Bytes::from(bytes))]))),
            Err(error) if error.kind() == TransportErrorKind::FileNotFound => Err(error),
            Err(error) => Ok(Box::pin(stream::iter([Err(error)]))),
        }
    }
}

impl PolicyTransport {
    async fn bytes(&self, url: Url) -> Result<Vec<u8>, TransportError> {
        let url = self
            .canonical_url(url)
            .map_err(|_| transport_error(TransportErrorKind::Other))?;
        let limit = self
            .limit(&url)
            .map_err(|_| transport_error(TransportErrorKind::Other))?;
        let role = if url.origin() == self.metadata.origin()
            && url.path().starts_with(self.metadata.path())
        {
            ["root", "timestamp", "snapshot", "targets"]
                .into_iter()
                .find(|role| {
                    url.path().ends_with(&format!("/{role}.json"))
                        || url.path().ends_with(&format!(".{role}.json"))
                })
        } else {
            None
        };
        let fetch = async {
            self.control
                .check()
                .map_err(|_| transport_error(TransportErrorKind::Other))?;
            let mut response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|_| transport_error(TransportErrorKind::Other))?;
            if !response.status().is_success() {
                let kind = if matches!(response.status().as_u16(), 403 | 404) {
                    TransportErrorKind::FileNotFound
                } else {
                    TransportErrorKind::Other
                };
                return Err(transport_error(kind));
            }
            if response
                .content_length()
                .is_some_and(|length| length > limit as u64)
            {
                return Err(transport_error(TransportErrorKind::Other));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| transport_error(TransportErrorKind::Other))?
            {
                if chunk.len() > limit.saturating_sub(bytes.len()) {
                    return Err(transport_error(TransportErrorKind::Other));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        };
        let bytes = tokio::select! {
            biased;
            _ = self.control.cancelled() => return Err(transport_error(TransportErrorKind::Other)),
            result = tokio::time::timeout(self.control.remaining(), fetch) => result.map_err(|_| transport_error(TransportErrorKind::Other))??,
        };
        if let Some(role) = role {
            json::metadata(&bytes, role).map_err(|_| transport_error(TransportErrorKind::Other))?;
        }
        Ok(bytes)
    }
}

impl PolicyTransport {
    fn canonical_url(&self, url: Url) -> Result<Url, TeeError> {
        if url.origin() == self.targets.origin() {
            if let Some(path) = url.path().strip_prefix(self.targets.path()) {
                // tough 0.24 prefixes the complete target path, while the Node/
                // Python publisher prefixes its basename. Keep one repository
                // layout; only normalize this fixed, authenticated target name.
                if let Some(hash) = path.strip_suffix(&format!(".{}/fleet.json", self.network)) {
                    if hex_digest(hash)
                        && url.query().is_none()
                        && url.fragment().is_none()
                        && url.username().is_empty()
                        && url.password().is_none()
                    {
                        return self
                            .targets
                            .join(&format!("{}/{hash}.fleet.json", self.network))
                            .map_err(|_| invalid());
                    }
                    return Err(invalid());
                }
            }
        }
        Ok(url)
    }

    fn limit(&self, url: &Url) -> Result<usize, TeeError> {
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        if url.origin() == self.metadata.origin() {
            if let Some(file) = url.path().strip_prefix(self.metadata.path()) {
                if file == "timestamp.json" {
                    return Ok(16_384);
                }
                let parts: Vec<_> = file.split('.').collect();
                let role = if parts.len() == 3
                    && parts[0].bytes().all(|byte| byte.is_ascii_digit())
                    && !parts[0].starts_with('0')
                {
                    parts[1]
                } else if parts.len() == 2 {
                    parts[0]
                } else {
                    ""
                };
                if parts.last() == Some(&"json") {
                    match role {
                        "root" => return Ok(MAX_ROOT_BYTES),
                        "snapshot" | "targets" => return Ok(MAX_METADATA_BYTES),
                        _ => {}
                    }
                }
            }
        }
        if url.origin() == self.targets.origin() && url.path().starts_with(self.targets.path()) {
            return Ok(MAX_POLICY_BYTES);
        }
        Err(invalid())
    }
}

struct Control {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
    deadline: Instant,
}

impl Control {
    fn check(&self) -> Result<(), TeeError> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(TeeError::PolicyUnavailable)
        } else {
            Ok(())
        }
    }
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct CancelOnDrop(Arc<Control>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }
}

fn create_directory(path: &Path) -> Result<(), TeeError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| TeeError::PolicyStorage)
}

fn acquire_lock(directory: &Path, control: &Control) -> Result<File, TeeError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(directory.join("lock"))
        .map_err(|_| TeeError::PolicyStorage)?;
    loop {
        control.check()?;
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return Err(TeeError::PolicyStorage),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheState {
    schema_version: u8,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    revision: u64,
    sha256: String,
}

fn preflight(config: &Config) -> Result<(), TeeError> {
    let directory = &config.directory;
    if let Some(bytes) = optional_bytes(&directory.join(STATE), 4096)? {
        json::unique_json(&bytes).map_err(|_| TeeError::PolicyStorage)?;
        let expected: CacheState =
            serde_json::from_slice(&bytes).map_err(|_| TeeError::PolicyStorage)?;
        if expected.schema_version != 1
            || !expected.files.contains_key("root.json")
            || inventory(directory)? != expected.files
        {
            return Err(TeeError::PolicyStorage);
        }
    } else {
        let fresh = fs::read_dir(directory)
            .map_err(|_| TeeError::PolicyStorage)?
            .all(|entry| entry.is_ok_and(|entry| entry.file_name() == "lock"));
        if !fresh {
            return Err(TeeError::PolicyStorage);
        }
        atomic_bytes(
            &directory.join("root.json"),
            config.options.root_json.as_bytes(),
        )?;
        seal(directory)?;
    }
    Ok(())
}

fn inventory(directory: &Path) -> Result<BTreeMap<String, String>, TeeError> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory).map_err(|_| TeeError::PolicyStorage)? {
        let entry = entry.map_err(|_| TeeError::PolicyStorage)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| TeeError::PolicyStorage)?;
        if name == "lock" || name == STATE {
            continue;
        }
        if !CACHE_FILES.contains(&name.as_str()) {
            return Err(TeeError::PolicyStorage);
        }
        let bytes = local_bytes(&entry.path(), MAX_METADATA_BYTES)?;
        if name == FLOOR {
            let floor: Floor =
                serde_json::from_slice(&bytes).map_err(|_| TeeError::PolicyStorage)?;
            if floor.revision == 0 || floor.revision > (1 << 53) - 1 || !hex_digest(&floor.sha256) {
                return Err(TeeError::PolicyStorage);
            }
        } else if name == "latest_known_time.json" {
            let time: String =
                serde_json::from_slice(&bytes).map_err(|_| TeeError::PolicyStorage)?;
            time.parse::<jiff::Timestamp>()
                .map_err(|_| TeeError::PolicyStorage)?;
        } else {
            let role = name.strip_suffix(".json").ok_or(TeeError::PolicyStorage)?;
            json::metadata(&bytes, role).map_err(|_| TeeError::PolicyStorage)?;
            match role {
                "root" => {
                    serde_json::from_slice::<Signed<Root>>(&bytes)
                        .map_err(|_| TeeError::PolicyStorage)?;
                }
                "timestamp" => {
                    serde_json::from_slice::<Signed<tough::schema::Timestamp>>(&bytes)
                        .map_err(|_| TeeError::PolicyStorage)?;
                }
                "snapshot" => {
                    serde_json::from_slice::<Signed<tough::schema::Snapshot>>(&bytes)
                        .map_err(|_| TeeError::PolicyStorage)?;
                }
                "targets" => {
                    serde_json::from_slice::<Signed<tough::schema::Targets>>(&bytes)
                        .map_err(|_| TeeError::PolicyStorage)?;
                }
                _ => return Err(TeeError::PolicyStorage),
            }
        }
        files.insert(name, digest(&bytes));
    }
    if !files.contains_key("root.json") {
        return Err(TeeError::PolicyStorage);
    }
    Ok(files)
}

fn seal(directory: &Path) -> Result<(), TeeError> {
    let files = inventory(directory)?;
    // Persist the verifier's writes before the checkpoint that commits their hashes.
    // An interrupted refresh is damage to recover explicitly, never permission to reset floors.
    for name in files.keys() {
        File::open(directory.join(name))
            .and_then(|file| file.sync_all())
            .map_err(|_| TeeError::PolicyStorage)?;
    }
    sync_directory(directory)?;
    atomic_json(
        &directory.join(STATE),
        &CacheState {
            schema_version: 1,
            files,
        },
    )?;
    sync_directory(directory)
}

fn sync_directory(directory: &Path) -> Result<(), TeeError> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| TeeError::PolicyStorage)?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn local_bytes(path: &Path, limit: usize) -> Result<Vec<u8>, TeeError> {
    let file = File::open(path).map_err(|_| TeeError::PolicyStorage)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TeeError::PolicyStorage)?;
    if bytes.len() > limit {
        return Err(TeeError::PolicyStorage);
    }
    Ok(bytes)
}

fn optional_bytes(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, TeeError> {
    match File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| TeeError::PolicyStorage)?;
            if bytes.len() > limit {
                return Err(TeeError::PolicyStorage);
            }
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(TeeError::PolicyStorage),
    }
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), TeeError> {
    atomic_bytes(
        path,
        &serde_json::to_vec(value).map_err(|_| TeeError::PolicyStorage)?,
    )
}

fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), TeeError> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or(TeeError::PolicyStorage)?)
        .map_err(|_| TeeError::PolicyStorage)?;
    file.write_all(bytes).map_err(|_| TeeError::PolicyStorage)?;
    file.as_file()
        .sync_all()
        .map_err(|_| TeeError::PolicyStorage)?;
    file.persist(path).map_err(|_| TeeError::PolicyStorage)?;
    Ok(())
}

fn repository_url(mut url: Url) -> Result<Url, TeeError> {
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain("localhost")) => true,
        _ => false,
    };
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn invalid() -> TeeError {
    TeeError::Policy("invalid TUF source configuration".into())
}
fn transport_error(kind: TransportErrorKind) -> TransportError {
    TransportError::new(kind, "TEE policy repository")
}
