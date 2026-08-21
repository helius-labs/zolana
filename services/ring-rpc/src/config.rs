use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use rand::RngCore;
use solana_address::Address;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};

#[derive(Debug, Parser)]
#[command(
    name = "ring-rpc",
    about = "Ring RPC for a custom ring with an auditor"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve(ServeArgs),
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long, env = "RING_RPC_BIND", default_value = "127.0.0.1")]
    pub bind: IpAddr,
    #[arg(long, env = "RING_RPC_PORT", default_value_t = 8785)]
    pub port: u16,
    #[arg(
        long,
        env = "RING_RPC_INDEXER_URL",
        default_value = "http://127.0.0.1:8784"
    )]
    pub indexer_url: String,
    #[arg(
        long,
        env = "RING_RPC_SOLANA_RPC_URL",
        default_value = "http://127.0.0.1:8899"
    )]
    pub rpc_url: String,
    /// Lowercase hex P256 scalar.
    #[arg(
        long,
        env = "RING_RPC_AUDITOR_KEY_FILE",
        conflicts_with = "root_secret_file",
        required_unless_present = "root_secret_file"
    )]
    pub auditor_key_file: Option<PathBuf>,
    #[arg(long, env = "RING_RPC_RING_PROGRAM_ID", requires = "auditor_key_file")]
    pub ring_program_id: Option<Address>,
    /// Lowercase hex root secret.
    #[arg(long, env = "RING_RPC_ROOT_SECRET_FILE")]
    pub root_secret_file: Option<PathBuf>,
    #[arg(
        long = "allow-origin",
        env = "RING_RPC_ALLOW_ORIGINS",
        value_delimiter = ','
    )]
    pub allow_origins: Vec<String>,
    #[arg(long, env = "RING_RPC_WEBAUTHN_RP_ID")]
    pub webauthn_rp_id: Option<String>,
    #[arg(long, env = "RING_RPC_MAX_CONNECTIONS", default_value = "256")]
    pub max_connections: NonZeroU32,
    #[arg(long, env = "RING_RPC_REQUEST_TIMEOUT_SECS", default_value = "30")]
    pub request_timeout_secs: NonZeroU64,
    #[arg(long, env = "RING_RPC_UPSTREAM_TIMEOUT_SECS", default_value = "10")]
    pub upstream_timeout_secs: NonZeroU64,
    #[arg(long, env = "RING_RPC_ALLOW_SHARED_KEY_FILE")]
    pub allow_shared_key_file: bool,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, value_enum, default_value_t = KeyKind::Auditor)]
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KeyKind {
    Auditor,
    Root,
}

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error("cannot read key file {path} because {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write key file {path} because {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("key file {path} has shared mode {mode}")]
    Shared { path: PathBuf, mode: FileMode },
    #[error("key file is not 64 hex characters")]
    Encoding,
    #[error("public key file is not 66 hex characters")]
    PubkeyEncoding,
    #[error("key path must name a file")]
    InvalidPath,
    #[error("key path is not a regular file")]
    NotRegular { path: PathBuf },
    #[error("key file is owned by another user")]
    ForeignOwner { path: PathBuf },
    #[error("key file access cannot be verified on the current platform")]
    AccessCheckUnavailable,
    #[error("auditor key is not a valid P256 secret key because {0}")]
    Key(#[from] KeypairError),
    #[error(transparent)]
    Root(#[from] RootSecretError),
}

#[must_use]
pub struct KeyFile<'a> {
    pub path: &'a Path,
    pub access: KeyAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAccess {
    OwnerOnly,
    Shared,
}

pub struct RootSecret(Zeroizing<[u8; 32]>);

#[derive(Debug, Error)]
pub enum RootSecretError {
    #[error("root secret cannot be zero")]
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMode(u32);

impl ServeArgs {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.get())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_secs.get())
    }
}

impl RootSecret {
    pub fn random() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            if let Ok(root) = Self::from_bytes(bytes) {
                return root;
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RootSecretError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RootSecretError::Zero);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl KeyFile<'_> {
    pub fn auditor_key(self) -> Result<ViewingKey, KeyFileError> {
        parse_auditor_key(&self.text()?)
    }

    pub fn root_secret(self) -> Result<RootSecret, KeyFileError> {
        Ok(RootSecret::from_bytes(*parse_hex32(&self.text()?)?)?)
    }

    fn text(self) -> Result<Zeroizing<String>, KeyFileError> {
        let mut options = OpenOptions::new();
        options.read(true);
        no_follow(&mut options);
        let mut file = options
            .open(self.path)
            .map_err(|source| KeyFileError::Read {
                path: self.path.to_path_buf(),
                source,
            })?;
        FileCheck {
            file: &file,
            path: self.path,
            access: self.access,
        }
        .run()?;
        let mut text = Zeroizing::new(String::new());
        Read::by_ref(&mut file)
            .take(MAX_KEY_TEXT_LEN + 1)
            .read_to_string(&mut text)
            .map_err(|source| KeyFileError::Read {
                path: self.path.to_path_buf(),
                source,
            })?;
        if text.len() as u64 > MAX_KEY_TEXT_LEN {
            return Err(KeyFileError::Encoding);
        }
        Ok(text)
    }
}

impl fmt::Display for FileMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:o}", self.0)
    }
}

pub fn write_auditor_key(out: &Path) -> Result<ViewingKey, KeyFileError> {
    create_parent(out)?;
    let public_path = public_key_path(out)?;
    let key = ViewingKey::new();
    let secret_hex = Zeroizing::new(hex::encode(*key.secret_bytes()));
    let public_hex = hex::encode(key.pubkey().as_bytes());
    let mut secret_file = NewFile {
        path: out,
        visibility: FileVisibility::Secret,
    }
    .open()?;
    let mut public_file = match (NewFile {
        path: &public_path,
        visibility: FileVisibility::Public,
    })
    .open()
    {
        Ok(file) => file,
        Err(error) => {
            drop(secret_file);
            remove_created(out)?;
            return Err(error);
        }
    };
    let result = FileWrite {
        file: &mut secret_file,
        path: out,
        bytes: secret_hex.as_bytes(),
    }
    .persist()
    .and_then(|()| {
        FileWrite {
            file: &mut public_file,
            path: &public_path,
            bytes: public_hex.as_bytes(),
        }
        .persist()
    });
    if let Err(error) = result {
        drop(secret_file);
        drop(public_file);
        remove_created(out)?;
        remove_created(&public_path)?;
        return Err(error);
    }
    Ok(key)
}

pub fn write_root_secret(out: &Path) -> Result<(), KeyFileError> {
    create_parent(out)?;
    let root = RootSecret::random();
    let root_hex = Zeroizing::new(hex::encode(root.as_bytes()));
    let mut file = NewFile {
        path: out,
        visibility: FileVisibility::Secret,
    }
    .open()?;
    FileWrite {
        file: &mut file,
        path: out,
        bytes: root_hex.as_bytes(),
    }
    .persist()
}

pub fn write_auditor_pubkey(path: &Path, pubkey: &P256Pubkey) -> Result<(), KeyFileError> {
    create_parent(path)?;
    let mut file = NewFile {
        path,
        visibility: FileVisibility::Public,
    }
    .open()?;
    FileWrite {
        file: &mut file,
        path,
        bytes: hex::encode(pubkey.as_bytes()).as_bytes(),
    }
    .persist()
}

pub fn read_auditor_pubkey(path: &Path) -> Result<P256Pubkey, KeyFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| KeyFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let text = text.trim();
    if text.len() != PUBKEY_HEX_LEN {
        return Err(KeyFileError::PubkeyEncoding);
    }
    let bytes: [u8; 33] = hex::decode(text)
        .map_err(|_| KeyFileError::PubkeyEncoding)?
        .try_into()
        .map_err(|_| KeyFileError::PubkeyEncoding)?;
    Ok(P256Pubkey::from_bytes(bytes)?)
}

pub fn public_key_path(secret: &Path) -> Result<PathBuf, KeyFileError> {
    let mut name = secret
        .file_name()
        .ok_or(KeyFileError::InvalidPath)?
        .to_os_string();
    name.push(".pub");
    Ok(secret.with_file_name(name))
}

const MAX_KEY_TEXT_LEN: u64 = 64;
const PUBKEY_HEX_LEN: usize = 66;

struct FileCheck<'a> {
    file: &'a File,
    path: &'a Path,
    access: KeyAccess,
}

impl FileCheck<'_> {
    fn run(self) -> Result<(), KeyFileError> {
        let metadata = self.file.metadata().map_err(|source| KeyFileError::Read {
            path: self.path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(KeyFileError::NotRegular {
                path: self.path.to_path_buf(),
            });
        }
        PrivateFileCheck {
            metadata: &metadata,
            path: self.path,
            access: self.access,
        }
        .run()
    }
}

struct PrivateFileCheck<'a> {
    metadata: &'a std::fs::Metadata,
    path: &'a Path,
    access: KeyAccess,
}

#[cfg(unix)]
impl PrivateFileCheck<'_> {
    fn run(self) -> Result<(), KeyFileError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY geteuid has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        if self.access == KeyAccess::OwnerOnly && self.metadata.uid() != effective_uid {
            return Err(KeyFileError::ForeignOwner {
                path: self.path.to_path_buf(),
            });
        }
        let mode = self.metadata.permissions().mode() & 0o777;
        if self.access == KeyAccess::OwnerOnly && mode & 0o077 != 0 {
            return Err(KeyFileError::Shared {
                path: self.path.to_path_buf(),
                mode: FileMode(mode),
            });
        }
        Ok(())
    }
}

#[cfg(not(unix))]
impl PrivateFileCheck<'_> {
    fn run(self) -> Result<(), KeyFileError> {
        match self.access {
            KeyAccess::Shared => Ok(()),
            KeyAccess::OwnerOnly => Err(KeyFileError::AccessCheckUnavailable),
        }
    }
}

enum FileVisibility {
    Secret,
    Public,
}

struct NewFile<'a> {
    path: &'a Path,
    visibility: FileVisibility,
}

impl NewFile<'_> {
    fn open(self) -> Result<File, KeyFileError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        no_follow(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mode = match self.visibility {
                FileVisibility::Secret => 0o600,
                FileVisibility::Public => 0o644,
            };
            options.mode(mode);
        }
        options
            .open(self.path)
            .map_err(|source| KeyFileError::Write {
                path: self.path.to_path_buf(),
                source,
            })
    }
}

struct FileWrite<'a> {
    file: &'a mut File,
    path: &'a Path,
    bytes: &'a [u8],
}

impl FileWrite<'_> {
    fn persist(self) -> Result<(), KeyFileError> {
        self.file
            .write_all(self.bytes)
            .and_then(|()| self.file.sync_all())
            .map_err(|source| KeyFileError::Write {
                path: self.path.to_path_buf(),
                source,
            })
    }
}

fn create_parent(path: &Path) -> Result<(), KeyFileError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|source| KeyFileError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn remove_created(path: &Path) -> Result<(), KeyFileError> {
    std::fs::remove_file(path).map_err(|source| KeyFileError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn no_follow(_options: &mut OpenOptions) {}

fn parse_auditor_key(text: &str) -> Result<ViewingKey, KeyFileError> {
    let secret = parse_hex32(text)?;
    Ok(ViewingKey::from_bytes(&secret)?)
}

fn parse_hex32(text: &str) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
    if text.len() != MAX_KEY_TEXT_LEN as usize
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(KeyFileError::Encoding);
    }
    let decoded = Zeroizing::new(hex::decode(text).map_err(|_| KeyFileError::Encoding)?);
    let mut secret = Zeroizing::new([0u8; 32]);
    if decoded.len() != secret.len() {
        return Err(KeyFileError::Encoding);
    }
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn short_and_non_hex_inputs_are_rejected() {
        assert!(matches!(
            parse_auditor_key("abcd"),
            Err(KeyFileError::Encoding)
        ));
        assert!(matches!(
            parse_auditor_key(&"zz".repeat(32)),
            Err(KeyFileError::Encoding)
        ));
        assert!(matches!(
            parse_auditor_key(&"AA".repeat(32)),
            Err(KeyFileError::Encoding)
        ));
    }

    #[test]
    fn keygen_writes_a_secret_the_loader_reads_and_a_matching_public_key() {
        let dir = temp_dir("keygen");
        let secret = dir.join("auditor.key");
        let key = write_auditor_key(&secret).expect("keygen");
        assert_eq!(
            KeyFile {
                path: &secret,
                access: KeyAccess::OwnerOnly,
            }
            .auditor_key()
            .expect("load")
            .pubkey(),
            key.pubkey()
        );
        let public_path = public_key_path(&secret).expect("public path");
        assert_eq!(
            std::fs::read_to_string(&public_path).expect("pub file"),
            hex::encode(key.pubkey().as_bytes())
        );
        assert_eq!(
            read_auditor_pubkey(&public_path).expect("pubkey"),
            key.pubkey()
        );
        assert!(matches!(
            write_auditor_key(&secret),
            Err(KeyFileError::Write { .. })
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn public_key_files_round_trip_and_reject_other_lengths() {
        let dir = temp_dir("pubkey");
        let path = dir.join("nested").join("auditor.key.pub");
        let key = ViewingKey::new();
        write_auditor_pubkey(&path, &key.pubkey()).expect("write");
        assert_eq!(read_auditor_pubkey(&path).expect("read"), key.pubkey());
        assert!(matches!(
            write_auditor_pubkey(&path, &key.pubkey()),
            Err(KeyFileError::Write { .. })
        ));
        let short = dir.join("short.pub");
        std::fs::write(&short, "02ab").expect("short");
        assert!(matches!(
            read_auditor_pubkey(&short),
            Err(KeyFileError::PubkeyEncoding)
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_shared_key_file_is_refused_unless_allowed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("shared");
        let secret = dir.join("auditor.key");
        write_auditor_key(&secret).expect("keygen");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            KeyFile {
                path: &secret,
                access: KeyAccess::OwnerOnly,
            }
            .auditor_key(),
            Err(KeyFileError::Shared {
                mode: FileMode(0o644),
                ..
            })
        ));
        assert!(KeyFile {
            path: &secret,
            access: KeyAccess::Shared,
        }
        .auditor_key()
        .is_ok());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn zero_scalar_is_rejected() {
        assert!(matches!(
            parse_auditor_key(&"00".repeat(32)),
            Err(KeyFileError::Key(_))
        ));
    }

    #[test]
    fn root_keygen_writes_a_nonzero_private_secret() {
        let dir = temp_dir("root-keygen");
        let secret = dir.join("nested/root.key");
        write_root_secret(&secret).expect("keygen");
        let root = KeyFile {
            path: &secret,
            access: KeyAccess::OwnerOnly,
        }
        .root_secret()
        .expect("root");
        assert!(root.as_bytes().iter().any(|byte| *byte != 0));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&secret)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn oversized_key_files_are_rejected() {
        let dir = temp_dir("oversized");
        let secret = dir.join("root.key");
        std::fs::write(&secret, "a".repeat(65)).expect("write");
        assert!(matches!(
            KeyFile {
                path: &secret,
                access: KeyAccess::Shared,
            }
            .root_secret(),
            Err(KeyFileError::Encoding)
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink");
        let target = dir.join("target.key");
        let link = dir.join("link.key");
        write_root_secret(&target).expect("keygen");
        symlink(&target, &link).expect("symlink");
        assert!(matches!(
            KeyFile {
                path: &link,
                access: KeyAccess::OwnerOnly,
            }
            .root_secret(),
            Err(KeyFileError::Read { .. })
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn public_key_symlinks_leave_no_secret() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("public-symlink");
        let secret = dir.join("auditor.key");
        let public = public_key_path(&secret).expect("public path");
        let target = dir.join("target");
        std::fs::write(&target, "unchanged").expect("target");
        symlink(&target, &public).expect("symlink");
        assert!(matches!(
            write_auditor_key(&secret),
            Err(KeyFileError::Write { .. })
        ));
        assert!(!secret.exists());
        assert_eq!(
            std::fs::read_to_string(target).expect("target"),
            "unchanged"
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
