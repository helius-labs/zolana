//! Key files are never overwritten, and a read takes only a regular file, owner-only unless [`Access::Shared`].

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    mem,
    path::{Path, PathBuf},
};

use thiserror::Error;
use zeroize::Zeroizing;

const KEY_HEX_LEN: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    OwnerOnly,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Secret,
    Public,
}

#[derive(Debug, Error)]
pub enum SecretFileError {
    #[error("cannot read {path}")]
    Read { path: PathBuf, source: io::Error },
    #[error("cannot write {path}")]
    Write { path: PathBuf, source: io::Error },
    #[error("{path} is not a regular file")]
    NotRegular { path: PathBuf },
    #[error("{path} is owned by another user")]
    ForeignOwner { path: PathBuf },
    #[error("{path} has shared mode {mode:o}")]
    Shared { path: PathBuf, mode: u32 },
    #[error("{path} is longer than {max} bytes")]
    TooLong { path: PathBuf, max: u64 },
    #[error("owner-only access to {path} needs unix")]
    AccessCheckUnavailable { path: PathBuf },
    #[error("key text is not 64 lowercase hex characters")]
    Hex,
}

/// Neither new file remains when either cannot be written.
#[must_use]
pub struct KeyPairFiles<'a> {
    pub secret_path: &'a Path,
    pub secret: &'a [u8],
    pub public_path: &'a Path,
    pub public: &'a [u8],
}

impl Visibility {
    #[cfg(unix)]
    const fn mode(self) -> u32 {
        match self {
            Self::Secret => 0o600,
            Self::Public => 0o644,
        }
    }
}

impl KeyPairFiles<'_> {
    pub fn create(self) -> Result<(), SecretFileError> {
        create_new(self.secret_path, self.secret, Visibility::Secret)?;
        create_new(self.public_path, self.public, Visibility::Public).inspect_err(|_| {
            let _ = fs::remove_file(self.secret_path);
        })
    }
}

/// Creates missing parents, a failed write leaves no file behind.
pub fn create_new(
    path: &Path,
    bytes: &[u8],
    visibility: Visibility,
) -> Result<(), SecretFileError> {
    #[cfg(not(unix))]
    if visibility == Visibility::Secret {
        return Err(SecretFileError::AccessCheckUnavailable {
            path: path.to_path_buf(),
        });
    }
    let failed = |source| SecretFileError::Write {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(failed)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags(libc::O_NOFOLLOW)
            .mode(visibility.mode());
    }
    let mut file = options.open(path).map_err(failed)?;
    if let Err(source) = persist(&mut file, bytes, visibility) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(failed(source));
    }
    Ok(())
}

/// Lowercase hex of a 32-byte key.
pub fn read_key32(path: &Path, access: Access) -> Result<Zeroizing<[u8; 32]>, SecretFileError> {
    decode_key32(&read_private(path, access, KEY_HEX_LEN)?)
}

fn read_private(
    path: &Path,
    access: Access,
    max_len: u64,
) -> Result<Zeroizing<String>, SecretFileError> {
    let failed = |source| SecretFileError::Read {
        path: path.to_path_buf(),
        source,
    };
    let mut options = OpenOptions::new();
    options.read(true);
    // A FIFO opens at once and fails the type check.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    let mut file = options.open(path).map_err(failed)?;
    let metadata = file.metadata().map_err(failed)?;
    if !metadata.is_file() {
        return Err(SecretFileError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    check_access(path, &metadata, access)?;
    let mut bytes = read_up_to(&mut file, max_len.saturating_add(1)).map_err(failed)?;
    if bytes.len() as u64 > max_len {
        return Err(SecretFileError::TooLong {
            path: path.to_path_buf(),
            max: max_len,
        });
    }
    String::from_utf8(mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|error| {
            let source = io::Error::new(io::ErrorKind::InvalidData, error.utf8_error());
            drop(Zeroizing::new(error.into_bytes()));
            failed(source)
        })
}

fn decode_key32(text: &str) -> Result<Zeroizing<[u8; 32]>, SecretFileError> {
    if text.len() as u64 != KEY_HEX_LEN
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(SecretFileError::Hex);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(text, bytes.as_mut_slice()).map_err(|_| SecretFileError::Hex)?;
    Ok(bytes)
}

fn persist(file: &mut File, bytes: &[u8], visibility: Visibility) -> io::Result<()> {
    // The umask must not tighten the mode.
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(
        visibility.mode(),
    ))?;
    #[cfg(not(unix))]
    let _ = visibility;
    file.write_all(bytes)?;
    file.sync_all()
}

/// One fixed buffer, a reallocation would free an unwiped copy.
fn read_up_to(file: &mut File, limit: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(limit)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    bytes.resize(limit, 0);
    let mut filled = 0;
    while filled < limit {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

#[cfg(unix)]
fn check_access(path: &Path, metadata: &Metadata, access: Access) -> Result<(), SecretFileError> {
    use std::os::unix::fs::MetadataExt;
    if access == Access::Shared {
        return Ok(());
    }
    // SAFETY: geteuid has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(SecretFileError::ForeignOwner {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretFileError::Shared {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_access(path: &Path, _metadata: &Metadata, access: Access) -> Result<(), SecretFileError> {
    match access {
        Access::Shared => Ok(()),
        Access::OwnerOnly => Err(SecretFileError::AccessCheckUnavailable {
            path: path.to_path_buf(),
        }),
    }
}

#[cfg(test)]
mod tests;
