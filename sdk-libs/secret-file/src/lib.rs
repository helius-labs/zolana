//! Key files are created once and never overwritten. A read refuses a link,
//! a special file, and with [`Access::OwnerOnly`] a file anyone else can open.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;
use zeroize::Zeroizing;

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
    #[error("access to {path} cannot be verified on this platform")]
    AccessCheckUnavailable { path: PathBuf },
    #[error("key text is not 64 lowercase hex characters")]
    Hex,
}

impl Visibility {
    #[cfg_attr(not(unix), allow(dead_code))]
    const fn mode(self) -> u32 {
        match self {
            Self::Secret => 0o600,
            Self::Public => 0o644,
        }
    }
}

/// Creates the parent directories. A failed write leaves no file behind.
pub fn create_new(
    path: &Path,
    bytes: &[u8],
    visibility: Visibility,
) -> Result<(), SecretFileError> {
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
    no_follow(&mut options);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, visibility.mode());
    let mut file = options.open(path).map_err(failed)?;
    if let Err(source) = persist(&mut file, bytes, visibility) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(failed(source));
    }
    Ok(())
}

/// Neither file remains when either cannot be written.
pub fn create_pair(secret: (&Path, &[u8]), public: (&Path, &[u8])) -> Result<(), SecretFileError> {
    create_new(secret.0, secret.1, Visibility::Secret)?;
    create_new(public.0, public.1, Visibility::Public).inspect_err(|_| {
        let _ = fs::remove_file(secret.0);
    })
}

pub fn read_private(
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
    no_follow(&mut options);
    let file = options.open(path).map_err(failed)?;
    let metadata = file.metadata().map_err(failed)?;
    if !metadata.is_file() {
        return Err(SecretFileError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    check_access(path, &metadata, access)?;
    let mut text = Zeroizing::new(String::new());
    file.take(max_len.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(failed)?;
    if text.len() as u64 > max_len {
        return Err(SecretFileError::TooLong {
            path: path.to_path_buf(),
            max: max_len,
        });
    }
    Ok(text)
}

pub fn read_hex32(text: &str) -> Result<Zeroizing<[u8; 32]>, SecretFileError> {
    if text.len() != 64
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
    // The umask must not loosen or tighten the mode.
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(
        visibility.mode(),
    ))?;
    #[cfg(not(unix))]
    let _ = visibility;
    file.write_all(bytes)?;
    file.sync_all()
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

#[cfg(unix)]
fn no_follow(options: &mut OpenOptions) {
    std::os::unix::fs::OpenOptionsExt::custom_flags(options, libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn no_follow(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests;
