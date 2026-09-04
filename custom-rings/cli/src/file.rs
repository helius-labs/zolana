//! One place the cli touches a path and reports the failure.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::de::DeserializeOwned;
use solana_keypair::Keypair;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileError {
    #[error("cannot read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot write {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot parse {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("cannot read keypair {path}, {message}")]
    Keypair { path: PathBuf, message: String },
    #[error("cannot write keypair {path}, {message}")]
    KeypairWrite { path: PathBuf, message: String },
}

pub fn read(path: &Path) -> Result<String, FileError> {
    fs::read_to_string(path).map_err(|source| FileError::Read {
        path: path.to_path_buf(),
        source,
    })
}

pub fn write(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), FileError> {
    fs::write(path, contents).map_err(|source| FileError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
pub fn make_executable(path: &Path) -> Result<(), FileError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| {
        FileError::Write {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
pub fn make_executable(_path: &Path) -> Result<(), FileError> {
    Ok(())
}

pub fn create_dir_all(path: &Path) -> Result<(), FileError> {
    fs::create_dir_all(path).map_err(|source| FileError::Write {
        path: path.to_path_buf(),
        source,
    })
}

pub fn parse_toml<T: DeserializeOwned>(path: &Path) -> Result<T, FileError> {
    toml::from_str(&read(path)?).map_err(|source| FileError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

pub fn read_keypair(path: &Path) -> Result<Keypair, FileError> {
    solana_keypair::read_keypair_file(path).map_err(|error| FileError::Keypair {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

pub fn read_or_create_keypair(path: &Path) -> Result<Keypair, FileError> {
    if path.is_file() {
        read_keypair(path)
    } else {
        let keypair = Keypair::new();
        write_keypair(&keypair, path)?;
        Ok(keypair)
    }
}

pub fn write_keypair(keypair: &Keypair, path: &Path) -> Result<(), FileError> {
    solana_keypair::write_keypair_file(keypair, path).map_err(|error| FileError::KeypairWrite {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    restrict_mode(path)
}

#[cfg(unix)]
fn restrict_mode(path: &Path) -> Result<(), FileError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        FileError::Write {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_mode(_path: &Path) -> Result<(), FileError> {
    Ok(())
}
