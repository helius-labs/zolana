pub mod process;
pub mod release;

use std::{env, path::PathBuf};

/// Every zolana tool shares this directory and its release cache.
pub fn config_dir() -> PathBuf {
    match (env::var_os("ZOLANA_CONFIG_DIR"), env::var_os("HOME")) {
        (Some(path), _) => PathBuf::from(path),
        (None, Some(home)) => PathBuf::from(home).join(".config").join("zolana"),
        (None, None) => PathBuf::from(".zolana"),
    }
}
