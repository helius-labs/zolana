use std::{env, path::PathBuf};

/// Names the workspace root [`workspace_path`] resolves against. This
/// repository's `.cargo/config.toml` sets it; another workspace sets it in its
/// own `[env]` or environment, or passes explicit paths.
pub const WORKSPACE_DIR_ENV: &str = "SPR_WORKSPACE_DIR";

pub fn default_program_path() -> PathBuf {
    program_path("SHIELDED_POOL_PROGRAM_PATH", "shielded_pool_program.so")
}

pub fn default_ring_test_program_path() -> PathBuf {
    program_path("RING_TEST_PROGRAM_PATH", "ring_test_program.so")
}

fn program_path(env_var: &str, file_name: &str) -> PathBuf {
    if let Ok(path) = env::var(env_var) {
        return PathBuf::from(path);
    }
    workspace_path("target/deploy").join(file_name)
}

/// `relative` under the workspace root `SPR_WORKSPACE_DIR` names, read at run
/// time and else at build time.
///
/// # Panics
///
/// When `SPR_WORKSPACE_DIR` is set neither when the test runs nor when this
/// crate was built.
pub fn workspace_path(relative: &str) -> PathBuf {
    let root = env::var_os(WORKSPACE_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| option_env!("SPR_WORKSPACE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| {
            panic!(
                "{WORKSPACE_DIR_ENV} is not set: set it to the workspace root, or pass explicit paths"
            )
        });
    root.join(relative)
}
