use std::path::PathBuf;

pub fn default_program_path() -> PathBuf {
    program_path("SHIELDED_POOL_PROGRAM_PATH", "shielded_pool_program.so")
}

pub fn default_ring_test_program_path() -> PathBuf {
    program_path("RING_TEST_PROGRAM_PATH", "ring_test_program.so")
}

fn program_path(env_var: &str, file_name: &str) -> PathBuf {
    if let Ok(path) = std::env::var(env_var) {
        return PathBuf::from(path);
    }
    workspace_path("target/deploy").join(file_name)
}

/// `relative` under the workspace this crate is built in.
pub fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}
