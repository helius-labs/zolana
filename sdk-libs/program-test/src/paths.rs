use std::path::PathBuf;

pub fn default_program_path() -> PathBuf {
    program_path("SHIELDED_POOL_PROGRAM_PATH", "shielded_pool_program.so")
}

pub fn default_zone_test_program_path() -> PathBuf {
    program_path("ZONE_TEST_PROGRAM_PATH", "zone_test_program.so")
}

fn program_path(env_var: &str, file_name: &str) -> PathBuf {
    if let Ok(path) = std::env::var(env_var) {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join(file_name)
}
