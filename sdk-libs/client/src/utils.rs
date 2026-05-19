use std::{env, path::PathBuf, process::Command};

pub fn find_light_bin() -> Option<PathBuf> {
    if let Some(path) = env_dir("LIGHT_PROTOCOL_PROGRAMS_DIR") {
        return Some(path);
    }

    if let Some(path) = env_dir("SBF_OUT_DIR") {
        return Some(path);
    }

    let root = project_root()?;
    [root.join("target/deploy")]
        .into_iter()
        .find(|path| path.join("account_compression.so").is_file())
}

fn env_dir(name: &str) -> Option<PathBuf> {
    let value = env::var(name).ok()?;
    let path = PathBuf::from(value);
    path.join("account_compression.so").is_file().then_some(path)
}

fn project_root() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    output.status.success().then(|| {
        PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string())
    })
}
