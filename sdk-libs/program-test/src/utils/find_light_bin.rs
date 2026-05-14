use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

const REQUIRED_PROGRAMS: &[&str] = &[
    "light_registry.so",
    "account_compression.so",
    "light_compressed_token.so",
    "spl_noop.so",
    "light_system_program_pinocchio.so",
];

pub fn find_light_bin() -> Option<PathBuf> {
    if let Some(path) = env_dir("LIGHT_PROTOCOL_PROGRAMS_DIR") {
        return Some(path);
    }

    if let Some(path) = env_dir("SBF_OUT_DIR") {
        return Some(path);
    }

    let root = project_root()?;
    [
        root.join("target/deploy"),
        root.join("sdk-libs/cli/bin"),
        root.join("cli/bin"),
    ]
    .into_iter()
    .find(|path| has_required_programs(path.as_path()))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    let value = env::var(name).ok()?;
    let path = PathBuf::from(value);
    has_required_programs(&path).then_some(path)
}

fn has_required_programs(path: &Path) -> bool {
    path.is_dir()
        && REQUIRED_PROGRAMS
            .iter()
            .all(|program| path.join(program).is_file())
}

fn project_root() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_light_bin() {
        let bin_path = find_light_bin();
        println!("find_light_bin() returned: {:?}", bin_path);

        if let Some(path) = &bin_path {
            assert!(path.exists(), "bin directory should exist");
            assert!(
                REQUIRED_PROGRAMS
                    .iter()
                    .all(|program| path.join(program).is_file()),
                "all Light program artifacts should exist in {:?}",
                path
            );
        }
    }
}
