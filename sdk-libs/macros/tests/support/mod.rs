pub fn with_normalized_git_paths(test: impl FnOnce()) -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let dependencies = executable.parent().expect("test binary directory");
    let mut sources = std::collections::BTreeSet::new();
    // Use dependency files from this build. Workspace-wide cargo metadata
    // would need manifests for unrelated packages on a clean CI runner.
    for entry in std::fs::read_dir(dependencies)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        let Some((name, _)) = filename.split_once('-') else {
            continue;
        };
        if !filename.ends_with(".d") || !(name.starts_with("spr_zk_") || name == "groth16_solana") {
            continue;
        }
        for line in std::fs::read_to_string(entry.path())?.lines() {
            if let Some(source) = line.strip_suffix("/src/lib.rs:") {
                if source.contains("/git/checkouts/") {
                    sources.insert((name.replace('_', "-"), source.replace("\\ ", " ")));
                }
            }
        }
    }
    let previous = std::env::var_os("CARGO_ENCODED_RUSTFLAGS");
    let mut flags = previous
        .as_ref()
        .map(|flags| flags.to_string_lossy().into_owned())
        .unwrap_or_default();
    // trybuild normalizes registry paths and their source line numbers.
    // Remap git sources into a synthetic registry layout for the same handling.
    for (name, source) in sources {
        if !flags.is_empty() {
            flags.push('\u{1f}');
        }
        flags.push_str(&format!(
            "--remap-path-prefix={source}=/registry/src/index.crates.io-0000000000000000/{name}-0.0.0"
        ));
    }
    flags.push_str("\u{1f}--cfg\u{1f}trybuild\u{1f}--verbose\u{1f}-A\u{1f}dead_code");
    std::env::set_var("CARGO_ENCODED_RUSTFLAGS", flags);
    test();
    match previous {
        Some(flags) => std::env::set_var("CARGO_ENCODED_RUSTFLAGS", flags),
        None => std::env::remove_var("CARGO_ENCODED_RUSTFLAGS"),
    }
    Ok(())
}
