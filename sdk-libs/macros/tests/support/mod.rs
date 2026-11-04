pub fn with_normalized_git_paths(test: impl FnOnce()) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--offline", "--locked", "--format-version", "1"])
        .output()?;
    assert!(
        metadata.status.success(),
        "{}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let previous = std::env::var_os("CARGO_ENCODED_RUSTFLAGS");
    let mut flags = previous
        .as_ref()
        .map(|flags| flags.to_string_lossy().into_owned())
        .unwrap_or_default();
    // trybuild normalizes registry paths but leaves git checkout paths and
    // their source line numbers machine-specific. Give git sources the same
    // diagnostic layout so the existing snapshots work for both sources.
    for package in metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .expect("Cargo metadata packages")
    {
        if !package
            .get("source")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|source| source.starts_with("git+"))
        {
            continue;
        }
        let manifest = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .expect("package manifest");
        let source = std::path::Path::new(manifest)
            .parent()
            .expect("manifest directory");
        let name = package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .expect("package name");
        let version = package
            .get("version")
            .and_then(serde_json::Value::as_str)
            .expect("package version");
        if !flags.is_empty() {
            flags.push('\u{1f}');
        }
        flags.push_str(&format!(
            "--remap-path-prefix={}=/registry/src/index.crates.io-0000000000000000/{name}-{version}",
            source.display()
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
