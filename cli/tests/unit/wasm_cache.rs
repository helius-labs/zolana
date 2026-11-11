use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "zolana-wasm-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        path
    }

    /// A package directory holding a wasm module and `marker`.
    fn package(&self, name: &str, marker: &[u8]) -> PathBuf {
        let directory = self.0.join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("program_bg.wasm"), "module").unwrap();
        fs::write(directory.join(super::super::PACKAGE_MARKER), marker).unwrap();
        directory
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A package built from `source` under the settings digest `settings`.
fn recorded(scratch: &Scratch, settings: &str, source: &Path) -> PathBuf {
    let sources = BTreeMap::from([(source.to_path_buf(), sha256(&fs::read(source).unwrap()))]);
    scratch.package(
        "pkg",
        &Fingerprint::new(settings.into(), sources).marker().unwrap(),
    )
}

/// A build start after every file a test wrote.
fn later() -> SystemTime {
    SystemTime::now() + std::time::Duration::from_secs(60)
}

#[test]
fn a_package_with_matching_settings_and_sources_is_reused() {
    let scratch = Scratch::new();
    let source = scratch.write("src/lib.rs", "fn main() {}");
    let package = recorded(&scratch, "settings", &source);
    assert!(up_to_date(&package, "settings"));
}

#[test]
fn a_changed_input_rebuilds_the_package() {
    let scratch = Scratch::new();
    let source = scratch.write("src/lib.rs", "fn main() {}");
    let package = recorded(&scratch, "settings", &source);
    assert!(!up_to_date(&package, "other settings"), "changed settings");

    fs::write(&source, "fn main() { changed() }").unwrap();
    assert!(!up_to_date(&package, "settings"), "changed source");

    fs::remove_file(&source).unwrap();
    assert!(!up_to_date(&package, "settings"), "removed source");
}

#[test]
fn a_package_without_its_module_is_rebuilt() {
    let scratch = Scratch::new();
    let source = scratch.write("src/lib.rs", "fn main() {}");
    let package = recorded(&scratch, "settings", &source);
    fs::remove_file(package.join("program_bg.wasm")).unwrap();
    assert!(!up_to_date(&package, "settings"));
}

#[test]
fn a_missing_older_or_sourceless_marker_rebuilds_the_package() {
    let scratch = Scratch::new();
    assert!(
        !up_to_date(&scratch.0.join("missing"), "settings"),
        "missing"
    );
    let older = scratch.package(
        "older",
        b"Written by `zolana zk compile`, which replaces this directory on every build.\n",
    );
    assert!(!up_to_date(&older, "settings"), "older CLI");
    let sourceless = scratch.package(
        "sourceless",
        &Fingerprint::new("settings".into(), BTreeMap::new())
            .marker()
            .unwrap(),
    );
    assert!(!up_to_date(&sourceless, "settings"), "no recorded sources");
}

#[test]
fn dep_info_sources_are_hashed_except_under_the_cargo_home() {
    let scratch = Scratch::new();
    let spaced = scratch.write("my crate/src/lib.rs", "pub fn a() {}");
    let plain = scratch.write("other/build.rs", "fn main() {}");
    let home = scratch.0.join("cargo-home");
    let registry = scratch.write("cargo-home/registry/src/dep/lib.rs", "pub fn dep() {}");
    let escape = |path: &Path| path.display().to_string().replace(' ', "\\ ");
    let dep_info = scratch.write(
        "out.d",
        &format!(
            "{}: {} {} {}\n\n{}:\n",
            escape(&scratch.0.join("out.wasm")),
            escape(&spaced),
            escape(&plain),
            escape(&registry),
            escape(&spaced),
        ),
    );
    assert_eq!(
        sources(&dep_info, &home, later()).unwrap(),
        BTreeMap::from([
            (spaced.clone(), sha256(b"pub fn a() {}")),
            (plain.clone(), sha256(b"fn main() {}")),
        ])
    );
}

#[test]
fn a_source_changed_during_or_just_before_the_build_records_nothing() {
    // The build may have read the earlier content of a file modified after it
    // started, and a coarse file timestamp can round that time down to just
    // before the start.
    let scratch = Scratch::new();
    let source = scratch.write("src/lib.rs", "pub fn a() {}");
    let dep_info = scratch.write("out.d", &format!("out.wasm: {}\n", source.display()));
    let home = scratch.0.join("cargo-home");
    for started in [
        SystemTime::UNIX_EPOCH,
        SystemTime::now(),
        SystemTime::now() + std::time::Duration::from_secs(1),
    ] {
        assert!(
            sources(&dep_info, &home, started).unwrap().is_empty(),
            "{started:?}"
        );
    }
}

#[test]
fn a_dep_info_path_that_is_not_a_file_records_nothing() {
    let scratch = Scratch::new();
    let source = scratch.write("src/lib.rs", "pub fn a() {}");
    let dep_info = scratch.write(
        "out.d",
        &format!(
            "out.wasm: {} {}\n",
            source.display(),
            scratch.0.join("missing.txt").display()
        ),
    );
    let home = scratch.0.join("cargo-home");
    assert!(sources(&dep_info, &home, later()).unwrap().is_empty());
}

#[test]
fn the_build_environment_keeps_cargo_and_rustc_settings_only() {
    let variables = [
        ("RUSTFLAGS", "-C target-feature=+simd128"),
        ("CARGO_PROFILE_RELEASE_PANIC", "abort"),
        ("CARGO_BUILD_TARGET_DIR", "out"),
        ("CARGO_TARGET_DIR", "out"),
        ("CARGO_PKG_VERSION", "1.0.0"),
        ("HOME", "/home/user"),
    ]
    .map(|(name, value)| (name.into(), value.into()));
    assert_eq!(
        build_environment(variables.into_iter())
            .into_keys()
            .collect::<Vec<_>>(),
        [
            "CARGO_BUILD_TARGET_DIR",
            "CARGO_PROFILE_RELEASE_PANIC",
            "CARGO_TARGET_DIR",
            "RUSTFLAGS",
        ]
    );
}

#[test]
fn cargo_configuration_covers_the_manifests_and_every_applying_config() {
    let scratch = Scratch::new();
    let root = scratch.write("ws/Cargo.toml", "[workspace]");
    let manifest = scratch.write("ws/app/Cargo.toml", "[package]");
    let crate_config = scratch.write("ws/app/.cargo/config.toml", "[build]");
    let root_config = scratch.write("ws/.cargo/config", "[build]");
    let home_config = scratch.write("home/config.toml", "[build]");
    scratch.write("ws/other/.cargo/config.toml", "[build]");
    let files = cargo_configuration(
        &scratch.0.join("ws/app"),
        &scratch.0.join("ws"),
        Some(scratch.0.join("home")),
    );
    for file in [&root, &manifest, &crate_config, &root_config, &home_config] {
        assert!(files.contains(file), "{} in {files:?}", file.display());
    }
    assert!(!files
        .iter()
        .any(|file| file.starts_with(scratch.0.join("ws/other"))));
}
