use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "zolana-wasm-out-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    /// A finished package in a staging directory beside the output.
    fn staging(&self) -> PathBuf {
        let staging = self.0.join(".pkg.building");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join(PACKAGE_MARKER), "").unwrap();
        fs::write(staging.join("new.js"), "new package").unwrap();
        staging
    }

    fn output(&self) -> PathBuf {
        self.0.join("pkg")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A `--wasm-out` directory the user chose.
fn chosen(directory: &Path) -> WasmOutput {
    WasmOutput {
        directory: directory.to_path_buf(),
        cli_owned: false,
    }
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_missing_empty_or_marked_output_is_replaced() {
    for existing in [None, Some(Vec::new()), Some(vec![PACKAGE_MARKER, "old.js"])] {
        let scratch = Scratch::new();
        let output = scratch.output();
        if let Some(files) = &existing {
            fs::create_dir(&output).unwrap();
            for file in files {
                fs::write(output.join(file), "old package").unwrap();
            }
        }
        install_package(&scratch.staging(), &chosen(&output)).unwrap();
        assert_eq!(
            names(&output),
            vec![PACKAGE_MARKER.to_string(), "new.js".to_string()],
            "{existing:?}"
        );
        assert_eq!(
            names(&scratch.0),
            vec!["pkg".to_string()],
            "the staging and previous packages must be gone"
        );
    }
}

#[test]
fn a_foreign_directory_is_never_replaced() {
    let scratch = Scratch::new();
    let output = scratch.output();
    fs::create_dir_all(output.join("src")).unwrap();
    fs::write(output.join("src/lib.rs"), "user code").unwrap();
    let staging = scratch.staging();
    for failure in [
        ensure_replaceable(&chosen(&output)),
        install_package(&staging, &chosen(&output)),
    ] {
        let message = failure.unwrap_err().to_string();
        assert!(
            message.contains(&output.display().to_string()) && message.contains(PACKAGE_MARKER),
            "{message}"
        );
    }
    assert_eq!(
        fs::read_to_string(output.join("src/lib.rs")).unwrap(),
        "user code"
    );
    assert_eq!(names(&output), vec!["src".to_string()]);
}

#[test]
fn a_file_is_never_replaced() {
    let scratch = Scratch::new();
    let output = scratch.output();
    fs::write(&output, "user file").unwrap();
    let message = install_package(&scratch.staging(), &chosen(&output))
        .unwrap_err()
        .to_string();
    assert!(message.contains("is not a directory"), "{message}");
    assert_eq!(fs::read_to_string(&output).unwrap(), "user file");
}

#[test]
fn the_default_output_is_replaced_without_a_marker() {
    // An older CLI wrote its default package without the marker.
    let scratch = Scratch::new();
    let output = scratch.output();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("old.js"), "old package").unwrap();
    let default = WasmOutput {
        directory: output.clone(),
        cli_owned: true,
    };
    install_package(&scratch.staging(), &default).unwrap();
    assert_eq!(
        names(&output),
        vec![PACKAGE_MARKER.to_string(), "new.js".to_string()]
    );
    assert_eq!(names(&scratch.0), vec!["pkg".to_string()]);
}

#[cfg(unix)]
#[test]
fn only_the_default_directory_of_the_default_build_is_cli_owned() {
    let scratch = Scratch::new();
    let package = Package {
        name: "app".into(),
        manifest: scratch.0.join("app/Cargo.toml"),
        root: scratch.0.clone(),
        target: scratch.0.join("target"),
        xark_wasm: None,
        xark_dependency: String::new(),
        metadata: Vec::new(),
        lib_name: None,
    };
    let out = scratch.0.join("target/zk/app");
    fs::create_dir_all(&out).unwrap();
    let owned = |options: &CompileOptions| wasm_output(&package, &out, options).unwrap().cli_owned;
    assert!(owned(&CompileOptions::default()), "default");
    assert!(
        !owned(&CompileOptions {
            r1cs_out: Some(out.clone()),
            ..CompileOptions::default()
        }),
        "--r1cs-out can point into a user's project"
    );
    assert!(
        !owned(&CompileOptions {
            wasm_out: Some(out.join("wasm")),
            ..CompileOptions::default()
        }),
        "--wasm-out"
    );

    // A default path that is a symlink leads into another directory.
    let elsewhere = scratch.0.join("web/public/wasm");
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, out.join("wasm")).unwrap();
    assert!(
        !owned(&CompileOptions::default()),
        "symlinked wasm directory"
    );

    // A symlinked build directory puts the default package in the user's tree.
    let project = scratch.0.join("project");
    fs::create_dir_all(&project).unwrap();
    fs::remove_dir_all(&out).unwrap();
    std::os::unix::fs::symlink(&project, &out).unwrap();
    assert!(
        !owned(&CompileOptions::default()),
        "symlinked build directory"
    );
}

#[test]
fn a_build_directory_that_does_not_resolve_is_not_cli_owned() {
    let scratch = Scratch::new();
    let package = Package {
        name: "app".into(),
        manifest: scratch.0.join("app/Cargo.toml"),
        root: scratch.0.clone(),
        target: scratch.0.join("missing-target"),
        xark_wasm: None,
        xark_dependency: String::new(),
        metadata: Vec::new(),
        lib_name: None,
    };
    let out = scratch.0.join("missing-target/zk/app");
    assert!(
        !wasm_output(&package, &out, &CompileOptions::default())
            .unwrap()
            .cli_owned
    );
}
