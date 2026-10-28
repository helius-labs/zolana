use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Workspace(PathBuf);

impl Workspace {
    fn new(default: &str, extra_dependencies: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "zolana-input-only-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let workspace = Self(root);
        workspace.write("Cargo.toml", "[workspace]\nmembers = [\"app\", \"other\", \"runtime\"]\nresolver = \"2\"\n");
        workspace.write("runtime/Cargo.toml", "[package]\nname = \"xark-wasm\"\nversion = \"0.0.0\"\nedition = \"2021\"\n");
        workspace.write("runtime/src/lib.rs", "compile_error!(\"dependency checks must not compile Rust\");\n");
        workspace.write("other/Cargo.toml", "[package]\nname = \"other\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[dependencies]\nxark-wasm = { path = \"../runtime\" }\n");
        workspace.write("other/src/lib.rs", "");
        workspace.write("app/Cargo.toml", &format!(
            "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [features]\ndefault = [{default}]\nwasm = []\nruntime = [\"dep:xark-wasm\"]\nhidden = [\"runtime\"]\n\
             [dependencies]\nxark-wasm = {{ path = \"../runtime\", optional = true }}\n{extra_dependencies}"
        ));
        workspace.write("app/src/lib.rs", "compile_error!(\"dependency checks must not compile Rust\");\n");
        workspace
    }

    fn write(&self, name: &str, contents: &str) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn package(&self) -> Package {
        Package {
            name: "app".into(), manifest: self.0.join("app/Cargo.toml"),
            root: self.0.clone(), target: self.0.join("target"), xark_source: self.0.clone(), xark_dependency: String::new(),
        }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

#[test]
fn permits_input_only_despite_another_workspace_members_runtime() {
    let workspace = Workspace::new("", "");
    assert_eq!(check_input_only(&workspace.package(), "wasm").map_err(|error| error.to_string()), Ok(()));
    assert_eq!(workspace.0.join("target").exists(), false, "preflight must not compile anything");
}

#[test]
fn rejects_direct_alias_and_default_feature_activation() {
    let workspace = Workspace::new("", "");
    for features in ["wasm,runtime", "wasm,hidden"] {
        let failure = check_input_only(&workspace.package(), features).unwrap_err();
        assert_eq!(failure.to_string(), "--no-prover conflicts with a resolved WASM dependency on xark-wasm; disable the feature or dependency that enables it");
    }
    let defaults = Workspace::new("\"hidden\"", "");
    let failure = check_input_only(&defaults.package(), "wasm").unwrap_err();
    assert_eq!(failure.to_string(), "--no-prover conflicts with a resolved WASM dependency on xark-wasm; disable the feature or dependency that enables it");
}

#[test]
fn ignores_dev_build_and_native_only_runtime_dependencies() {
    for extra_dependencies in [
        "[dev-dependencies]\nxark-wasm = { path = \"../runtime\" }\n",
        "[build-dependencies]\nxark-wasm = { path = \"../runtime\" }\n",
        "[target.'cfg(not(target_arch = \"wasm32\"))'.dependencies]\nxark-wasm = { path = \"../runtime\" }\n",
    ] {
        let workspace = Workspace::new("", extra_dependencies);
        assert_eq!(check_input_only(&workspace.package(), "wasm").map_err(|error| error.to_string()), Ok(()));
    }
}

#[test]
fn ignores_host_proc_macro_dependencies() {
    let workspace = Workspace::new("", "macro-helper = { path = \"../macro-helper\" }\n");
    workspace.write("macro-helper/Cargo.toml", "[package]\nname = \"macro-helper\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[lib]\nproc-macro = true\n[dependencies]\nxark-wasm = { path = \"../runtime\" }\n");
    workspace.write("macro-helper/src/lib.rs", "compile_error!(\"dependency checks must not compile Rust\");\n");
    assert_eq!(check_input_only(&workspace.package(), "wasm").map_err(|error| error.to_string()), Ok(()));
}

#[test]
fn reports_cargo_resolution_errors_before_building() {
    let workspace = Workspace::new("", "");
    let failure = check_input_only(&workspace.package(), "missing-feature").unwrap_err();
    assert_eq!(failure.to_string().contains("missing-feature"), true);
    assert_eq!(workspace.0.join("target").exists(), false);
}
