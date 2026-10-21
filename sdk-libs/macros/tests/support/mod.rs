pub fn normalize_git_diagnostics() {
    // trybuild normalizes registry and path dependencies, but not Git sources.
    // It also replaces RUSTFLAGS, so remap those sources through a rustc wrapper.
    std::env::set_var(
        "RUSTC_WRAPPER",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ui-rustc.sh"),
    );
}
