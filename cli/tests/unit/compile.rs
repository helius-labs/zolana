use super::*;

#[test]
fn xark_is_pinned_to_its_crates_io_version_or_git_revision() {
    assert_eq!(
        xark_source::pinned_dependency(xark_source::CRATES_IO, "0.3.0").as_deref(),
        Ok("version = \"=0.3.0\"")
    );
    let pinned = "git = \"https://github.com/ananas-block/xark\", rev = \"ad7baad\"";
    for source in [
        "git+https://github.com/ananas-block/xark?rev=ad7baad",
        "git+https://github.com/ananas-block/xark?rev=ad7baad#ad7baad990cb",
    ] {
        assert_eq!(
            xark_source::pinned_dependency(source, "0.3.0").as_deref(),
            Ok(pinned)
        );
    }
    for source in [
        "registry+https://example.com/index",
        "path+file:///xark/crates/lang",
        "git+https://github.com/ananas-block/xark",
        "git+https://github.com/ananas-block/xark?branch=main",
        "git+https://github.com/ananas-block/xark?rev=",
        "git+https://github.com/ananas-block/xark?rev=a&branch=main",
        "git+?rev=ad7baad",
    ] {
        assert!(
            xark_source::pinned_dependency(source, "0.3.0").is_err(),
            "{source}"
        );
    }
}

#[test]
fn plain_circuits_name_every_program_only_flag() {
    assert_eq!(
        program_only_flags(&CompileOptions::default()),
        Vec::<&str>::new()
    );
    let options = CompileOptions {
        wasm_target: Some(WasmTarget::Web),
        wasm_features: Some(DEFAULT_WASM_FEATURES.into()),
        verifier: true,
        no_prover: true,
        single_threaded: true,
        wasm_opt: true,
        ..CompileOptions::default()
    };
    assert_eq!(
        program_only_flags(&options),
        vec![
            "--wasm-target",
            "--wasm-features",
            "--verifier",
            "--no-prover",
            "--single-threaded",
            "--wasm-opt",
        ]
    );
}
