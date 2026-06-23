fn main() {
    #[cfg(feature = "generate")]
    generate();
}

#[cfg(feature = "generate")]
fn generate() {
    use std::{env, fs, path::PathBuf};

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let spec_path = env::var("ZOLANA_OPENAPI_SPEC")
        .or_else(|_| env::var("PHOTON_ZOLANA_OPENAPI_SPEC"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("../../../photon/src/openapi/specs/zolana.yaml"));

    println!("cargo::rerun-if-changed={}", spec_path.display());

    // Regeneration is best-effort: when the Photon spec is not available
    // (e.g. building with `--all-features` without a Photon checkout) keep the
    // committed `src/codegen.rs` instead of failing the build.
    let spec_content = match fs::read_to_string(&spec_path) {
        Ok(content) => content,
        Err(err) => {
            println!(
                "cargo::warning=zolana-api: skipping codegen, cannot read OpenAPI spec at {}: {err}",
                spec_path.display()
            );
            return;
        }
    };
    let mut spec: serde_yaml::Value =
        serde_yaml::from_str(&spec_content).expect("Failed to parse OpenAPI spec");

    if let Some(info) = spec.get_mut("info").and_then(|info| info.as_mapping_mut()) {
        info.insert(
            serde_yaml::Value::String("title".to_string()),
            serde_yaml::Value::String("zolana-indexer-api".to_string()),
        );
        info.insert(
            serde_yaml::Value::String("description".to_string()),
            serde_yaml::Value::String("Zolana indexer API".to_string()),
        );
    }

    if let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_mapping_mut()) {
        for (path, methods) in paths.iter_mut() {
            let path_str = path.as_str().unwrap_or("");
            let base_id = path_str.trim_start_matches('/');

            if let Some(methods_map) = methods.as_mapping_mut() {
                for (method, operation) in methods_map.iter_mut() {
                    if method.as_str() == Some("summary") {
                        continue;
                    }

                    if let Some(op_map) = operation.as_mapping_mut() {
                        let method_str = method.as_str().unwrap_or("get");
                        let operation_id = format!("{}_{}", method_str, to_snake_case(base_id));

                        op_map.insert(
                            serde_yaml::Value::String("operationId".to_string()),
                            serde_yaml::Value::String(operation_id),
                        );
                    }
                }
            }
        }
    }

    let modified_spec = serde_yaml::to_string(&spec).expect("Failed to serialize modified spec");
    let spec: openapiv3::OpenAPI =
        serde_yaml::from_str(&modified_spec).expect("Failed to parse modified OpenAPI spec");

    let mut settings = progenitor::GenerationSettings::default();
    settings.with_interface(progenitor::InterfaceStyle::Builder);

    let mut generator = progenitor::Generator::new(&settings);
    let tokens = generator
        .generate_tokens(&spec)
        .expect("Failed to generate client code");

    let ast: syn::File = syn::parse2(tokens).expect("Failed to parse generated code");
    let content = prettyplease::unparse(&ast);
    fs::write(manifest_dir.join("src/codegen.rs"), content)
        .expect("Failed to write generated code");

    eprintln!("zolana-api: regenerated src/codegen.rs from OpenAPI spec");
}

#[cfg(feature = "generate")]
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_is_lower = false;

    for c in s.chars() {
        if c.is_uppercase() {
            if prev_is_lower {
                result.push('_');
            }
            result.extend(c.to_lowercase());
            prev_is_lower = false;
        } else {
            result.push(c);
            prev_is_lower = c.is_lowercase();
        }
    }

    result
}
