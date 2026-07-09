fn main() {
    #[cfg(feature = "generate")]
    generate();
}

#[cfg(feature = "generate")]
fn generate() {
    use std::{env, fs, path::PathBuf};

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let spec_path = env::var("RINGS_OPENAPI_SPEC")
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
                "cargo::warning=rings-api: skipping codegen, cannot read OpenAPI spec at {}: {err}",
                spec_path.display()
            );
            return;
        }
    };
    let mut spec: serde_yaml::Value =
        serde_yaml::from_str(&spec_content).expect("Failed to parse OpenAPI spec");

    // progenitor's openapiv3 (3.0.x only, latest 2.2.0) rejects the "3.1.0"
    // version utoipa emits. Normalize the declared version and rewrite utoipa's
    // 3.1 nullable form (`oneOf/anyOf: [{type: 'null'}, X]`) to 3.0's
    // `nullable: true`, which progenitor understands.
    if let Some(map) = spec.as_mapping_mut() {
        map.insert(
            serde_yaml::Value::String("openapi".to_string()),
            serde_yaml::Value::String("3.0.3".to_string()),
        );
    }
    normalize_nullable(&mut spec);

    if let Some(info) = spec.get_mut("info").and_then(|info| info.as_mapping_mut()) {
        info.insert(
            serde_yaml::Value::String("title".to_string()),
            serde_yaml::Value::String("rings-indexer-api".to_string()),
        );
        info.insert(
            serde_yaml::Value::String("description".to_string()),
            serde_yaml::Value::String("Rings indexer API".to_string()),
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

    eprintln!("rings-api: regenerated src/codegen.rs from OpenAPI spec");
}

#[cfg(feature = "generate")]
fn is_null_type(value: &serde_yaml::Value) -> bool {
    value.get("type").and_then(|t| t.as_str()) == Some("null")
}

/// Rewrite utoipa's OpenAPI 3.1 nullable form
/// (`oneOf`/`anyOf: [{type: 'null'}, X]`) into 3.0's `X + nullable: true`, which
/// progenitor/openapiv3 (3.0.x) can parse. A nullable `$ref` becomes
/// `allOf: [ref], nullable: true` (the standard 3.0 workaround).
#[cfg(feature = "generate")]
fn normalize_nullable(value: &mut serde_yaml::Value) {
    use serde_yaml::Value;

    match value {
        Value::Mapping(map) => {
            for (_key, child) in map.iter_mut() {
                normalize_nullable(child);
            }

            for combiner in ["oneOf", "anyOf"] {
                let items = match map.get(combiner) {
                    Some(Value::Sequence(items)) => items.clone(),
                    _ => continue,
                };
                if !items.iter().any(is_null_type) {
                    continue;
                }
                let non_null: Vec<Value> = items
                    .into_iter()
                    .filter(|item| !is_null_type(item))
                    .collect();
                if non_null.len() != 1 {
                    continue;
                }

                map.remove(combiner);
                match non_null.into_iter().next().expect("one non-null variant") {
                    Value::Mapping(inner) if inner.contains_key("$ref") => {
                        map.insert(
                            Value::String("allOf".to_string()),
                            Value::Sequence(vec![Value::Mapping(inner)]),
                        );
                    }
                    Value::Mapping(inner) => {
                        for (inner_key, inner_val) in inner {
                            map.insert(inner_key, inner_val);
                        }
                    }
                    other => {
                        map.insert(
                            Value::String("allOf".to_string()),
                            Value::Sequence(vec![other]),
                        );
                    }
                }
                map.insert(Value::String("nullable".to_string()), Value::Bool(true));
                break;
            }
        }
        Value::Sequence(seq) => {
            for child in seq.iter_mut() {
                normalize_nullable(child);
            }
        }
        _ => {}
    }
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
