use serde_json::Value;

use super::*;
use crate::prover::ProverKeys;

fn catalog() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../test-vectors/runtime_proving_keys.json"
    ))
    .unwrap()
}

fn parse(value: &Value) -> Result<ProvingKeySet, ClientError> {
    ProvingKeySet::from_attested_response(&value.to_string())
}

fn reason(value: &Value) -> &'static str {
    match parse(value) {
        Err(ClientError::ProvingKeySet(reason)) => reason,
        other => panic!("accepted or failed otherwise: {other:?}"),
    }
}

fn zopro<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    let entry = value["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["name"] == name)
        .unwrap();
    entry["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["format"] == "zopro")
        .unwrap()
}

#[test]
fn the_prover_serves_the_compiled_verifying_keys() {
    let compiled = RuntimeKeyMetadata::compiled();
    let embedded: RuntimeKeyMetadata = serde_json::from_str(include_str!(
        "../../../../../prover/server/prover/provingkeys/runtime-keys.json"
    ))
    .unwrap();
    assert_eq!(
        embedded, compiled,
        "run cargo run -q -p xtask -- runtime-proving-keys"
    );
    let shared: RuntimeKeyMetadata = serde_json::from_value(catalog()["runtime"].clone()).unwrap();
    assert_eq!(shared, compiled);
    assert_eq!(compiled.verifying_keys.len(), 41);
    assert!(compiled
        .verifying_keys
        .keys()
        .all(|name| name.starts_with("transfer_confidential_") || name.starts_with("merge_")));
    assert!(!compiled
        .verifying_keys
        .keys()
        .any(|name| name.contains("eddsa") || name.contains("ring")));
}

#[test]
fn an_attested_catalog_yields_its_keys_and_cache_key() {
    let value = catalog();
    let keys = parse(&value).unwrap();
    assert_eq!(
        keys.cache_key(),
        value["expectedCacheKey"].as_str().unwrap()
    );
    let all: Vec<_> = keys.keys().collect();
    assert_eq!(all.len(), 41);
    for (key, artifact) in all {
        let pinned = known_proving_keys()
            .find(|(name, _)| *name == key.name)
            .unwrap()
            .1;
        assert_eq!(key.sha256, pinned);
        assert_eq!(artifact.format, ProvingKeyFormat::Zopro);
        assert!(artifact.url.ends_with(&key.name.replace(".key", ".zopro")));
    }
}

#[test]
fn a_key_outside_the_set_is_refused() {
    let keys = parse(&catalog()).unwrap();
    let merge = ExpectedProvingKey::merge(8).unwrap();
    assert_eq!(keys.expected(&merge).unwrap(), merge);
    for key in [
        ExpectedProvingKey::merge_ring(8).unwrap(),
        ExpectedProvingKey {
            name: "transfer_confidential_eddsa_2_2.key".into(),
            sha256: [0; 32],
        },
        ExpectedProvingKey::batch_address_append(40, 10).unwrap(),
    ] {
        assert!(matches!(
            keys.expected(&key),
            Err(ClientError::ProvingKeySet("unsupported_circuit"))
        ));
    }
}

#[test]
fn a_rotated_key_replaces_the_compiled_pin() {
    let mut value = catalog();
    let name = "transfer_confidential_2_2.key";
    let rotated = "ab".repeat(32);
    value["runtime"]["verifyingKeys"][name]["provingKeySha256"] = rotated.clone().into();
    let entry = value["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["name"] == name)
        .unwrap();
    entry["artifacts"][0]["sha256"] = rotated.clone().into();
    let keys = parse(&value).unwrap();
    assert_ne!(
        keys.cache_key(),
        catalog()["expectedCacheKey"].as_str().unwrap()
    );
    let expected = keys
        .expected(&ExpectedProvingKey::transfer_confidential(2, 2).unwrap())
        .unwrap();
    assert_eq!(hex(&expected.sha256), rotated);
}

#[test]
fn the_prover_check_under_a_set_compares_only_its_keys() {
    let keys = parse(&catalog()).unwrap();
    let artifact = |sha256: String| ProvingKeyArtifact {
        format: ProvingKeyFormat::Gnark,
        sha256,
        size: 1,
        url: "https://keys.example/key".into(),
    };
    let report = |name: &str, sha256: String| ProverKeys {
        keys: known_proving_keys()
            .map(|(key, pinned)| ProverKeyStatus {
                name: key.to_owned(),
                artifacts: vec![artifact(if key == name {
                    sha256.clone()
                } else {
                    hex(&pinned)
                })],
            })
            .collect(),
    };
    // A rotation also changes keys outside the set, which the set refuses anyway.
    let outside = report("merge_ring_8_1.key", "cd".repeat(32));
    assert!(outside.check_with_keys(Some(&keys)).is_ok());
    assert!(matches!(
        outside.check(),
        Err(ClientError::ProverProvingKeysMismatch { .. })
    ));
    let inside = report("merge_8_1.key", "cd".repeat(32));
    assert!(matches!(
        inside.check_with_keys(Some(&keys)),
        Err(ClientError::ProverProvingKeysMismatch { mismatches }) if mismatches == ["merge_8_1.key"]
    ));
}

#[test]
fn incompatible_or_malformed_catalogs_are_refused() {
    type Change = fn(&mut Value);
    let cases: Vec<(&str, Change)> = vec![
        ("runtime_missing", |v| {
            v.as_object_mut().unwrap().remove("runtime");
        }),
        ("incompatible", |v| {
            v["runtime"]["abi"] = "spr-confidential-v2".into()
        }),
        ("incompatible", |v| {
            v["runtime"]["programId"] = "11111111111111111111111111111111".into()
        }),
        ("incompatible", |v| {
            v["runtime"]["verifyingKeys"]
                .as_object_mut()
                .unwrap()
                .remove("merge_8_1.key");
        }),
        ("malformed", |v| v["runtime"]["extra"] = 1.into()),
        ("malformed", |v| {
            v["runtime"]["verifyingKeys"]["merge_8_1.key"]["alphaG1"] = "00".into()
        }),
        ("malformed", |v| {
            let key = &mut v["runtime"]["verifyingKeys"]["merge_8_1.key"];
            key["alphaG1"] = key["alphaG1"].as_str().unwrap().to_uppercase().into();
        }),
        ("malformed", |v| {
            v["runtime"]["verifyingKeys"]["merge_8_1.key"]["ic"] = Value::Array(vec![]);
        }),
        ("source_mismatch", |v| {
            v["runtime"]["verifyingKeys"]["merge_8_1.key"]["provingKeySha256"] =
                "cd".repeat(32).into()
        }),
        ("malformed", |v| {
            zopro(v, "merge_8_1.key")["sha256"] = "AB".repeat(32).into()
        }),
        ("malformed", |v| {
            zopro(v, "merge_8_1.key")["size"] = 0.into()
        }),
        ("malformed", |v| {
            zopro(v, "merge_8_1.key")["size"] = 0x1_0000_0000u64.into()
        }),
        ("malformed", |v| {
            zopro(v, "merge_8_1.key")["url"] = "http://keys.example/merge_8_1.zopro".into()
        }),
        ("malformed", |v| {
            zopro(v, "merge_8_1.key")["url"] = "https://user:pw@keys.example/k".into()
        }),
        ("malformed", |v| {
            zopro(v, "merge_8_1.key")["url"] = "https://keys.example/k#frag".into()
        }),
        ("malformed", |v| {
            let keys = v["keys"].as_array_mut().unwrap();
            keys.push(keys[0].clone());
        }),
        ("malformed", |v| {
            let artifact = zopro(v, "merge_8_1.key").clone();
            let entry = v["keys"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|key| key["name"] == "merge_8_1.key")
                .unwrap();
            entry["artifacts"].as_array_mut().unwrap().push(artifact);
        }),
        ("malformed", |v| {
            let entry = v["keys"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|key| key["name"] == "merge_8_1.key")
                .unwrap();
            entry["artifacts"].as_array_mut().unwrap().truncate(1);
        }),
        ("malformed", |v| v["keys"] = Value::Array(vec![])),
    ];
    for (expected, change) in cases {
        let mut value = catalog();
        change(&mut value);
        assert_eq!(reason(&value), expected, "{value:#}");
    }
}

#[test]
fn a_loopback_download_and_unknown_verifiers_are_accepted() {
    let mut value = catalog();
    zopro(&mut value, "merge_8_1.key")["url"] = "http://127.0.0.1:8080/merge_8_1.zopro".into();
    let extra = value["runtime"]["verifyingKeys"]["merge_8_1.key"].clone();
    value["runtime"]["verifyingKeys"]["merge_99_1.key"] = extra;
    let keys = parse(&value).unwrap();
    assert_eq!(keys.keys().count(), 41);
}

#[test]
fn the_set_verifies_a_real_proof_against_its_own_verifying_key() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../../test-vectors/runtime_key_proof.json"
    ))
    .unwrap();
    let proof = Proof::from_gnark_json(&vector["proof"].to_string()).unwrap();
    let name = vector["key"].as_str().unwrap();
    let digits = vector["publicInputHash"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x");
    let public_input: [u8; 32] = hex::decode(format!("{digits:0>64}"))
        .unwrap()
        .try_into()
        .unwrap();
    let keys = parse(&catalog()).unwrap();
    keys.verify(name, public_input, &proof).unwrap();

    let mut other_statement = public_input;
    other_statement[31] ^= 1;
    assert!(keys.verify(name, other_statement, &proof).is_err());
    assert!(keys.verify("merge_8_1.key", public_input, &proof).is_err());
    assert!(matches!(
        keys.verify("merge_ring_8_1.key", public_input, &proof),
        Err(ClientError::ProvingKeySet("unsupported_circuit"))
    ));

    let mut value = catalog();
    let key = &mut value["runtime"]["verifyingKeys"][name];
    key["alphaG1"] = key["ic"][0].clone();
    assert!(parse(&value)
        .unwrap()
        .verify(name, public_input, &proof)
        .is_err());
}
