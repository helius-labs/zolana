use super::*;
use ark_bn254::{Bn254, G1Affine, G2Affine, g1, g2};
use ark_serialize::CanonicalSerialize;
use groth16_solana::vk::setup::{SetupTxt, find_setup_txts};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Artifact(PathBuf);

impl Artifact {
    fn new(production: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "zolana-vk-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let artifact = Self(path);
        let alpha = G1Affine::new_unchecked(g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y);
        let gamma = G2Affine::new_unchecked(g2::G2_GENERATOR_X, g2::G2_GENERATOR_Y);
        let key = xark_groth16::VerifyingKey::<Bn254> {
            alpha_g1: alpha,
            beta_g2: -gamma,
            gamma_g2: gamma,
            delta_g2: if production { -gamma } else { gamma },
            gamma_abc_g1: vec![alpha, -alpha],
        };
        let mut bytes = Vec::new();
        key.serialize_compressed(&mut bytes).unwrap();
        fs::write(artifact.0.join("vk.bin"), &bytes).unwrap();
        fs::write(
            artifact.0.join("pk.bin"),
            b"exact serialized proving key bytes\0\xff",
        )
        .unwrap();
        fs::write(artifact.0.join("digest"), "circuit-digest\n").unwrap();
        artifact.write_metadata(&json!({
            "verifying_key_sha256": format!("{:x}", Sha256::digest(&bytes)),
            "digest": "circuit-digest",
            "production_safe": production,
        }));
        artifact
    }

    fn metadata(&self) -> Value {
        serde_json::from_slice(&fs::read(self.0.join("metadata.json")).unwrap()).unwrap()
    }

    fn write_metadata(&self, metadata: &Value) {
        fs::write(self.0.join("metadata.json"), metadata.to_string()).unwrap();
    }

    fn replace_key(&self, bytes: &[u8]) {
        fs::write(self.0.join("vk.bin"), bytes).unwrap();
        let mut metadata = self.metadata();
        metadata["verifying_key_sha256"] = json!(format!("{:x}", Sha256::digest(bytes)));
        self.write_metadata(&metadata);
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn metadata_hashes_exact_proving_key_bytes() {
    let artifact = Artifact::new(false);
    let bytes = fs::read(artifact.0.join("pk.bin")).unwrap();
    let expected = KeySetupMetadata {
        proving_key_sha256: Sha256::digest(&bytes).into(),
        insecure_test_setup: true,
    };
    let actual = key_setup_metadata(&artifact.0).unwrap();
    assert_eq!(
        actual, expected,
        "metadata must pin the serialized pk.bin bytes"
    );
    assert_eq!(
        serde_json::to_value(&actual).unwrap(),
        json!({
            "provingKeySha256": expected.proving_key_sha256,
            "insecureTestSetup": true,
        }),
        "browser metadata must use camelCase"
    );
    fs::write(artifact.0.join("pk.bin"), b"different serialization").unwrap();
    assert_ne!(
        key_setup_metadata(&artifact.0).unwrap().proving_key_sha256,
        actual.proving_key_sha256
    );
}

#[test]
fn key_source_preserves_standard_setup_metadata_and_compatibility_hashes() {
    let artifact = Artifact::new(false);
    let metadata = key_setup_metadata(&artifact.0).unwrap();
    let source = key_source(&artifact.0).unwrap();
    let marker = source
        .split("pub static VERIFYINGKEY_SETUP_TXT: &str = \"")
        .nth(1)
        .unwrap()
        .split("\";")
        .next()
        .unwrap()
        .replace("\\x00", "\0");
    assert_eq!(
        find_setup_txts(marker.as_bytes()).unwrap(),
        vec![SetupTxt {
            name: "VERIFYINGKEY".into(),
            insecure_test_setup: true,
            proving_key_sha256: metadata.proving_key_sha256,
        }],
        "the standard retained marker must match the trusted browser metadata"
    );
    let digest = metadata
        .proving_key_sha256
        .iter()
        .map(|byte| format!("{byte}u8"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(source.contains(&format!(
        "pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32] = [{digest}];"
    )));
    assert!(source.contains("#[unsafe(export_name = \"groth16_solana_vk_setup_"));
    assert!(
        source.contains(&format!(
            "pub const ZOLANA_VK_SHA256: &str = \"{}\";",
            artifact.metadata()["verifying_key_sha256"]
                .as_str()
                .unwrap()
        ))
    );
    assert!(source.contains("pub const ZOLANA_CIRCUIT_DIGEST: &str = \"circuit-digest\";"));
}

#[test]
fn generated_curve_points_match_solana_verifying_key() {
    let artifact = Artifact::new(true);
    let source = key_source(&artifact.0).unwrap();
    let bytes = fs::read(artifact.0.join("vk.bin")).unwrap();
    let key = crate::proof::SolanaVerifyingKey::from_xark(&bytes).unwrap();
    let key = key.as_key();
    let field_bytes = |field: &str| -> Vec<u8> {
        source
            .split(&format!("{field}: "))
            .nth(1)
            .unwrap()
            .split("],")
            .next()
            .unwrap()
            .split(|ch: char| !(ch.is_ascii_alphanumeric()))
            .filter_map(|token| token.strip_suffix("u8").map(|byte| byte.parse().unwrap()))
            .collect()
    };
    for (field, expected) in [
        ("vk_alpha_g1", key.vk_alpha_g1.as_slice()),
        ("vk_beta_g2", key.vk_beta_g2.as_slice()),
        ("vk_gamma_g2", key.vk_gamma_g2.as_slice()),
        ("vk_delta_g2", key.vk_delta_g2.as_slice()),
    ] {
        assert_eq!(
            field_bytes(field),
            expected,
            "generated {field} encoding differs"
        );
    }
    let ic_source = source
        .split("vk_ic: &[")
        .nth(1)
        .unwrap()
        .split("\n\t],")
        .next()
        .unwrap();
    let ic: Vec<u8> = ic_source
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| token.strip_suffix("u8").map(|byte| byte.parse().unwrap()))
        .collect();
    assert_eq!(
        ic,
        key.vk_ic.concat(),
        "generated public input points differ"
    );
    assert!(source.contains("nr_pubinputs: 1,"));
}

#[test]
fn false_or_unknown_production_flag_keeps_test_guard() {
    let artifact = Artifact::new(false);
    for flag in [
        Some(json!(false)),
        Some(Value::Null),
        Some(json!("true")),
        None,
    ] {
        let mut metadata = artifact.metadata();
        match flag {
            Some(value) => metadata["production_safe"] = value,
            None => {
                metadata.as_object_mut().unwrap().remove("production_safe");
            }
        }
        artifact.write_metadata(&metadata);
        let source = key_source(&artifact.0).unwrap();
        assert!(source.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;"));
        assert!(source.contains("#[cfg(not(feature = \"insecure-test-setup\"))]\ncompile_error!("));
        assert!(key_setup_metadata(&artifact.0).unwrap().insecure_test_setup);
    }
}

#[test]
fn production_key_omits_test_guard() {
    let artifact = Artifact::new(true);
    let source = key_source(&artifact.0).unwrap();
    assert!(source.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;"));
    assert!(!source.contains("compile_error!"));
    assert!(!key_setup_metadata(&artifact.0).unwrap().insecure_test_setup);
}

#[test]
fn production_key_rejects_delta_equal_to_gamma() {
    let artifact = Artifact::new(false);
    let mut metadata = artifact.metadata();
    metadata["production_safe"] = json!(true);
    artifact.write_metadata(&metadata);
    for result in [
        key_source(&artifact.0).map(|_| ()),
        key_setup_metadata(&artifact.0).map(|_| ()),
    ] {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("vk_delta_2 equals vk_gamma_2")
        );
    }
}

#[test]
fn mismatched_verifying_key_hash_is_rejected() {
    let artifact = Artifact::new(false);
    fs::write(artifact.0.join("vk.bin"), b"replaced verifying key").unwrap();
    assert_eq!(
        key_setup_metadata(&artifact.0).unwrap_err().to_string(),
        "verifying key differs from its setup metadata"
    );
}

#[test]
fn mismatched_circuit_digest_is_rejected() {
    let artifact = Artifact::new(false);
    fs::write(artifact.0.join("digest"), "different circuit").unwrap();
    assert_eq!(
        key_setup_metadata(&artifact.0).unwrap_err().to_string(),
        "verifying key belongs to a different circuit"
    );
}

#[test]
fn invalid_verifying_key_is_rejected_even_with_matching_metadata() {
    let artifact = Artifact::new(false);
    artifact.replace_key(b"not a serialized verifying key");
    assert!(key_setup_metadata(&artifact.0).is_err());
}

#[test]
fn verifying_key_with_no_constant_input_is_rejected() {
    let artifact = Artifact::new(false);
    let key = xark_groth16::VerifyingKey::<Bn254>::default();
    let mut bytes = Vec::new();
    key.serialize_compressed(&mut bytes).unwrap();
    artifact.replace_key(&bytes);
    assert!(
        key_setup_metadata(&artifact.0)
            .unwrap_err()
            .to_string()
            .contains("IC is empty")
    );
}

#[test]
fn missing_proving_key_is_rejected() {
    let artifact = Artifact::new(false);
    fs::remove_file(artifact.0.join("pk.bin")).unwrap();
    assert!(
        key_setup_metadata(&artifact.0)
            .unwrap_err()
            .to_string()
            .contains("No such file")
    );
}
