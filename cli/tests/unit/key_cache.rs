use super::*;
use serde_json::json;
use std::{path::PathBuf, sync::atomic::{AtomicUsize, Ordering}};

#[path = "../support/zk_fixture.rs"]
mod fixture;

struct Cache(PathBuf);

impl Cache {
    fn new(production: bool, seed: Option<u64>) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!("zolana-cache-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let cache = Self(root);
        let (proving_key, verifying_key) = fixture::key_bytes();
        fs::write(cache.0.join("pk.bin"), proving_key).unwrap();
        fs::write(cache.0.join("vk.bin"), &verifying_key).unwrap();
        fs::write(cache.0.join("digest"), "current-circuit\n").unwrap();
        cache.metadata(json!({
            "protocol": "groth16", "curve": "bn254", "digest": "current-circuit",
            "production_safe": production, "deterministic_rng_seed": seed,
            "setup_mode": if production { "phase2-from-ptau" } else { "insecure-dev-mode" },
            "verifying_key_sha256": format!("{:x}", Sha256::digest(&verifying_key)),
        }));
        cache
    }

    fn metadata(&self, metadata: Value) { fs::write(self.0.join("metadata.json"), metadata.to_string()).unwrap(); }

    fn edit_metadata(&self, field: &str, value: Value) {
        let mut metadata: Value = serde_json::from_slice(&fs::read(self.0.join("metadata.json")).unwrap()).unwrap();
        metadata[field] = value;
        self.metadata(metadata);
    }

    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = fs::read_dir(&self.0).unwrap().map(|file| {
            let path = file.unwrap().path();
            (path.file_name().unwrap().into(), fs::read(path).unwrap())
        }).collect::<Vec<_>>();
        files.sort();
        files
    }

    fn assert_rejected_without_changes(&self, mode: Mode) {
        let original = self.snapshot();
        assert!(reusable(&self.0, mode).is_err());
        assert_eq!(self.snapshot(), original, "a rejected setup must preserve every existing artifact");
    }
}

impl Drop for Cache { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

#[test]
fn reuses_complete_pairs_for_the_requested_setup() {
    for (production, seed, mode) in [(false, Some(0), Mode::Test), (false, None, Mode::Default), (true, None, Mode::Default), (true, None, Mode::Existing), (false, Some(0), Mode::Existing)] {
        let cache = Cache::new(production, seed);
        assert_eq!(reusable(&cache.0, mode).unwrap(), true);
    }
    let contributed = Cache::new(true, None);
    contributed.edit_metadata("setup_mode", json!("phase2-from-ptau+mpc[2 contributors]"));
    assert_eq!(reusable(&contributed.0, Mode::Default).unwrap(), true);
}

#[test]
fn regenerates_only_known_dev_caches_when_mode_or_artifacts_change() {
    for (seed, mode) in [(Some(0), Mode::Default), (Some(42), Mode::Test), (None, Mode::Test)] {
        let cache = Cache::new(false, seed);
        assert_eq!(reusable(&cache.0, mode).unwrap(), false);
    }
    let cache = Cache::new(false, Some(0));
    fs::remove_file(cache.0.join("vk.bin")).unwrap();
    assert_eq!(reusable(&cache.0, Mode::Test).unwrap(), false);
    fs::remove_file(cache.0.join("pk.bin")).unwrap();
    fs::remove_file(cache.0.join("metadata.json")).unwrap();
    assert_eq!(reusable(&cache.0, Mode::Default).unwrap(), false);
}

#[test]
fn never_replaces_production_keys_for_test_or_invalid_cache_requests() {
    Cache::new(true, None).assert_rejected_without_changes(Mode::Test);
    for damaged in ["digest", "pk.bin", "vk.bin", "vk_hash", "pk_truncated"] {
        let cache = Cache::new(true, None);
        match damaged {
            "digest" => fs::write(cache.0.join("digest"), "changed-circuit").unwrap(),
            "pk.bin" | "vk.bin" => fs::remove_file(cache.0.join(damaged)).unwrap(),
            "vk_hash" => cache.edit_metadata("verifying_key_sha256", json!("wrong")),
            _ => fs::write(cache.0.join("pk.bin"), b"truncated").unwrap(),
        }
        cache.assert_rejected_without_changes(Mode::Default);
    }
}

#[test]
fn refuses_unknown_or_inconsistent_provenance() {
    for (field, value) in [("production_safe", json!("unknown")), ("setup_mode", json!("insecure-dev-mode")), ("setup_mode", json!("phase2-from-ptau+mpc[broken")), ("deterministic_rng_seed", json!(0)), ("protocol", json!("other")), ("curve", json!("other"))] {
        let cache = Cache::new(true, None);
        cache.edit_metadata(field, value);
        cache.assert_rejected_without_changes(Mode::Default);
    }
    let cache = Cache::new(false, None);
    fs::remove_file(cache.0.join("metadata.json")).unwrap();
    cache.assert_rejected_without_changes(Mode::Default);
    fs::write(cache.0.join("metadata.json"), b"not JSON").unwrap();
    cache.assert_rejected_without_changes(Mode::Default);
}

#[test]
fn rejects_a_different_embedded_proving_key_vk() {
    use ark_bn254::Bn254;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let cache = Cache::new(true, None);
    let bytes = fs::read(cache.0.join("vk.bin")).unwrap();
    let mut verifying_key = xark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(bytes.as_slice()).unwrap();
    verifying_key.alpha_g1 = -verifying_key.alpha_g1;
    let mut changed = Vec::new();
    verifying_key.serialize_compressed(&mut changed).unwrap();
    fs::write(cache.0.join("vk.bin"), &changed).unwrap();
    cache.edit_metadata("verifying_key_sha256", json!(format!("{:x}", Sha256::digest(changed))));
    cache.assert_rejected_without_changes(Mode::Default);
}
