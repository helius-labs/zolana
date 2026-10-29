//! Compatibility checks use the gnark artifact; downloads retain both formats.
use serde_json::Value;
use spr_client::{
    prover::{ProverKeyStatus, ProverKeys, ProvingKeyFormat},
    ClientError,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/proving_key_catalog.json"
    ))
    .unwrap()
}

fn matching_prover() -> ProverKeys {
    serde_json::from_value(vectors()["catalog"].clone()).unwrap()
}

fn status_mut<'a>(prover: &'a mut ProverKeys, name: &str) -> &'a mut ProverKeyStatus {
    prover.keys.iter_mut().find(|key| key.name == name).unwrap()
}

#[test]
fn shared_catalog_preserves_both_download_formats() {
    let prover = matching_prover();
    let report = prover.check().expect("matching keys");
    assert_eq!(report.keys, prover.keys);
    let artifacts = &report.keys[1].artifacts;
    assert_eq!(artifacts[0].format, ProvingKeyFormat::Gnark);
    assert_eq!(artifacts[1].format, ProvingKeyFormat::Zopro);
    assert_ne!(artifacts[0].sha256, artifacts[1].sha256);
    assert_ne!(artifacts[0].url, artifacts[1].url);
}

#[test]
fn every_mismatching_gnark_digest_is_named() {
    let mut prover = matching_prover();
    for key in &mut prover.keys {
        key.artifacts[0].sha256 = "ab".repeat(32);
    }
    match prover.check() {
        Err(ClientError::ProverProvingKeysMismatch { mismatches }) => {
            assert_eq!(mismatches.len(), 2);
            for key in &prover.keys {
                assert!(mismatches.iter().any(|m| m.starts_with(&key.name)));
            }
        }
        other => panic!("expected mismatch, got {other:?}"),
    }
}

#[test]
fn a_missing_key_stays_absent_and_does_not_fail() {
    let mut prover = matching_prover();
    prover.keys.remove(0);
    assert_eq!(prover.check().unwrap().keys, prover.keys);
}

#[test]
fn zopro_file_checksum_is_not_compared_to_the_gnark_pin() {
    let mut prover = matching_prover();
    status_mut(&mut prover, "transfer_confidential_2_2.key").artifacts[1].sha256 = "ab".repeat(32);
    assert!(prover.check().is_ok());
}

#[test]
fn shared_malformed_catalogs_are_rejected() {
    for case in vectors()["invalidCatalogs"].as_array().unwrap() {
        let result = serde_json::from_value::<ProverKeys>(case["catalog"].clone());
        let accepted = result.map(|keys| keys.check().is_ok()).unwrap_or(false);
        assert!(!accepted, "accepted {}", case["description"]);
    }
}
