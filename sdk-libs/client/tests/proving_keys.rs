//! The startup check of a prover's `GET /proving-keys` report against the
//! proving-key sha256 each committed verifying key pins.

use zolana_client::{
    prover::{known_proving_keys, ProverKeyStatus, ProverKeys, ProvingKeyCheck},
    ClientError,
};

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a prover built from this commit reports before it loads anything.
fn matching_prover() -> ProverKeys {
    ProverKeys {
        prefix: "proving-keys/test".to_string(),
        keys: known_proving_keys()
            .map(|(name, sha256)| ProverKeyStatus {
                name: name.to_string(),
                expected_sha256: Some(hex(&sha256)),
                loaded_sha256: None,
                available: true,
            })
            .collect(),
    }
}

fn status_mut<'a>(prover: &'a mut ProverKeys, name: &str) -> &'a mut ProverKeyStatus {
    prover
        .keys
        .iter_mut()
        .find(|status| status.name == name)
        .expect("key is listed")
}

#[test]
fn a_prover_on_the_same_key_set_passes() {
    let mut prover = matching_prover();
    let loaded = status_mut(&mut prover, "transfer_ring_2_2.key");
    loaded.loaded_sha256 = loaded.expected_sha256.clone();

    let report = prover.check().expect("same key set");
    let expected: Vec<ProvingKeyCheck> = known_proving_keys()
        .map(|(name, _)| ProvingKeyCheck {
            name,
            served: true,
            available: true,
            loaded: name == "transfer_ring_2_2.key",
        })
        .collect();
    assert_eq!(
        (report.prefix.as_str(), report.keys),
        ("proving-keys/test", expected)
    );
}

#[test]
fn every_mismatching_digest_is_named() {
    let mut prover = matching_prover();
    status_mut(&mut prover, "merge_8_1.key").expected_sha256 = Some("ab".repeat(32));
    status_mut(&mut prover, "batch_address-append_40_10.key").loaded_sha256 = Some("cd".repeat(32));

    match prover.check() {
        Err(ClientError::ProverProvingKeysMismatch { mismatches }) => {
            let named: Vec<bool> = [
                "batch_address-append_40_10.key loaded",
                "merge_8_1.key expected",
            ]
            .iter()
            .map(|prefix| mismatches.iter().any(|m| m.starts_with(prefix)))
            .collect();
            assert_eq!((mismatches.len(), named), (2, vec![true, true]));
        }
        other => panic!("expected ProverProvingKeysMismatch, got {other:?}"),
    }
}

/// Provers may serve a subset: a key the prover lacks or cannot load is
/// reported, not rejected.
#[test]
fn a_missing_or_unavailable_key_is_reported() {
    let mut prover = matching_prover();
    prover.keys.retain(|status| status.name != "merge_36_1.key");
    status_mut(&mut prover, "transfer_ring_36_2.key").available = false;

    let report = prover.check().expect("subset is not a mismatch");
    let find = |name: &str| {
        report
            .keys
            .iter()
            .find(|check| check.name == name)
            .cloned()
            .expect("known key is reported")
    };
    assert_eq!(
        (find("merge_36_1.key"), find("transfer_ring_36_2.key")),
        (
            ProvingKeyCheck {
                name: "merge_36_1.key",
                served: false,
                available: false,
                loaded: false,
            },
            ProvingKeyCheck {
                name: "transfer_ring_36_2.key",
                served: true,
                available: false,
                loaded: false,
            },
        )
    );
}

#[test]
fn a_malformed_digest_is_a_server_error() {
    for bad in ["zz".repeat(32), "AB".repeat(32), "ab".repeat(31)] {
        let mut prover = matching_prover();
        status_mut(&mut prover, "merge_8_1.key").expected_sha256 = Some(bad.clone());
        assert!(
            matches!(prover.check(), Err(ClientError::ProverServer(_))),
            "{bad} was accepted"
        );
    }
}
