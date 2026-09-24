//! Pins the proving-key sha256 each committed verifying key carries to
//! `proving-keys.lock`, the file the prover verifies every key it loads
//! against. A key regenerated from a stale proving key, or a lock rotated
//! without regenerating the verifying keys, fails here instead of on-chain.
//! An insecure test setup cannot slip in either: its generated file does not
//! compile without an `insecure-test-setup` feature, which this crate lacks.
#![cfg(feature = "verifying-keys")]

use std::collections::BTreeMap;

use zolana_interface::{
    verifying_keys::{Bsb22Commitment, CircuitId, RingP256ProofData, PROVING_KEY_SHA256S},
    N_PUBLIC_SLOTS,
};

const LOCK: &str = include_str!("../../../prover/server/prover/provingkeys/proving-keys.lock");

fn locked_sha256s() -> BTreeMap<String, String> {
    let lock: serde_json::Value = serde_json::from_str(LOCK).expect("proving-keys.lock is JSON");
    lock["keys"]
        .as_object()
        .expect("proving-keys.lock has a keys object")
        .iter()
        .map(|(name, entry)| {
            let sha256 = entry["sha256"].as_str().expect("lock entry has a sha256");
            (name.clone(), sha256.to_string())
        })
        .collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn proving_key_sha256s_match_lockfile() {
    let locked = locked_sha256s();
    for (name, sha256) in PROVING_KEY_SHA256S {
        let pinned = locked
            .get(*name)
            .unwrap_or_else(|| panic!("{name} is not in proving-keys.lock"));
        assert_eq!(&hex(sha256), pinned, "{name}");
    }
}

/// Every supported transfer circuit resolves to the proving-key sha256 of the
/// key file its rail and shape name, the digest a prover reports for it.
#[test]
fn circuit_proving_key_sha256_matches_its_key_file() {
    let table: BTreeMap<&str, [u8; 32]> = PROVING_KEY_SHA256S.iter().copied().collect();
    let slots = N_PUBLIC_SLOTS as u8;
    let p256 = RingP256ProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        default_owner_tag: None,
    };
    let mut checked = 0;
    for n_inputs in 1..=36u8 {
        for n_outputs in 1..=8u8 {
            for (rail, circuit) in [
                (
                    "transfer_confidential",
                    CircuitId::ConfidentialEddsa(n_inputs, n_outputs, slots),
                ),
                (
                    "transfer_ring",
                    CircuitId::RingEddsa(n_inputs, n_outputs, slots),
                ),
                (
                    "transfer_p256_ring",
                    CircuitId::RingP256(n_inputs, n_outputs, slots, p256),
                ),
                (
                    "transfer_ring_authority",
                    CircuitId::RingAuthority(n_inputs, n_outputs, slots),
                ),
            ] {
                let name = format!("{rail}_{n_inputs}_{n_outputs}.key");
                assert_eq!(
                    circuit.proving_key_sha256(),
                    table.get(name.as_str()),
                    "{name}"
                );
                assert_eq!(
                    circuit.is_supported(),
                    table.contains_key(name.as_str()),
                    "{name}"
                );
                checked += usize::from(circuit.is_supported());
            }
        }
    }
    let transfer_keys = table
        .keys()
        .filter(|name| name.starts_with("transfer_"))
        .count();
    assert_eq!(checked, transfer_keys);
}

#[test]
fn every_locked_transfer_and_merge_key_has_a_verifying_key() {
    let locked: Vec<String> = locked_sha256s()
        .into_keys()
        .filter(|name| name.starts_with("transfer_") || name.starts_with("merge_"))
        .collect();
    let committed: Vec<String> = PROVING_KEY_SHA256S
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    assert_eq!(committed, locked);
}
