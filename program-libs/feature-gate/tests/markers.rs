#![cfg(feature = "std")]

use feature_gate::{
    features, find_features, hashes_with_prefix, CircuitFeature, FeatureInfo, BEGIN, END,
};

const HASHES: [[u8; 32]; 2] = [[0x12; 32], [0xab; 32]];
const ENABLED: CircuitFeature = CircuitFeature {
    name: "example",
    enabled: true,
    proving_key_sha256s: &HASHES,
};
const DISABLED: CircuitFeature = CircuitFeature {
    enabled: false,
    ..ENABLED
};
const ENABLED_MARKER: [u8; ENABLED.encoded_len()] = ENABLED.encode();
const DISABLED_MARKER: [u8; DISABLED.encoded_len()] = DISABLED.encode();

#[test]
fn only_enabled_features_allow_their_own_keys() {
    assert_eq!(
        (
            ENABLED.allows(&[0x12; 32]),
            ENABLED.allows(&[0xab; 32]),
            ENABLED.allows(&[0x34; 32]),
            DISABLED.allows(&[0x12; 32])
        ),
        (true, true, false, false)
    );
    assert_eq!(
        features::confidential_eddsa(&HASHES).enabled,
        cfg!(feature = "confidential-eddsa")
    );
}

#[test]
fn exported_bytes_follow_the_indexer_format() {
    let expected = format!(
        "{}name\0example\0enabled\0true\0proving_key_sha256\0{}\0proving_key_sha256\0{}\0{}",
        core::str::from_utf8(BEGIN).unwrap(),
        "12".repeat(32),
        "ab".repeat(32),
        core::str::from_utf8(END).unwrap()
    );
    assert_eq!(ENABLED_MARKER.as_slice(), expected.as_bytes());
}

#[test]
fn finds_enabled_and_disabled_features_in_binary_bytes() {
    for (marker, enabled) in [(&ENABLED_MARKER[..], true), (&DISABLED_MARKER[..], false)] {
        let mut binary = b"\x7fELFprefix".to_vec();
        binary.extend_from_slice(marker);
        binary.extend_from_slice(b"suffix");
        assert_eq!(
            find_features(&binary).unwrap(),
            vec![FeatureInfo {
                name: "example".into(),
                enabled,
                proving_key_sha256s: HASHES.to_vec()
            }]
        );
    }
    assert_eq!(
        find_features(b"\x7fELF no feature metadata").unwrap(),
        Vec::new()
    );
}

#[test]
fn rejects_truncated_ambiguous_and_malformed_markers() {
    let text = core::str::from_utf8(&ENABLED_MARKER).unwrap();
    let hash = "12".repeat(32);
    let cases = [
        text.trim_end_matches('\0').to_string(),
        text.replace("enabled\0true", "enabled\0unknown"),
        text.replace("name\0example", "name\0"),
        text.replace("name\0example", "name\0BAD"),
        text.replace(&hash, "zz"),
        text.replace(&"ab".repeat(32), &hash),
        text.replace("proving_key_sha256", "unrecognized_field"),
        format!("{text}{text}"),
        format!(
            "{}name\0example\0enabled\0true\0{}",
            core::str::from_utf8(BEGIN).unwrap(),
            core::str::from_utf8(END).unwrap()
        ),
    ];
    for case in cases {
        assert!(find_features(case.as_bytes()).is_err(), "accepted {case:?}");
    }
}

#[test]
fn extracts_only_the_named_key_family_at_compile_time() {
    const SELECTED: [[u8; 32]; 2] = hashes_with_prefix(
        &[
            ("other.key", [1; 32]),
            ("example_1.key", [2; 32]),
            ("example_2.key", [3; 32]),
        ],
        "example_",
    );
    assert_eq!(SELECTED, [[2; 32], [3; 32]]);
}
