//! Self-contained gates for the custom-ring verifying key and the auditor
//! encryption. The folded prove and verify round trip lives in the Go
//! `prover/custom_ring` suite. Rust and Go public-input parity is pinned by
//! `go_vectors.rs` and `go_policy_vectors.rs`.

use custom_ring_interface::verifying_key::VERIFYINGKEY;
use custom_ring_sdk::AuditorMessage;
use zolana_keypair::ViewingKey;

/// The `go_vectors.rs` fixture, also the Go circuit test's (scalars 0x11 / 0x22
/// / 0x33).
const TX_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
const EPH_SK: &str = "01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d";
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

fn hex_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let decoded = hex::decode(hex_str).expect("valid hex");
    <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
}

fn viewing_key(hex_str: &str) -> ViewingKey {
    ViewingKey::from_bytes(&hex_bytes::<32>(hex_str)).expect("valid P-256 scalar")
}

fn fixture_ciphertext() -> [u8; 32] {
    hex_bytes::<32>("6de7c18c3c3676ca517647a25df33a7150ace3e07b410bc296fac11b1355382b")
}

/// One public input plus the emulated-P256 gadget's BSB22 commitment, `vk_ic`
/// carries `public_inputs + 2`.
#[test]
fn the_committed_verifying_key_carries_a_bsb22_commitment() {
    assert_eq!(VERIFYINGKEY.nr_pubinputs, 1);
    assert!(VERIFYINGKEY.vk_commitment.is_some());
    assert_eq!(VERIFYINGKEY.vk_ic.len(), 3);
}

/// The auditor recovers the viewing scalar byte for byte, a reduced recovery
/// would decrypt nothing.
#[test]
fn the_auditor_recovers_the_exact_scalar() {
    let recovered = AuditorMessage::new(viewing_key(EPH_SK).pubkey(), fixture_ciphertext())
        .decrypt(&viewing_key(AUDITOR_SK))
        .expect("auditor decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));
}
