use serde::Deserialize;
use zolana_keypair::{random_blinding, NullifierKey};
use zolana_transaction::instructions::merge::{
    merge_dummy_nullifier, merge_output_blinding, DOMAIN_MERGE_DUMMY_NULLIFIER,
    DOMAIN_MERGE_OUTPUT_BLINDING_V1,
};

fn nullifier_key(secret_byte: u8) -> NullifierKey {
    let mut secret = [0u8; 31];
    secret[30] = secret_byte;
    NullifierKey::from_secret(secret)
}

fn field_u32(x: u32) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[28..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// The recovery domains are the ASCII tags the Go circuit uses; a drift here
/// silently breaks wallet recovery, so pin the byte values.
pub(crate) fn recovery_domains_are_the_ascii_tags() {
    assert_eq!(
        DOMAIN_MERGE_OUTPUT_BLINDING_V1,
        u32::from_be_bytes(*b"TMOB")
    );
    assert_eq!(DOMAIN_MERGE_DUMMY_NULLIFIER, u32::from_be_bytes(*b"TMDN"));
}

/// Golden vectors, pinned against the Go circuit
/// (`spp_merge/shared/derivation_test.go`). The secret is the 31-byte
/// big-endian of 42, so its right-aligned field element is `field_u32(42)`.
pub(crate) fn recovery_derivations_match_circuit_vectors() {
    let key = nullifier_key(42);
    let first_nullifier = field_u32(7);
    assert_eq!(
        hex::encode(merge_output_blinding(&key, &first_nullifier).unwrap()),
        "2f6bd14769ab9af9cdede9526bb87e83ee9ba49a41f8e2b7158b50433f541897",
    );
    assert_eq!(
        hex::encode(merge_dummy_nullifier(&key, &first_nullifier, 3).unwrap()),
        "1498da905bec363e5c1ae40faee4aca4e3ee990a9e030599797bcbda18cff914",
    );
}

#[derive(Deserialize)]
struct KeyDerivationVectors {
    merge_recovery: MergeRecovery,
}

#[derive(Deserialize)]
struct MergeRecovery {
    nullifier_secret: String,
    first_nullifier: String,
    output_blinding: String,
    dummy_slot_index: u8,
    dummy_nullifier: String,
}

/// The shared cross-language vector file must agree with the goldens above;
/// the TypeScript SDK asserts the same section, so the three implementations
/// (Rust, TS, Go circuit) cannot drift apart silently.
pub(crate) fn recovery_derivations_match_shared_vectors() {
    let vectors: KeyDerivationVectors =
        serde_json::from_str(include_str!("../../../../test-vectors/key_derivation.json")).unwrap();
    let section = vectors.merge_recovery;
    let secret: [u8; 31] = hex::decode(&section.nullifier_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let first_nullifier: [u8; 32] = hex::decode(&section.first_nullifier)
        .unwrap()
        .try_into()
        .unwrap();
    let key = NullifierKey::from_secret(secret);
    assert_eq!(
        hex::encode(merge_output_blinding(&key, &first_nullifier).unwrap()),
        section.output_blinding,
    );
    assert_eq!(
        hex::encode(
            merge_dummy_nullifier(&key, &first_nullifier, section.dummy_slot_index).unwrap()
        ),
        section.dummy_nullifier,
    );
}

/// Domain separation: the two derivations never collide, and the nullifier
/// secret, the first nullifier, and the slot index all bind.
pub(crate) fn recovery_derivations_bind_every_input() {
    let key = nullifier_key(42);
    let other_key = nullifier_key(43);
    let first_nullifier = field_u32(7);
    assert_ne!(
        merge_output_blinding(&key, &first_nullifier).unwrap(),
        merge_output_blinding(&key, &field_u32(8)).unwrap()
    );
    assert_ne!(
        merge_dummy_nullifier(&key, &first_nullifier, 3).unwrap(),
        merge_dummy_nullifier(&key, &first_nullifier, 4).unwrap()
    );
    assert_ne!(
        merge_dummy_nullifier(&key, &first_nullifier, 3).unwrap(),
        merge_dummy_nullifier(&key, &field_u32(8), 3).unwrap()
    );
    assert_ne!(
        merge_dummy_nullifier(&key, &first_nullifier, 3).unwrap(),
        merge_dummy_nullifier(&other_key, &first_nullifier, 3).unwrap()
    );
    assert_ne!(
        merge_output_blinding(&key, &first_nullifier).unwrap(),
        merge_dummy_nullifier(&key, &first_nullifier, 0).unwrap()
    );
}

/// The merged output is indexed by the first input nullifier: its blinding is
/// derived deterministically from the owner's nullifier secret and that
/// nullifier, so the owner recovers the output without a published merge view
/// tag.
pub(crate) fn recovery_derivations_are_deterministic() {
    let key = NullifierKey::from_secret(random_blinding()[1..].try_into().unwrap());
    let first_nullifier = random_blinding();
    assert_eq!(
        merge_output_blinding(&key, &first_nullifier).unwrap(),
        merge_output_blinding(&key, &first_nullifier).unwrap()
    );
    assert_eq!(
        merge_dummy_nullifier(&key, &first_nullifier, 0).unwrap(),
        merge_dummy_nullifier(&key, &first_nullifier, 0).unwrap()
    );
}
