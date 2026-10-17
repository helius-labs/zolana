pub mod batch_address_append_40_10;
pub mod batch_address_append_40_250;

/// Proving key file name, as in proving-keys.lock and the prover's
/// `/proving-keys`, and the sha256 its committed verifying key pins. The lock
/// names these keys with a hyphen, the modules with an underscore.
pub const PROVING_KEY_SHA256S: &[(&str, [u8; 32])] = &[
    (
        "batch_address-append_40_10.key",
        batch_address_append_40_10::VERIFYINGKEY_PROVING_KEY_SHA256,
    ),
    (
        "batch_address-append_40_250.key",
        batch_address_append_40_250::VERIFYINGKEY_PROVING_KEY_SHA256,
    ),
];
