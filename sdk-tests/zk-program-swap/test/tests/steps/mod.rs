pub(crate) mod cancel;
pub(crate) mod create;
mod deposit;
mod failures;
pub(crate) mod fill;
pub(crate) mod fill_verifiable_encryption;

/// Assert a transaction failed with the given custom program error, by code (e.g.
/// `8005`) or its hex form (e.g. `0x1f45`), as the validator surfaces it.
#[track_caller]
pub(crate) fn assert_custom_error(error: &anyhow::Error, code: u32) {
    let message = error.to_string().to_lowercase();
    let hex = format!("0x{code:x}");
    assert!(
        message.contains(&code.to_string()) || message.contains(&hex),
        "expected custom program error {code} ({hex}), got: {message}"
    );
}
