use spr_hasher::state_discriminator;

/// Pinned to `sha256(b"account:" || name)[..8]` computed outside this crate
/// (Python `hashlib`), so a change to the prefix or the truncation fails here.
#[test]
fn state_discriminator_is_truncated_sha256_of_account_prefixed_name() {
    assert_eq!(
        state_discriminator("CompressedAccount").unwrap(),
        [0xf6, 0x7e, 0x92, 0x05, 0xe1, 0xcf, 0x81, 0x63]
    );
    assert_eq!(
        state_discriminator("").unwrap(),
        [0xcc, 0xf1, 0xf0, 0xfb, 0x14, 0xc5, 0xc3, 0x12]
    );
}

/// Anchor's account discriminator for the same name, so a state read by an
/// Anchor client decodes: the documented vector
/// (https://www.anchor-lang.com/docs/basics/idl#discriminators) and a name
/// whose case Anchor keeps as written.
#[test]
fn state_discriminator_matches_anchor_account_discriminators() {
    assert_eq!(
        state_discriminator("NewAccount").unwrap(),
        [176, 95, 4, 118, 91, 177, 125, 232]
    );
    assert_eq!(
        state_discriminator("HTTPState").unwrap(),
        [197, 97, 21, 78, 185, 99, 45, 90]
    );
}
