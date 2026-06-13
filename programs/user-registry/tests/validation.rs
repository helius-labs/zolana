use zolana_interface::user_registry::state::P256_PUBKEY_LEN;
use zolana_user_registry::{
    constants::BN254_FR_MODULUS,
    validation::{validate_canonical_nullifier_pubkey, validate_p256_pubkey},
};

#[test]
fn rejects_invalid_p256_prefixes() {
    for prefix in [0x00u8, 0x01, 0x04, 0x05, 0xFF] {
        let mut key = [0u8; P256_PUBKEY_LEN];
        key[0] = prefix;
        assert!(
            validate_p256_pubkey(&key).is_err(),
            "prefix {prefix:#04x} must be rejected"
        );
    }
    for prefix in [0x02u8, 0x03] {
        let mut key = [0u8; P256_PUBKEY_LEN];
        key[0] = prefix;
        assert!(
            validate_p256_pubkey(&key).is_ok(),
            "prefix {prefix:#04x} must be accepted"
        );
    }
}

#[test]
fn rejects_nullifier_at_field_modulus() {
    let mut at_modulus = BN254_FR_MODULUS;
    assert!(validate_canonical_nullifier_pubkey(&at_modulus).is_err());
    at_modulus[31] = 0;
    assert!(validate_canonical_nullifier_pubkey(&at_modulus).is_ok());
}
