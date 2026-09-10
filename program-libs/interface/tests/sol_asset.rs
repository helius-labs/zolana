use zolana_hasher::{primitives::hash_bytes, Hasher, Poseidon};
use zolana_interface::SOL_ASSET_FIELD;

#[test]
fn sol_asset_field_is_pk_field_of_zero_address() {
    let zero = [0u8; 32];
    let expected = Poseidon::hashv(&[&zero[..], &zero[..]]).unwrap();
    assert_eq!(SOL_ASSET_FIELD, expected);
}

#[test]
fn sol_asset_field_is_hash_bytes_of_the_zero_asset() {
    assert_eq!(SOL_ASSET_FIELD, hash_bytes(&[0u8; 32]).unwrap());
}
