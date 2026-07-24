use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::SOL_ASSET_FIELD;

#[test]
fn sol_asset_field_is_pk_field_of_zero_address() {
    let zero = [0u8; 32];
    let expected = Poseidon::hashv(&[&zero[..], &zero[..]]).unwrap();
    assert_eq!(SOL_ASSET_FIELD, expected);
}
