use zolana_hasher::primitives::bool_fe;

#[test]
fn true_is_field_one() {
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(bool_fe(true), expected);
}

#[test]
fn false_is_field_zero() {
    assert_eq!(bool_fe(false), [0u8; 32]);
}
