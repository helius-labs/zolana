use zolana_hasher::primitives::right_align;

#[test]
fn right_aligns_fixed_size_values() {
    assert_eq!(right_align(&[]), [0u8; 32]);

    let encoded = right_align(&[1u8, 2, 3]);
    assert_eq!(&encoded[..29], &[0u8; 29]);
    assert_eq!(&encoded[29..], &[1, 2, 3]);
}
