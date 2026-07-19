use zolana_hasher::{
    primitives::{right_align, right_align_slice},
    HasherError,
};

#[test]
fn aligns_bytes_into_the_low_end() {
    let mut expected = [0u8; 32];
    expected[29] = 1;
    expected[30] = 2;
    expected[31] = 3;
    assert_eq!(right_align(&[1u8, 2, 3]), expected);
    assert_eq!(right_align_slice(&[1u8, 2, 3]).unwrap(), expected);
}

#[test]
fn full_width_input_is_identity() {
    let mut input = [0u8; 32];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    assert_eq!(right_align(&input), input);
    assert_eq!(right_align_slice(&input).unwrap(), input);
}

#[test]
fn empty_input_is_zero() {
    assert_eq!(right_align(&[]), [0u8; 32]);
    assert_eq!(right_align_slice(&[]).unwrap(), [0u8; 32]);
}

#[test]
fn slice_longer_than_32_bytes_is_rejected() {
    assert_eq!(
        right_align_slice(&[0u8; 33]),
        Err(HasherError::InvalidInputLength(32, 33))
    );
}
