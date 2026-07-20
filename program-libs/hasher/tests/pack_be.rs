use zolana_hasher::{
    primitives::{pack_be, pack_be_chunks, pack_be_slice},
    HasherError,
};

/// 32-byte input → [31,1] chunks, each right-aligned. (Was the `pack32` layout.)
#[test]
fn packs_32_bytes_into_two_chunks() {
    let b: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let [c0, c1] = pack_be::<32, 2>(&b);

    let expected_c0: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let expected_c1: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 32,
    ];
    assert_eq!(c0, expected_c0);
    assert_eq!(c1, expected_c1);
}

/// 33-byte input → [31,2] chunks. (Was the `pack33` layout.)
#[test]
fn packs_33_bytes_into_two_chunks() {
    let b: [u8; 33] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33,
    ];
    let [c0, c1] = pack_be::<33, 2>(&b);

    let expected_c1: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        32, 33,
    ];
    assert_eq!(&c0[1..32], &b[0..31]);
    assert_eq!(c0[0], 0);
    assert_eq!(c1, expected_c1);
}

/// 31 bytes fit in a single chunk with a zero top byte.
#[test]
fn packs_31_bytes_into_one_chunk() {
    let b = [7u8; 31];
    let [c0] = pack_be::<31, 1>(&b);
    assert_eq!(c0[0], 0);
    assert_eq!(&c0[1..32], &b[..]);
}

#[test]
fn chunk_count_boundaries() {
    assert_eq!(pack_be_chunks(1), 1);
    assert_eq!(pack_be_chunks(31), 1);
    assert_eq!(pack_be_chunks(32), 2);
    assert_eq!(pack_be_chunks(62), 2);
    assert_eq!(pack_be_chunks(63), 3);
    assert_eq!(pack_be_chunks(310), 10);
}

#[test]
fn slice_matches_const_generic() {
    let b: [u8; 33] = core::array::from_fn(|i| i as u8 + 1);
    let [c0, c1] = pack_be::<33, 2>(&b);
    let mut out = [[0u8; 32]; 4];
    let used = pack_be_slice(&b, &mut out).unwrap();
    assert_eq!(used, &[c0, c1]);
}

#[test]
fn slice_rejects_too_small_output() {
    let b = [0u8; 63]; // needs 3 chunks
    let mut out = [[0u8; 32]; 2];
    assert_eq!(
        pack_be_slice(&b, &mut out),
        Err(HasherError::InvalidInputLength(3, 2))
    );
}
