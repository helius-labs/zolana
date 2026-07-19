use zolana_hasher::{primitives::pack_info, HasherError};

/// The merge scheme's actual info string: fits `lo` alone, `hi` stays zero.
#[test]
fn short_info_packs_into_lo() {
    let (lo, hi) = pack_info(b"TSPP/merge").unwrap();

    let mut expected_lo = [0u8; 32];
    expected_lo[0] = 10;
    expected_lo[22..32].copy_from_slice(b"TSPP/merge");

    assert_eq!(lo, expected_lo);
    assert_eq!(hi, [0u8; 32]);
}

#[test]
fn long_info_splits_across_both_limbs() {
    let info: Vec<u8> = (1..=40u8).collect();
    let (lo, hi) = pack_info(&info).unwrap();

    let mut expected_lo = [0u8; 32];
    expected_lo[0] = 40;
    expected_lo[1..32].copy_from_slice(&info[..31]);
    let mut expected_hi = [0u8; 32];
    expected_hi[23..32].copy_from_slice(&info[31..]);

    assert_eq!(lo, expected_lo);
    assert_eq!(hi, expected_hi);
}

#[test]
fn info_longer_than_62_bytes_is_rejected() {
    assert_eq!(
        pack_info(&[0u8; 63]),
        Err(HasherError::InvalidInputLength(62, 63))
    );
}
