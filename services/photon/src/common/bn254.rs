pub const BN254_FIELD_SIZE_MINUS_ONE_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

pub fn is_bn254_field_element(bytes: &[u8; 32]) -> bool {
    bytes <= &BN254_FIELD_SIZE_MINUS_ONE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn increment_big_endian(bytes: &mut [u8; 32]) {
        for byte in bytes.iter_mut().rev() {
            if *byte < u8::MAX {
                *byte += 1;
                break;
            }
            *byte = 0;
        }
    }

    #[test]
    fn bn254_field_size_minus_one_matches_canonical_decimal() {
        let field_size_minus_one = BigUint::from_bytes_be(&BN254_FIELD_SIZE_MINUS_ONE_BYTES);

        assert_eq!(
            field_size_minus_one.to_str_radix(10),
            "21888242871839275222246405745257275088548364400416034343698204186575808495616"
        );
    }

    #[test]
    fn bn254_field_range_accepts_max_and_rejects_modulus() {
        assert!(is_bn254_field_element(&BN254_FIELD_SIZE_MINUS_ONE_BYTES));

        let mut modulus = BN254_FIELD_SIZE_MINUS_ONE_BYTES;
        increment_big_endian(&mut modulus);
        assert!(!is_bn254_field_element(&modulus));
    }
}
