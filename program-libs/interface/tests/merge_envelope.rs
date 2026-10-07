use proptest::prelude::*;
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::merge_transact::MERGE_CIPHERTEXT_LEN,
    merge_utils::merge_envelope_public_elements,
};

fn hex32(hex_str: &str) -> [u8; 32] {
    let bytes: Vec<u8> = hex_str
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                .expect("valid hex")
        })
        .collect();
    <[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes")
}

fn point(prefix: u8, start: u8) -> [u8; 33] {
    core::array::from_fn(|index| match index {
        0 => prefix,
        _ => start + (index - 1) as u8,
    })
}

fn ciphertext(start: u8) -> [u8; MERGE_CIPHERTEXT_LEN] {
    core::array::from_fn(|index| start + index as u8)
}

#[test]
fn packs_the_envelope_into_the_four_hand_computed_elements() {
    let recipient = point(0x02, 0x10);
    let ephemeral = point(0x03, 0x50);
    let ciphertext = ciphertext(0x80);

    let elements = merge_envelope_public_elements(&recipient, &ephemeral, &ciphertext).unwrap();

    assert_eq!(
        elements,
        [
            hex32("0002101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d"),
            hex32("0003505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d"),
            hex32("002e2f6e6f808182838485868788898a8b8c8d8e8f909192939495969798999a"),
            hex32("000000000000000000000000000000000000009b9c9d9e9fa0a1a2a3a4a5a6a7"),
        ]
    );
}

#[test]
fn the_sec1_parity_reaches_the_low_element() {
    let ciphertext = ciphertext(0);
    let even =
        merge_envelope_public_elements(&point(0x02, 1), &point(0x02, 1), &ciphertext).unwrap();
    let odd_recipient =
        merge_envelope_public_elements(&point(0x03, 1), &point(0x02, 1), &ciphertext).unwrap();
    let odd_ephemeral =
        merge_envelope_public_elements(&point(0x02, 1), &point(0x03, 1), &ciphertext).unwrap();
    assert_ne!(even.first(), odd_recipient.first());
    assert_eq!(even.get(1), odd_recipient.get(1));
    assert_eq!(even.first(), odd_ephemeral.first());
    assert_ne!(even.get(1), odd_ephemeral.get(1));
}

#[test]
fn rejects_a_recipient_or_ephemeral_without_a_compressed_prefix() {
    let ciphertext = ciphertext(0);
    for prefix in [0x00, 0x01, 0x04, 0x06, 0x07, 0xff] {
        assert_eq!(
            merge_envelope_public_elements(&point(prefix, 1), &point(0x02, 1), &ciphertext),
            Err(ShieldedPoolError::InvalidViewingKeyEncoding),
            "recipient prefix {prefix:#04x}"
        );
        assert_eq!(
            merge_envelope_public_elements(&point(0x03, 1), &point(prefix, 1), &ciphertext),
            Err(ShieldedPoolError::InvalidEphemeralKeyEncoding),
            "ephemeral prefix {prefix:#04x}"
        );
    }
}

proptest! {
    #[test]
    fn every_element_is_a_canonical_field_element(
        recipient_odd in any::<bool>(),
        ephemeral_odd in any::<bool>(),
        recipient_x in any::<[u8; 32]>(),
        ephemeral_x in any::<[u8; 32]>(),
        ciphertext in any::<[u8; MERGE_CIPHERTEXT_LEN]>(),
    ) {
        let compress = |odd: bool, x: [u8; 32]| {
            let mut bytes = [0u8; 33];
            let (head, tail) = bytes.split_at_mut(1);
            head.fill(0x02 | u8::from(odd));
            tail.copy_from_slice(&x);
            bytes
        };
        let elements = merge_envelope_public_elements(
            &compress(recipient_odd, recipient_x),
            &compress(ephemeral_odd, ephemeral_x),
            &ciphertext,
        )
        .unwrap();
        for element in &elements {
            prop_assert_eq!(element.first(), Some(&0));
            prop_assert!(is_canonical_bn254_scalar_be(element));
        }
    }
}
