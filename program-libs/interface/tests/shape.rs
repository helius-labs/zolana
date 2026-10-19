use zolana_interface::shape::{
    owner_signer_slots, Shape, FIXED_TRANSACT_ADDRESSES, MAX_SIGNERS, MAX_TRANSACTION_ADDRESSES,
    RING_AUTHORITY_WIDTHS, SPP_SUPPORTED_SHAPES,
};

/// The width bound rests on the number of addresses one transaction can
/// carry; pin it to the agave v1 message limit so a protocol change there
/// surfaces here.
#[test]
fn max_transaction_addresses_is_the_v1_message_limit() {
    assert_eq!(
        MAX_TRANSACTION_ADDRESSES,
        usize::from(solana_message::v1::MAX_ADDRESSES)
    );
}

#[test]
fn signer_width_is_one_payer_plus_the_owner_slots_for_every_supported_shape() {
    let expected: [(Shape, usize); 47] = [
        (Shape::IN1_OUT2, 2),
        (Shape::IN1_OUT4, 2),
        (Shape::IN1_OUT8, 2),
        (Shape::IN2_OUT2, 3),
        (Shape::IN2_OUT4, 3),
        (Shape::IN1_OUT16, 2),
        (Shape::IN2_OUT8, 3),
        (Shape::IN3_OUT2, 4),
        (Shape::IN3_OUT4, 4),
        (Shape::IN2_OUT16, 3),
        (Shape::IN3_OUT8, 4),
        (Shape::IN4_OUT2, 5),
        (Shape::IN4_OUT4, 5),
        (Shape::IN4_OUT8, 5),
        (Shape::IN5_OUT2, 6),
        (Shape::IN5_OUT4, 6),
        (Shape::IN4_OUT16, 5),
        (Shape::IN5_OUT8, 6),
        (Shape::IN6_OUT2, 7),
        (Shape::IN6_OUT4, 7),
        (Shape::IN5_OUT16, 6),
        (Shape::IN6_OUT8, 7),
        (Shape::IN4_OUT32, 5),
        (Shape::IN8_OUT2, 9),
        (Shape::IN8_OUT4, 9),
        (Shape::IN8_OUT8, 9),
        (Shape::IN8_OUT16, 9),
        (Shape::IN4_OUT64, 5),
        (Shape::IN12_OUT2, 13),
        (Shape::IN12_OUT4, 13),
        (Shape::IN12_OUT8, 13),
        (Shape::IN16_OUT2, 17),
        (Shape::IN16_OUT4, 17),
        (Shape::IN16_OUT8, 17),
        (Shape::IN4_OUT146, 5),
        (Shape::IN4_OUT148, 5),
        (Shape::IN24_OUT2, 25),
        (Shape::IN24_OUT4, 25),
        (Shape::IN32_OUT2, 29),
        (Shape::IN16_OUT140, 17),
        (Shape::IN16_OUT142, 17),
        (Shape::IN40_OUT2, 21),
        (Shape::IN48_OUT2, 13),
        (Shape::IN49_OUT2, 12),
        (Shape::IN57_OUT120, 4),
        (Shape::IN57_OUT121, 4),
        (Shape::IN58_OUT121, 3),
    ];
    assert_eq!(
        expected.map(|(shape, _)| shape),
        SPP_SUPPORTED_SHAPES,
        "the supported list mirrors the Go cost order"
    );
    for (shape, width) in expected {
        assert_eq!(shape.signer_width(), width, "{shape:?}");
        assert_eq!(
            shape.signer_width(),
            owner_signer_slots(shape.n_inputs()) + 1,
            "{shape:?}"
        );
    }
}

/// Every supported shape leaves room in one transaction for the fixed
/// accounts, one nullifier PDA per input and every owner signer slot.
#[test]
fn owner_signer_slots_fit_in_one_transaction_for_every_supported_shape() {
    for shape in SPP_SUPPORTED_SHAPES {
        let n_inputs = shape.n_inputs();
        assert!(
            owner_signer_slots(n_inputs) + n_inputs + FIXED_TRANSACT_ADDRESSES
                <= MAX_TRANSACTION_ADDRESSES,
            "{shape:?}"
        );
        assert!(owner_signer_slots(n_inputs) <= n_inputs, "{shape:?}");
    }
}

#[test]
fn owner_signer_slots_is_the_input_count_until_the_address_budget_binds() {
    assert_eq!(owner_signer_slots(0), 0);
    assert_eq!(owner_signer_slots(1), 1);
    assert_eq!(owner_signer_slots(30), 30);
    assert_eq!(owner_signer_slots(31), 29);
    assert_eq!(owner_signer_slots(32), 28);
    assert_eq!(owner_signer_slots(51), 9);
    assert_eq!(owner_signer_slots(60), 0);
    assert_eq!(owner_signer_slots(61), 0);
}

#[test]
fn max_signers_is_the_widest_supported_signer_vector() {
    assert_eq!(MAX_SIGNERS, 29);
    assert_eq!(
        SPP_SUPPORTED_SHAPES
            .iter()
            .map(|shape| shape.signer_width())
            .max(),
        Some(MAX_SIGNERS)
    );
}

#[test]
fn is_supported_is_membership_in_the_supported_shapes() {
    for n_inputs in 0..=60 {
        for n_outputs in 0..=20 {
            let shape = Shape::new(n_inputs, n_outputs);
            assert_eq!(
                shape.is_supported(),
                SPP_SUPPORTED_SHAPES.contains(&shape),
                "{shape:?}"
            );
        }
    }
}

#[test]
fn ring_authority_shapes_are_square_at_the_listed_widths() {
    assert_eq!(RING_AUTHORITY_WIDTHS, [2, 4]);
    for n_inputs in 0..=8 {
        for n_outputs in 0..=8 {
            assert_eq!(
                Shape::new(n_inputs, n_outputs).is_ring_authority(),
                n_inputs == n_outputs && RING_AUTHORITY_WIDTHS.contains(&n_inputs),
                "{n_inputs}x{n_outputs}"
            );
        }
    }
}
