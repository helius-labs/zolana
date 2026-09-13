use zolana_interface::shape::{
    owner_signer_slots, Shape, FIXED_TRANSACT_ADDRESSES, MAX_SIGNERS, MAX_TRANSACTION_ADDRESSES,
    SPP_SUPPORTED_SHAPES,
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
    let expected: [(Shape, usize); 11] = [
        (Shape::IN1_OUT1, 2),
        (Shape::IN1_OUT2, 2),
        (Shape::IN2_OUT2, 3),
        (Shape::IN2_OUT3, 3),
        (Shape::IN3_OUT3, 4),
        (Shape::IN4_OUT3, 5),
        (Shape::IN4_OUT4, 5),
        (Shape::IN5_OUT3, 6),
        (Shape::IN5_OUT4, 6),
        (Shape::IN1_OUT8, 2),
        (Shape::IN36_OUT2, 25),
    ];
    assert_eq!(expected.len(), SPP_SUPPORTED_SHAPES.len());
    for (shape, width) in expected {
        assert!(SPP_SUPPORTED_SHAPES.contains(&shape), "{shape:?}");
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
    assert_eq!(owner_signer_slots(36), 24);
    assert_eq!(owner_signer_slots(60), 0);
    assert_eq!(owner_signer_slots(61), 0);
}

#[test]
fn max_signers_is_the_widest_supported_signer_vector() {
    assert_eq!(MAX_SIGNERS, 25);
    assert_eq!(
        SPP_SUPPORTED_SHAPES
            .iter()
            .map(|shape| shape.signer_width())
            .max(),
        Some(MAX_SIGNERS)
    );
}
