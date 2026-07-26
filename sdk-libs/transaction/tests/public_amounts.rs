use solana_address::Address;
use zolana_interface::SOL_ASSET_FIELD;
use zolana_transaction::{
    instructions::transact::{
        signed_magnitude_to_field, signed_to_field, spp_proof_inputs::asset_field, ExternalData,
        PublicMovements, SettlementLeg, SppProofInputs,
    },
    TransactionError, SOL_MINT,
};

fn spl_leg(mint: Address, is_deposit: bool, amount: u64, seed: u8) -> SettlementLeg {
    SettlementLeg::Spl {
        mint,
        is_deposit,
        amount,
        user_spl_token: Address::new_from_array([seed; 32]),
        spl_token_interface: Address::new_from_array([seed.wrapping_add(1); 32]),
    }
}

fn sol_leg(is_deposit: bool, amount: u64, seed: u8) -> SettlementLeg {
    SettlementLeg::Sol {
        is_deposit,
        amount,
        user_sol_account: Address::new_from_array([seed; 32]),
    }
}

fn proof_inputs(public_legs: Vec<SettlementLeg>) -> SppProofInputs {
    let external_data = ExternalData::new([0; 33], [0; 16], vec![], vec![], vec![])
        .with_public_legs(public_legs)
        .unwrap();
    SppProofInputs::new(vec![], vec![], external_data, Address::default())
}

#[test]
fn zero_public_movements_match_the_field_encoding_of_zero() {
    let default = PublicMovements::default();
    for amount in default.amounts {
        assert_eq!(amount, signed_to_field(0));
    }
    for asset in default.assets {
        assert_eq!(asset, [0u8; 32]);
    }
}

#[test]
fn more_than_five_same_asset_legs_accumulate_into_one_slot() {
    let legs = (1..=12).map(|seed| sol_leg(false, 1, seed)).collect();
    let movements = proof_inputs(legs).public_movements().unwrap();

    assert_eq!(movements.assets, [SOL_ASSET_FIELD, [0; 32], [0; 32]]);
    assert_eq!(movements.amounts, [signed_to_field(-12), [0; 32], [0; 32]]);
}

#[test]
fn three_distinct_assets_fill_slots_in_first_appearance_order() {
    let first = Address::new_from_array([21; 32]);
    let second = Address::new_from_array([22; 32]);
    let movements = proof_inputs(vec![
        spl_leg(first, true, 4, 1),
        sol_leg(false, 2, 2),
        spl_leg(second, true, 9, 3),
    ])
    .public_movements()
    .unwrap();

    assert_eq!(
        movements.assets,
        [
            asset_field(&first).unwrap(),
            SOL_ASSET_FIELD,
            asset_field(&second).unwrap()
        ]
    );
    assert_eq!(
        movements.amounts,
        [signed_to_field(4), signed_to_field(-2), signed_to_field(9)]
    );
    assert_eq!(
        movements.interleaved(),
        [
            asset_field(&first).unwrap(),
            signed_to_field(4),
            SOL_ASSET_FIELD,
            signed_to_field(-2),
            asset_field(&second).unwrap(),
            signed_to_field(9),
        ]
    );
}

#[test]
fn four_active_assets_are_rejected() {
    let legs = vec![
        sol_leg(true, 1, 1),
        spl_leg(Address::new_from_array([31; 32]), true, 2, 2),
        spl_leg(Address::new_from_array([32; 32]), true, 3, 3),
        spl_leg(Address::new_from_array([33; 32]), true, 4, 4),
    ];

    assert_eq!(
        proof_inputs(legs).public_movements(),
        Err(TransactionError::TooManyPublicAssets { got: 4, max: 3 })
    );
}

#[test]
fn mixed_directions_cancel_before_active_asset_limit() {
    let cancelled = Address::new_from_array([41; 32]);
    let active = Address::new_from_array([42; 32]);
    let movements = proof_inputs(vec![
        spl_leg(cancelled, true, u64::MAX, 1),
        spl_leg(active, true, 7, 2),
        spl_leg(cancelled, false, u64::MAX, 3),
        sol_leg(false, 5, 4),
    ])
    .public_movements()
    .unwrap();

    assert_eq!(
        movements.assets,
        [asset_field(&active).unwrap(), SOL_ASSET_FIELD, [0; 32]]
    );
    assert_eq!(
        movements.amounts,
        [signed_to_field(7), signed_to_field(-5), [0; 32]]
    );
}

#[test]
fn same_asset_sum_overflow_is_rejected() {
    let mint = Address::new_from_array([51; 32]);
    let inputs = proof_inputs(vec![
        spl_leg(mint, true, u64::MAX, 1),
        spl_leg(mint, true, 1, 2),
    ]);
    assert_eq!(
        inputs.public_movements(),
        Err(TransactionError::PublicMovementOverflow { asset: mint })
    );
}

#[test]
fn transient_sum_above_u64_can_cancel_back_into_range() {
    let mint = Address::new_from_array([52; 32]);
    let movements = proof_inputs(vec![
        spl_leg(mint, true, u64::MAX, 1),
        spl_leg(mint, true, u64::MAX, 2),
        spl_leg(mint, false, u64::MAX, 3),
    ])
    .public_movements()
    .expect("only the final aggregate magnitude is range checked");

    assert_eq!(
        movements.amounts.first().copied(),
        Some(signed_magnitude_to_field(true, u64::MAX))
    );
}

#[test]
fn full_u64_magnitude_is_encoded_for_each_direction() {
    let deposit = proof_inputs(vec![sol_leg(true, u64::MAX, 1)])
        .public_movements()
        .unwrap();
    let withdrawal = proof_inputs(vec![sol_leg(false, u64::MAX, 1)])
        .public_movements()
        .unwrap();

    assert_eq!(
        deposit.amounts.first().copied(),
        Some(signed_magnitude_to_field(true, u64::MAX))
    );
    assert_eq!(
        withdrawal.amounts.first().copied(),
        Some(signed_magnitude_to_field(false, u64::MAX))
    );
}

#[test]
fn raw_external_data_rejects_zero_and_wire_count_overflow() {
    let base = || ExternalData::new([0; 33], [0; 16], vec![], vec![], vec![]);
    assert_eq!(
        base().with_public_legs(vec![sol_leg(true, 0, 1)]),
        Err(TransactionError::ZeroPublicLegAmount)
    );
    assert!(base()
        .with_public_legs(vec![
            sol_leg(true, 1, 1);
            zolana_interface::MAX_WIRE_PUBLIC_LEGS
        ])
        .is_ok());
    assert_eq!(
        base().with_public_legs(vec![
            sol_leg(true, 1, 1);
            zolana_interface::MAX_WIRE_PUBLIC_LEGS + 1
        ]),
        Err(TransactionError::TooManyPublicLegs {
            got: zolana_interface::MAX_WIRE_PUBLIC_LEGS + 1,
            max: zolana_interface::MAX_WIRE_PUBLIC_LEGS,
        })
    );
    assert_eq!(
        base().with_public_legs(vec![spl_leg(SOL_MINT, true, 1, 1)]),
        Err(TransactionError::SettlementTargetMismatch { asset: SOL_MINT })
    );
    assert_eq!(SOL_MINT, Address::default());
}
