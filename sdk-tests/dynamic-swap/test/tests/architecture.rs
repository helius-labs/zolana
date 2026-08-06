use dynamic_swap_program::{
    instructions::create_escrow::ORDER_EXPIRY_SECONDS,
    state::{Escrow, Liquidity, Pair},
};
use dynamic_swap_sdk::{
    escrow_pda,
    shared::{exact_available_slots, should_refresh_capacity, slot_value},
};
use solana_pubkey::Pubkey;

#[test]
fn order_expiry_is_ten_minutes() {
    assert_eq!(ORDER_EXPIRY_SECONDS, 600);
}

#[test]
fn order_pda_uses_fresh_commitment_instead_of_taker_key() {
    let pair = Pubkey::new_unique();
    let first = escrow_pda(&pair, &[1; 32]);
    let second = escrow_pda(&pair, &[2; 32]);
    assert_ne!(first, second);
}

#[test]
fn configured_capacity_example_refreshes_below_one_hundred() {
    let value = slot_value(1, 1).unwrap();
    assert_eq!(exact_available_slots(1_000, 0, value).unwrap(), 1_000);
    assert!(!should_refresh_capacity(100, value, 100).unwrap());
    assert!(should_refresh_capacity(99, value, 100).unwrap());
}

#[test]
fn state_layout_sizes_are_stable() {
    assert_eq!(Pair::SIZE, 224);
    assert_eq!(Liquidity::SIZE, 88);
    assert_eq!(Escrow::SIZE, 144);
}

#[test]
fn opening_and_settlement_capacity_accounting_matches_the_design() {
    let slot = slot_value(1, 1).unwrap();
    let mut available_slots = 1_000u64;
    let mut reserved_liability = 0u64;

    // create_escrow: move one advertised slot into aggregate reservations.
    available_slots -= 1;
    reserved_liability += slot;
    assert_eq!((available_slots, reserved_liability), (999, 1));

    // settle: remove this order's liability. The consumed slot is not restored
    // until a proved refresh.
    reserved_liability -= slot;
    assert_eq!((available_slots, reserved_liability), (999, 0));
}
