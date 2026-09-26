use pinocchio::Address;
use timelock_escrow_program::instructions::{escrow, withdraw};

#[test]
fn escrow_change_goes_to_the_creator_and_the_escrow_utxo_to_the_authority() {
    let creator = Address::new_from_array([1u8; 32]);
    let authority = Address::new_from_array([2u8; 32]);

    assert_eq!(
        escrow::owner_tags(&creator, &authority),
        [[1u8; 32], [2u8; 32]]
    );
}

#[test]
fn withdraw_pays_the_creator() {
    let creator = Address::new_from_array([3u8; 32]);

    assert_eq!(withdraw::owner_tags(&creator), [[3u8; 32]]);
}
