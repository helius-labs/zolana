use pinocchio::Address;
use rings_user_registry_interface::{USER_RECORD_SEED, USER_REGISTRY_PROGRAM_ID};

#[test]
fn stored_bump_derivation_matches_canonical_search() {
    let program_id = Address::new_from_array(USER_REGISTRY_PROGRAM_ID);
    for owner in [[0u8; 32], [7u8; 32], [0xFFu8; 32]] {
        let (expected, bump) =
            Address::find_program_address(&[USER_RECORD_SEED, &owner], &program_id);
        let derived = Address::derive_address(
            &[USER_RECORD_SEED, owner.as_slice()],
            Some(bump),
            &program_id,
        );
        assert_eq!(derived, expected);
    }
}
