use timelock_escrow_program::ESCROW_OWNER_HASH;
use timelock_escrow_sdk::escrow_authority;

#[test]
fn escrow_owner_hash_is_the_escrow_authority_owner_hash() {
    assert_eq!(
        ESCROW_OWNER_HASH,
        escrow_authority().owner_hash().expect("escrow owner hash")
    );
}
