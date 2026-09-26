use timelock_escrow_arkworks::escrow_authority;
use timelock_escrow_program::ESCROW_OWNER_HASH;

#[test]
fn escrow_owner_hash_is_the_escrow_authority_owner_hash() {
    assert_eq!(
        escrow_authority().owner_hash().expect("escrow owner hash"),
        ESCROW_OWNER_HASH
    );
}
