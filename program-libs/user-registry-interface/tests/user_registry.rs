use rings_user_registry_interface::USER_REGISTRY_PROGRAM_ID;
use solana_pubkey::Pubkey;

#[test]
fn program_id_matches_known_base58() {
    assert_eq!(
        Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID).to_string(),
        "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc"
    );
}
