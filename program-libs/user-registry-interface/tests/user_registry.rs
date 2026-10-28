use solana_pubkey::Pubkey;
use spr_user_registry_interface::USER_REGISTRY_PROGRAM_ID;

#[test]
fn program_id_matches_known_base58() {
    assert_eq!(
        Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID).to_string(),
        "regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ"
    );
}
