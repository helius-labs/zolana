use solana_pubkey::Pubkey;
use zolana_user_registry_interface::USER_REGISTRY_PROGRAM_ID;

#[test]
fn program_id_matches_known_base58() {
    assert_eq!(
        Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID).to_string(),
        "9EwHPNdsPHMt7kaUZaXDTaj92HVC8CL4Q16io4Vu87t4"
    );
}
