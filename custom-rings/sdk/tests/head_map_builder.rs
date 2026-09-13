use custom_ring_sdk::{tag, CreateHeadMapRoot, CustomRing};
use solana_address::Address;
use solana_instruction::AccountMeta;

#[test]
fn shared_root_creation_uses_config_authority_and_one_writable_pda() {
    let ring = CustomRing::new(Address::new_from_array([17; 32]));
    let payer = Address::new_from_array([18; 32]);
    let authority = Address::new_from_array([19; 32]);
    let instruction = CreateHeadMapRoot {
        ring,
        payer,
        authority,
    }
    .instruction();
    assert_eq!(instruction.program_id, ring.program_id());
    assert_eq!(instruction.data, vec![tag::CREATE_HEAD_MAP_ROOT]);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.head_map_root_pda(), false),
            AccountMeta::new_readonly(Address::default(), false),
        ]
    );
}
