//! Post-instruction checks for the protocol config account.

use solana_pubkey::Pubkey;
use zolana_interface::state::ProtocolConfig;
use zolana_program_test::ZolanaProgramTest;

/// Verify the protocol config account at `config`: canonical length, every role
/// authority equals `authority`, the merge authority equals `merge_authority`,
/// and both permissionless flags are off.
#[track_caller]
pub fn litesvm_assert_protocol_config(
    program_test: &ZolanaProgramTest,
    config: &Pubkey,
    authority: &Pubkey,
    merge_authority: &[u8; 32],
) {
    let data = program_test
        .account_data(config)
        .expect("config PDA exists");
    assert_eq!(
        data.len(),
        ProtocolConfig::SIZE,
        "protocol config account length"
    );
    let cfg: &ProtocolConfig = bytemuck::from_bytes(&data);
    assert_eq!(
        cfg.protocol_authority.to_bytes(),
        authority.to_bytes(),
        "protocol authority"
    );
    assert_eq!(
        cfg.tree_creation_authority.to_bytes(),
        authority.to_bytes(),
        "tree creation authority"
    );
    assert_eq!(
        cfg.forester_authority.to_bytes(),
        authority.to_bytes(),
        "forester authority"
    );
    assert_eq!(
        cfg.zone_creation_authority.to_bytes(),
        authority.to_bytes(),
        "zone creation authority"
    );
    assert_eq!(
        cfg.merge_authority.to_bytes(),
        *merge_authority,
        "merge authority"
    );
    assert_eq!(
        cfg.tree_creation_is_permissionless, 0,
        "tree creation permissionless"
    );
    assert_eq!(
        cfg.zone_creation_is_permissionless, 0,
        "zone creation permissionless"
    );
}
