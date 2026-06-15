//! Post-instruction checks for the protocol config account.

use solana_pubkey::Pubkey;
use zolana_interface::state::ProtocolConfig;
use zolana_program_test::ZolanaProgramTest;

/// Verify the protocol config account at `config` against the integration-test
/// expectations: the account has the canonical length, stores `authority`, and
/// holds exactly `merge_authorities` (count and per-slot value).
#[track_caller]
pub fn assert_protocol_config(
    program_test: &ZolanaProgramTest,
    config: &Pubkey,
    authority: &Pubkey,
    merge_authorities: &[[u8; 32]],
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
    assert_eq!(cfg.authority, authority.to_bytes(), "config authority");
    assert_eq!(
        cfg.merge_authority_count,
        merge_authorities.len() as u64,
        "merge authority count"
    );
    assert_eq!(
        cfg.active_merge_authorities(),
        merge_authorities,
        "merge authorities"
    );
}
