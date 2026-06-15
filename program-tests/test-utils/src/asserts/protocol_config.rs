//! Post-instruction checks for the protocol config account.

use solana_pubkey::Pubkey;
use zolana_interface::state::{
    CONFIG_AUTHORITY_END, CONFIG_AUTHORITY_OFFSET, PROTOCOL_CONFIG_ACCOUNT_LEN,
    PROTOCOL_CONFIG_MERGE_AUTHORITIES_OFFSET, PROTOCOL_CONFIG_MERGE_AUTHORITY_COUNT_OFFSET,
};
use zolana_program_test::ZolanaProgramTest;

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

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
    let data = program_test.account_data(config).expect("config PDA exists");
    assert_eq!(
        data.len(),
        PROTOCOL_CONFIG_ACCOUNT_LEN,
        "protocol config account length"
    );
    assert_eq!(
        &data[CONFIG_AUTHORITY_OFFSET..CONFIG_AUTHORITY_END],
        authority.as_ref(),
        "config authority"
    );
    assert_eq!(
        read_u64(&data, PROTOCOL_CONFIG_MERGE_AUTHORITY_COUNT_OFFSET),
        merge_authorities.len() as u64,
        "merge authority count"
    );
    for (i, expected) in merge_authorities.iter().enumerate() {
        let offset = PROTOCOL_CONFIG_MERGE_AUTHORITIES_OFFSET + i * 32;
        assert_eq!(&data[offset..offset + 32], expected, "merge authority {i}");
    }
}
