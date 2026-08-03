//! `update_ring_config_owner` unit tests, moved out of the program crate
//! (`ring_config/update_owner.rs`): the new authority is read only from the
//! signer account, legacy owner payloads are rejected, and an unsigned new
//! owner is rejected.

use bytemuck::bytes_of;
use pinocchio::error::ProgramError;
use shielded_pool_program::testing::{load_ring_config, process_update_ring_config_owner};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    error::ShieldedPoolError,
    state::{discriminator::RING_CONFIG, RingConfig},
};

fn ring_config(authority: [u8; 32]) -> Vec<u8> {
    bytes_of(&RingConfig {
        discriminator: RING_CONFIG,
        authority: authority.into(),
        program_id: [9u8; 32].into(),
        ring_authority_transact_is_enabled: 1,
        paused: 0,
        bump: 7,
    })
    .to_vec()
}

#[test]
fn reads_new_owner_only_from_the_signer_account() {
    let mut accounts = [
        get_account_view([1; 32], [0; 32], true, false, false, vec![]),
        get_account_view(
            [2; 32],
            shielded_pool_program::ID.to_bytes(),
            false,
            true,
            false,
            ring_config([1; 32]),
        ),
        get_account_view([3; 32], [0; 32], true, false, false, vec![]),
    ];

    process_update_ring_config_owner(&mut accounts, &[]).unwrap();

    let config = load_ring_config(&accounts[1]).expect("updated config");
    assert_eq!(config.authority.to_bytes(), [3; 32]);
}

#[test]
fn rejects_legacy_owner_payload() {
    assert_eq!(
        process_update_ring_config_owner(&mut [], &[7; 32]),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidInstructionData as u32
        ))
    );
}

#[test]
fn rejects_unsigned_new_owner() {
    let mut accounts = [
        get_account_view([1; 32], [0; 32], true, false, false, vec![]),
        get_account_view(
            [2; 32],
            shielded_pool_program::ID.to_bytes(),
            false,
            true,
            false,
            ring_config([1; 32]),
        ),
        get_account_view([3; 32], [0; 32], false, false, false, vec![]),
    ];

    assert!(process_update_ring_config_owner(&mut accounts, &[]).is_err());
}
