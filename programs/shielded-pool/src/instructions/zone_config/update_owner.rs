use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::error::ShieldedPoolError;

use crate::instructions::zone_config::loader::load_and_validate_zone_authority_mut;

pub fn process_update_zone_config_owner(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("zone_config")?;
    let new_authority = iter.next_signer("new_authority")?;

    let mut current = load_and_validate_zone_authority_mut(config, authority)?;
    current.authority = new_authority.address().into();
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytemuck::bytes_of;
    use pinocchio::error::ProgramError;
    use zolana_account_checks::account_info::test_account_info::get_account_view;
    use zolana_interface::state::{discriminator::ZONE_CONFIG, ZoneConfig};

    use super::*;

    fn zone_config(authority: [u8; 32]) -> Vec<u8> {
        bytes_of(&ZoneConfig {
            discriminator: ZONE_CONFIG,
            authority: authority.into(),
            program_id: [9u8; 32].into(),
            zone_authority_transact_is_enabled: 1,
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
                crate::ID.to_bytes(),
                false,
                true,
                false,
                zone_config([1; 32]),
            ),
            get_account_view([3; 32], [0; 32], true, false, false, vec![]),
        ];

        process_update_zone_config_owner(&mut accounts, &[]).unwrap();

        let config = crate::instructions::zone_config::loader::load_zone_config(&accounts[1])
            .expect("updated config");
        assert_eq!(config.authority.to_bytes(), [3; 32]);
    }

    #[test]
    fn rejects_legacy_owner_payload() {
        assert_eq!(
            process_update_zone_config_owner(&mut [], &[7; 32]),
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
                crate::ID.to_bytes(),
                false,
                true,
                false,
                zone_config([1; 32]),
            ),
            get_account_view([3; 32], [0; 32], false, false, false, vec![]),
        ];

        assert!(process_update_zone_config_owner(&mut accounts, &[]).is_err());
    }
}
