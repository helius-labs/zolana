use borsh::BorshDeserialize;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, instruction::UpdateProtocolConfigData};

use crate::instructions::protocol_config::loader::load_and_validate_protocol_authority_mut;

pub fn process_update_protocol_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = UpdateProtocolConfigData::try_from_slice(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_mut("protocol_config")?;

    if let UpdateProtocolConfigData::ProtocolAuthority(a) = &data {
        let new_authority = iter.next_signer("new_authority")?;
        if new_authority.address().to_bytes() != a.to_bytes() {
            return Err(ShieldedPoolError::InvalidInstructionData.into());
        }
    }

    let mut current = load_and_validate_protocol_authority_mut(protocol_config, authority)?;
    match data {
        UpdateProtocolConfigData::ProtocolAuthority(a) => current.protocol_authority = a,
        UpdateProtocolConfigData::TreeCreationAuthority(a) => current.tree_creation_authority = a,
        UpdateProtocolConfigData::ForesterAuthority(a) => current.forester_authority = a,
        UpdateProtocolConfigData::ZoneCreationAuthority(a) => current.zone_creation_authority = a,
        UpdateProtocolConfigData::MergeAuthority(a) => current.merge_authority = a,
        UpdateProtocolConfigData::TreeCreationPermissionless(b) => {
            current.tree_creation_is_permissionless = u8::from(b)
        }
        UpdateProtocolConfigData::ZoneCreationPermissionless(b) => {
            current.zone_creation_is_permissionless = u8::from(b)
        }
    }
    Ok(())
}
