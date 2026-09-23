use custom_ring_interface::KeyEscrow;
use pinocchio::{error::ProgramError, Address};
use zolana_account_checks::AccountIterator;

use crate::{error::CustomRingError, instructions::loader::load_key_registry_root};

/// The registry root a statement binds, `None` with escrow off.
pub(crate) struct EscrowRoot<'a> {
    pub program_id: &'a Address,
    pub escrow: KeyEscrow,
    pub index: u8,
}

impl EscrowRoot<'_> {
    pub fn load(
        self,
        accounts: &mut AccountIterator<'_>,
    ) -> Result<Option<[u8; 32]>, ProgramError> {
        match self.escrow {
            KeyEscrow::Off if self.index != 0 => {
                Err(CustomRingError::InvalidInstructionData.into())
            }
            KeyEscrow::Off => Ok(None),
            KeyEscrow::Registry => {
                let account = accounts.next_account("key_registry_root")?;
                load_key_registry_root(self.program_id, account)?
                    .root_at(self.index)
                    .map(Some)
                    .ok_or_else(|| CustomRingError::StaleKeyRegistryRoot.into())
            }
        }
    }
}
