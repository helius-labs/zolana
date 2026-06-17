use pinocchio::{
    cpi::invoke,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError, state::SplAssetRegistry, SHIELDED_POOL_CPI_AUTHORITY,
    SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR,
};

/// Write a freshly created registry account: discriminator, mint, and the
/// assigned asset id. Refuses to touch a non-zeroed buffer.
pub struct RegistryInitParams {
    pub mint: Address,
    pub asset_id: u64,
}

impl RegistryInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?;
        if data.len() != SplAssetRegistry::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
        }
        let registry: &mut SplAssetRegistry = bytemuck::from_bytes_mut(&mut data[..]);
        registry.set(self.mint, self.asset_id);
        Ok(())
    }
}

/// Initialize the per-mint SPL token vault via the token program's
/// `InitializeAccount3`, fixing the vault authority to the shielded-pool CPI
/// authority.
pub struct SplInterfaceInitParams<'a> {
    pub token_program: &'a AccountView,
    pub vault: &'a AccountView,
    pub mint: &'a AccountView,
}

impl SplInterfaceInitParams<'_> {
    #[inline(always)]
    pub fn init(self) -> ProgramResult {
        let instruction_accounts = [
            InstructionAccount::writable(self.vault.address()),
            InstructionAccount::readonly(self.mint.address()),
        ];
        let mut instruction_data = [0u8; 33];
        instruction_data[0] = SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR;
        instruction_data[1..33].copy_from_slice(&SHIELDED_POOL_CPI_AUTHORITY);
        let instruction = InstructionView {
            program_id: self.token_program.address(),
            accounts: &instruction_accounts,
            data: &instruction_data,
        };
        invoke(&instruction, &[self.vault, self.mint])
            .map_err(|_| ProgramError::from(ShieldedPoolError::InvalidSplAssetRegistry))
    }
}
