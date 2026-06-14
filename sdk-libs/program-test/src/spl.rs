use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateSplInterfaceData},
    SPL_ASSET_COUNTER_PDA_SEED, SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED,
    SPL_TOKEN_ACCOUNT_AMOUNT_END, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET, SPL_TOKEN_ACCOUNT_LEN,
    SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR, SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR,
    SPL_TOKEN_MINT_ACCOUNT_LEN, SPL_TOKEN_MINT_TO_DISCRIMINATOR, SPL_TOKEN_PROGRAM_ID,
};

use crate::{instructions::system_create_account_ix, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
    pub fn token_program_id() -> Pubkey {
        Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
    }

    pub fn spl_asset_counter_pda(&self) -> Pubkey {
        Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id).0
    }

    pub fn spl_asset_registry_pda(&self, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()],
            &self.program_id,
        )
        .0
    }

    pub fn spl_asset_vault_pda(&self, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[SPL_ASSET_VAULT_PDA_SEED, mint.as_ref()], &self.program_id).0
    }

    pub fn create_mint(&mut self) -> Result<Pubkey, ProgramTestError> {
        let mint = Keypair::new();
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(SPL_TOKEN_MINT_ACCOUNT_LEN);
        let create_ix = system_create_account_ix(
            &self.payer.pubkey(),
            &mint.pubkey(),
            rent,
            SPL_TOKEN_MINT_ACCOUNT_LEN as u64,
            &Self::token_program_id(),
        );
        let mut data = vec![SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, 9];
        data.extend_from_slice(&self.payer.pubkey().to_bytes());
        data.push(0);
        let init_ix = Instruction {
            program_id: Self::token_program_id(),
            accounts: vec![AccountMeta::new(mint.pubkey(), false)],
            data,
        };
        self.send(&[create_ix, init_ix], &[&mint])?;
        Ok(mint.pubkey())
    }

    pub fn create_token_account(
        &mut self,
        mint: &Pubkey,
        owner: &Pubkey,
    ) -> Result<Pubkey, ProgramTestError> {
        let account = Keypair::new();
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(SPL_TOKEN_ACCOUNT_LEN);
        let create_ix = system_create_account_ix(
            &self.payer.pubkey(),
            &account.pubkey(),
            rent,
            SPL_TOKEN_ACCOUNT_LEN as u64,
            &Self::token_program_id(),
        );
        let mut data = vec![SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR];
        data.extend_from_slice(&owner.to_bytes());
        let init_ix = Instruction {
            program_id: Self::token_program_id(),
            accounts: vec![
                AccountMeta::new(account.pubkey(), false),
                AccountMeta::new_readonly(*mint, false),
            ],
            data,
        };
        self.send(&[create_ix, init_ix], &[&account])?;
        Ok(account.pubkey())
    }

    pub fn mint_to(
        &mut self,
        mint: &Pubkey,
        account: &Pubkey,
        amount: u64,
    ) -> Result<(), ProgramTestError> {
        let mut data = vec![SPL_TOKEN_MINT_TO_DISCRIMINATOR];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: Self::token_program_id(),
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(self.payer.pubkey(), true),
            ],
            data,
        };
        self.send(&[ix], &[])
    }

    pub fn token_balance(&self, account: &Pubkey) -> Option<u64> {
        let data = self.account_data(account)?;
        let bytes = data
            .get(SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET..SPL_TOKEN_ACCOUNT_AMOUNT_END)?
            .try_into()
            .ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    pub fn create_spl_interface(
        &mut self,
        authority: &Keypair,
        mint: &Pubkey,
    ) -> Result<(Pubkey, Pubkey), ProgramTestError> {
        let registry = self.spl_asset_registry_pda(mint);
        let vault = self.spl_asset_vault_pda(mint);
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config_pda(), false),
                AccountMeta::new(self.spl_asset_counter_pda(), false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(self.cpi_authority(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(Self::token_program_id(), false),
            ],
            data: encode_instruction(tag::CREATE_SPL_INTERFACE, &CreateSplInterfaceData),
        };
        self.send(&[ix], &[authority])?;
        Ok((registry, vault))
    }
}
