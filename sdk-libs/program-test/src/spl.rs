use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateSplInterface},
    pda, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_ACCOUNT_AMOUNT_END, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET,
    SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR,
    SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, SPL_TOKEN_MINT_ACCOUNT_LEN,
    SPL_TOKEN_MINT_TO_DISCRIMINATOR, SPL_TOKEN_PROGRAM_ID,
};

use crate::{instructions::system_create_account_ix, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
    pub fn token_program_id() -> Pubkey {
        Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
    }

    pub fn token_2022_program_id() -> Pubkey {
        Pubkey::new_from_array(SPL_TOKEN_2022_PROGRAM_ID)
    }

    pub fn create_mint(&mut self) -> Result<Pubkey, ProgramTestError> {
        self.create_mint_with_program(Self::token_program_id())
    }

    pub fn create_mint_with_program(
        &mut self,
        token_program: Pubkey,
    ) -> Result<Pubkey, ProgramTestError> {
        self.create_mint_from(&Keypair::new(), token_program)
    }

    /// A fixed mint pins mint-seeded PDA bump search costs.
    pub fn create_mint_from(
        &mut self,
        mint: &Keypair,
        token_program: Pubkey,
    ) -> Result<Pubkey, ProgramTestError> {
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(SPL_TOKEN_MINT_ACCOUNT_LEN);
        let create_ix = system_create_account_ix(
            &self.payer.pubkey(),
            &mint.pubkey(),
            rent,
            SPL_TOKEN_MINT_ACCOUNT_LEN as u64,
            &token_program,
        );
        let mut data = vec![SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, 9];
        data.extend_from_slice(&self.payer.pubkey().to_bytes());
        data.push(0);
        let init_ix = Instruction {
            program_id: token_program,
            accounts: vec![AccountMeta::new(mint.pubkey(), false)],
            data,
        };
        self.send(&[create_ix, init_ix], &[mint])?;
        Ok(mint.pubkey())
    }

    pub fn create_token_account(
        &mut self,
        mint: &Pubkey,
        owner: &Pubkey,
    ) -> Result<Pubkey, ProgramTestError> {
        self.create_token_account_with_program(mint, owner, Self::token_program_id())
    }

    pub fn create_token_account_with_program(
        &mut self,
        mint: &Pubkey,
        owner: &Pubkey,
        token_program: Pubkey,
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
            &token_program,
        );
        let mut data = vec![SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR];
        data.extend_from_slice(&owner.to_bytes());
        let init_ix = Instruction {
            program_id: token_program,
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
        self.mint_to_with_program(mint, account, amount, Self::token_program_id())
    }

    pub fn mint_to_with_program(
        &mut self,
        mint: &Pubkey,
        account: &Pubkey,
        amount: u64,
        token_program: Pubkey,
    ) -> Result<(), ProgramTestError> {
        let mut data = vec![SPL_TOKEN_MINT_TO_DISCRIMINATOR];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: token_program,
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

    pub fn create_asset_counter(
        &mut self,
        authority: &Keypair,
    ) -> Result<Pubkey, ProgramTestError> {
        let counter = pda::spl_asset_counter();
        let ix = CreateAssetCounter {
            authority: authority.pubkey(),
        }
        .instruction();
        self.send(&[ix], &[authority])?;
        Ok(counter)
    }

    /// Create the singleton SPL asset counter if it does not exist yet.
    pub fn ensure_asset_counter(&mut self, authority: &Keypair) -> Result<(), ProgramTestError> {
        if self.account_data(&pda::spl_asset_counter()).is_none() {
            self.create_asset_counter(authority)?;
        }
        Ok(())
    }

    pub fn create_spl_interface(
        &mut self,
        authority: &Keypair,
        mint: &Pubkey,
    ) -> Result<(Pubkey, Pubkey), ProgramTestError> {
        self.create_spl_interface_with_program(authority, mint, Self::token_program_id())
    }

    pub fn create_spl_interface_with_program(
        &mut self,
        authority: &Keypair,
        mint: &Pubkey,
        token_program: Pubkey,
    ) -> Result<(Pubkey, Pubkey), ProgramTestError> {
        let registry = pda::spl_asset_registry(mint);
        let vault = pda::spl_interface(mint);
        let ix = CreateSplInterface {
            authority: authority.pubkey(),
            mint: *mint,
            token_program,
        }
        .instruction();
        self.send(&[ix], &[authority])?;
        Ok((registry, vault))
    }
}
