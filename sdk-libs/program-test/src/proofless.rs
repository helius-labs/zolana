use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    event::DepositView,
    instruction::{Deposit, DepositIxData, DepositSplAccounts},
    pda,
};

use crate::{single_deposit_view, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
    pub fn deposit(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        data: &DepositIxData,
    ) -> Result<DepositView, ProgramTestError> {
        let ix = Deposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data.clone(),
            cpi_signer: data.cpi_signer,
        }
        .instruction();
        self.send_deposit_ix(ix, depositor)
    }

    pub fn deposit_spl(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        user_token: &Pubkey,
        mint: &Pubkey,
        data: &DepositIxData,
    ) -> Result<DepositView, ProgramTestError> {
        let ix = Deposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            spl: Some(DepositSplAccounts {
                user_token: *user_token,
                vault: pda::spl_asset_vault(mint),
                registry: pda::spl_asset_registry(mint),
                token_program: Self::token_program_id(),
            }),
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data.clone(),
            cpi_signer: data.cpi_signer,
        }
        .instruction();
        self.send_deposit_ix(ix, depositor)
    }

    pub fn deposit_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        data: &DepositIxData,
    ) -> Result<DepositView, ProgramTestError> {
        let mut ix = Deposit {
            tree: Pubkey::default(),
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data.clone(),
            cpi_signer: data.cpi_signer,
        }
        .instruction();
        ix.program_id = self.program_id;
        ix.accounts = accounts;
        self.send_deposit_ix(ix, depositor)
    }

    pub(crate) fn send_deposit_ix(
        &mut self,
        ix: Instruction,
        depositor: &Keypair,
    ) -> Result<DepositView, ProgramTestError> {
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_deposit_view(&outcome.events)
    }

    pub fn deposit_sol(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        lamports: u64,
        owner_utxo_hash: [u8; 32],
    ) -> Result<DepositView, ProgramTestError> {
        let data = Self::sol_shield_data(lamports, owner_utxo_hash);
        self.deposit(tree, depositor, &data)
    }
}
