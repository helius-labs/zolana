use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    event::DepositView,
    instruction::{DepositAccounts, DepositIxData, DepositSplAccounts},
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
        let ix = data.instruction(DepositAccounts::sol(*tree, depositor.pubkey()));
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
        let ix = data.instruction(DepositAccounts::spl(
            *tree,
            depositor.pubkey(),
            DepositSplAccounts {
                user_token: *user_token,
                vault: pda::spl_asset_vault(mint),
                registry: pda::spl_asset_registry(mint),
                token_program: Self::token_program_id(),
            },
        ));
        self.send_deposit_ix(ix, depositor)
    }

    pub fn deposit_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        data: &DepositIxData,
    ) -> Result<DepositView, ProgramTestError> {
        let mut ix = data.instruction(DepositAccounts::sol(Pubkey::default(), depositor.pubkey()));
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
