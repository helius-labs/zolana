use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    event::ProoflessShieldView,
    instruction::{ProoflessShieldAccounts, ProoflessShieldIxData, ProoflessShieldSplAccounts},
    pda,
};

use crate::{single_proofless_shield_view, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
    pub fn proofless_shield(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldView, ProgramTestError> {
        let ix = data.instruction(ProoflessShieldAccounts::sol(*tree, depositor.pubkey()));
        self.send_proofless_shield_ix(ix, depositor)
    }

    pub fn proofless_shield_spl(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        user_token: &Pubkey,
        mint: &Pubkey,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldView, ProgramTestError> {
        let ix = data.instruction(ProoflessShieldAccounts::spl(
            *tree,
            depositor.pubkey(),
            ProoflessShieldSplAccounts {
                user_token: *user_token,
                vault: pda::spl_asset_vault(mint),
                registry: pda::spl_asset_registry(mint),
                token_program: Self::token_program_id(),
            },
        ));
        self.send_proofless_shield_ix(ix, depositor)
    }

    pub fn proofless_shield_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldView, ProgramTestError> {
        let mut ix = data.instruction(ProoflessShieldAccounts::sol(
            Pubkey::default(),
            depositor.pubkey(),
        ));
        ix.program_id = self.program_id;
        ix.accounts = accounts;
        self.send_proofless_shield_ix(ix, depositor)
    }

    pub(crate) fn send_proofless_shield_ix(
        &mut self,
        ix: Instruction,
        depositor: &Keypair,
    ) -> Result<ProoflessShieldView, ProgramTestError> {
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_proofless_shield_view(&outcome.events)
    }

    pub fn proofless_shield_sol(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        lamports: u64,
        owner_utxo_hash: [u8; 32],
    ) -> Result<ProoflessShieldView, ProgramTestError> {
        let data = Self::sol_shield_data(lamports, owner_utxo_hash);
        self.proofless_shield(tree, depositor, &data)
    }
}
