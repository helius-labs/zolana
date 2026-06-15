use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{
    proofless_shield, proofless_shield_spl as proofless_shield_spl_ix, ProoflessShieldEvent,
    ProoflessShieldIxData, ProoflessShieldSplAccounts,
};

use crate::{single_proofless_shield_event, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
    pub fn proofless_shield(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
        let ix = proofless_shield(*tree, depositor.pubkey(), data);
        self.send_proofless_shield_ix(ix, depositor)
    }

    pub fn proofless_shield_spl(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        user_token: &Pubkey,
        mint: &Pubkey,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
        let ix = proofless_shield_spl_ix(
            ProoflessShieldSplAccounts {
                tree: *tree,
                depositor: depositor.pubkey(),
                cpi_authority: self.cpi_authority(),
                user_token: *user_token,
                vault: self.spl_asset_vault_pda(mint),
                registry: self.spl_asset_registry_pda(mint),
                token_program: Self::token_program_id(),
                shielded_pool_program: self.program_id,
            },
            data,
        );
        self.send_proofless_shield_ix(ix, depositor)
    }

    pub fn proofless_shield_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
        let mut ix = proofless_shield(Pubkey::default(), depositor.pubkey(), data);
        ix.program_id = self.program_id;
        ix.accounts = accounts;
        self.send_proofless_shield_ix(ix, depositor)
    }

    pub(crate) fn send_proofless_shield_ix(
        &mut self,
        ix: Instruction,
        depositor: &Keypair,
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_proofless_shield_event(&outcome.events)
    }

    pub fn proofless_shield_sol(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        lamports: u64,
        owner_utxo_hash: [u8; 32],
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
        let data = Self::sol_shield_data(lamports, owner_utxo_hash);
        self.proofless_shield(tree, depositor, &data)
    }
}
