use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{
    proofless_shield, tag, ProoflessShieldEvent, ProoflessShieldIxData,
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
        let accounts = vec![
            AccountMeta::new(*tree, false),
            AccountMeta::new(depositor.pubkey(), true),
            AccountMeta::new_readonly(self.cpi_authority(), false),
            AccountMeta::new(*user_token, false),
            AccountMeta::new(self.spl_asset_vault_pda(mint), false),
            AccountMeta::new_readonly(self.spl_asset_registry_pda(mint), false),
            AccountMeta::new_readonly(Self::token_program_id(), false),
            AccountMeta::new_readonly(self.program_id, false),
        ];
        self.proofless_shield_with_accounts(accounts, depositor, data)
    }

    pub fn proofless_shield_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
        let mut instruction_data = vec![tag::PROOFLESS_SHIELD];
        instruction_data.extend_from_slice(
            &data
                .serialize()
                .expect("proofless ix data serialization is infallible"),
        );
        let ix = Instruction {
            program_id: self.program_id,
            accounts,
            data: instruction_data,
        };
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
