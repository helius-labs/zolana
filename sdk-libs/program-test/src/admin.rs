use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{
    encode_instruction, tag, PauseTreeData, UpdateProtocolConfigData,
};

use crate::{
    instructions::{
        create_protocol_config_instruction, create_tree_instructions, protocol_config_pda,
    },
    ProgramTestError, ZolanaProgramTest,
};

impl ZolanaProgramTest {
    pub fn protocol_config_pda(&self) -> Pubkey {
        protocol_config_pda(&self.program_id)
    }

    pub fn create_protocol_config(
        &mut self,
        authority: &Keypair,
    ) -> Result<Pubkey, ProgramTestError> {
        self.create_protocol_config_with_merge_authorities(authority, Vec::new())
    }

    pub fn create_protocol_config_with_merge_authorities(
        &mut self,
        authority: &Keypair,
        merge_authorities: Vec<[u8; 32]>,
    ) -> Result<Pubkey, ProgramTestError> {
        self.airdrop(&authority.pubkey(), 1_000_000_000)?;
        let config = self.protocol_config_pda();
        let ix = create_protocol_config_instruction(
            self.program_id,
            authority.pubkey(),
            merge_authorities,
        );
        self.send(&[ix], &[authority])?;
        Ok(config)
    }

    pub fn update_protocol_config(
        &mut self,
        authority: &Keypair,
        new_authority: &Pubkey,
    ) -> Result<(), ProgramTestError> {
        self.update_protocol_config_with_merge_authorities(authority, new_authority, Vec::new())
    }

    pub fn update_protocol_config_with_merge_authorities(
        &mut self,
        authority: &Keypair,
        new_authority: &Pubkey,
        merge_authorities: Vec<[u8; 32]>,
    ) -> Result<(), ProgramTestError> {
        let data = encode_instruction(
            tag::UPDATE_PROTOCOL_CONFIG,
            &UpdateProtocolConfigData {
                authority: new_authority.to_bytes(),
                merge_authorities,
            },
        );
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(self.protocol_config_pda(), false),
            ],
            data,
        };
        self.send(&[ix], &[authority])
    }

    pub fn pause_tree(
        &mut self,
        authority: &Keypair,
        tree: &Keypair,
        paused: bool,
    ) -> Result<(), ProgramTestError> {
        let data = encode_instruction(tag::PAUSE_TREE, &PauseTreeData { paused });
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config_pda(), false),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data,
        };
        self.send(&[ix], &[authority])
    }

    pub fn create_tree(
        &mut self,
        account_size: u64,
        authority: &Keypair,
    ) -> Result<Keypair, ProgramTestError> {
        let tree = Keypair::new();
        let program_id = self.program_id;
        let payer = self.payer.pubkey();
        let authority_key = authority.pubkey();
        let tree_key = tree.pubkey();
        let ixs = create_tree_instructions(
            self,
            program_id,
            &payer,
            &authority_key,
            &tree_key,
            account_size,
        )?;
        self.send(&ixs, &[&tree, authority])?;
        Ok(tree)
    }
}
