use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        create_protocol_config, pause_tree as pause_tree_ix,
        update_protocol_config as update_protocol_config_ix, CreateProtocolConfigData,
        PauseTreeData, UpdateProtocolConfigData,
    },
    pda,
};

use crate::{instructions::create_tree_instructions, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
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
        let config = pda::protocol_config();
        let ix = create_protocol_config(
            authority.pubkey(),
            CreateProtocolConfigData {
                authority: authority.pubkey().to_bytes(),
                merge_authorities,
            },
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
        let ix = update_protocol_config_ix(
            authority.pubkey(),
            UpdateProtocolConfigData {
                authority: new_authority.to_bytes(),
                merge_authorities,
            },
        );
        self.send(&[ix], &[authority])
    }

    pub fn pause_tree(
        &mut self,
        authority: &Keypair,
        tree: &Keypair,
        paused: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = pause_tree_ix(authority.pubkey(), tree.pubkey(), PauseTreeData { paused });
        self.send(&[ix], &[authority])
    }

    pub fn create_tree(
        &mut self,
        account_size: u64,
        authority: &Keypair,
    ) -> Result<Keypair, ProgramTestError> {
        let tree = self.next_tree_keypair();
        let payer = self.payer.pubkey();
        let authority_key = authority.pubkey();
        let tree_key = tree.pubkey();
        let ixs = create_tree_instructions(self, &payer, &authority_key, &tree_key, account_size)?;
        self.send(&ixs, &[&tree, authority])?;
        Ok(tree)
    }
}
