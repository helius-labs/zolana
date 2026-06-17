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
        let merge_authority = authority.pubkey().to_bytes();
        self.create_protocol_config_with_merge_authority(authority, merge_authority)
    }

    pub fn create_protocol_config_with_merge_authority(
        &mut self,
        authority: &Keypair,
        merge_authority: [u8; 32],
    ) -> Result<Pubkey, ProgramTestError> {
        let data =
            create_protocol_config_data(authority.pubkey().to_bytes(), merge_authority, false);
        self.create_protocol_config_with_data(authority, data)
    }

    pub fn create_protocol_config_permissionless(
        &mut self,
        authority: &Keypair,
    ) -> Result<Pubkey, ProgramTestError> {
        let merge_authority = authority.pubkey().to_bytes();
        let data =
            create_protocol_config_data(authority.pubkey().to_bytes(), merge_authority, true);
        self.create_protocol_config_with_data(authority, data)
    }

    pub fn create_protocol_config_with_data(
        &mut self,
        authority: &Keypair,
        data: CreateProtocolConfigData,
    ) -> Result<Pubkey, ProgramTestError> {
        self.airdrop(&authority.pubkey(), 1_000_000_000)?;
        let config = pda::protocol_config();
        let ix = create_protocol_config(authority.pubkey(), data);
        self.send(&[ix], &[authority])?;
        Ok(config)
    }

    pub fn update_protocol_config(
        &mut self,
        authority: &Keypair,
        new_authority: &Pubkey,
    ) -> Result<(), ProgramTestError> {
        let merge_authority = new_authority.to_bytes();
        self.update_protocol_config_with_merge_authority(authority, new_authority, merge_authority)
    }

    pub fn update_protocol_config_with_merge_authority(
        &mut self,
        authority: &Keypair,
        new_authority: &Pubkey,
        merge_authority: [u8; 32],
    ) -> Result<(), ProgramTestError> {
        let payer = authority.pubkey();
        let next = new_authority.to_bytes();
        // Rotate `protocol_authority` last so the current authority signs every
        // instruction in the batch.
        let ixs = [
            update_protocol_config_ix(
                payer,
                UpdateProtocolConfigData::TreeCreationAuthority(next.into()),
            ),
            update_protocol_config_ix(
                payer,
                UpdateProtocolConfigData::ForesterAuthority(next.into()),
            ),
            update_protocol_config_ix(
                payer,
                UpdateProtocolConfigData::ZoneCreationAuthority(next.into()),
            ),
            update_protocol_config_ix(
                payer,
                UpdateProtocolConfigData::MergeAuthority(merge_authority.into()),
            ),
            update_protocol_config_ix(
                payer,
                UpdateProtocolConfigData::ProtocolAuthority(next.into()),
            ),
        ];
        self.send(&ixs, &[authority])
    }

    pub fn pause_tree(
        &mut self,
        authority: &Keypair,
        tree: &Keypair,
        paused: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = pause_tree_ix(
            authority.pubkey(),
            tree.pubkey(),
            PauseTreeData {
                paused: u8::from(paused),
            },
        );
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

fn create_protocol_config_data(
    authority: [u8; 32],
    merge_authority: [u8; 32],
    permissionless: bool,
) -> CreateProtocolConfigData {
    CreateProtocolConfigData {
        protocol_authority: authority.into(),
        tree_creation_authority: authority.into(),
        tree_creation_is_permissionless: u8::from(permissionless),
        forester_authority: authority.into(),
        zone_creation_authority: authority.into(),
        zone_creation_is_permissionless: u8::from(permissionless),
        merge_authority: merge_authority.into(),
    }
}
