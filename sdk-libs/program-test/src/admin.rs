use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        CreateProtocolConfig, CreateProtocolConfigData, PauseTree, UpdateProtocolConfig,
        UpdateProtocolConfigData,
    },
    pda,
};

use crate::{instructions::create_tree_instructions, ProgramTestError, ZolanaProgramTest};

impl ZolanaProgramTest {
    pub fn create_protocol_config(
        &mut self,
        authority: &Keypair,
    ) -> Result<Pubkey, ProgramTestError> {
        let data = create_protocol_config_data(authority.pubkey().to_bytes(), false);
        self.create_protocol_config_with_data(authority, data)
    }

    pub fn create_protocol_config_permissionless(
        &mut self,
        authority: &Keypair,
    ) -> Result<Pubkey, ProgramTestError> {
        let data = create_protocol_config_data(authority.pubkey().to_bytes(), true);
        self.create_protocol_config_with_data(authority, data)
    }

    pub fn create_protocol_config_with_data(
        &mut self,
        authority: &Keypair,
        data: CreateProtocolConfigData,
    ) -> Result<Pubkey, ProgramTestError> {
        self.airdrop(&authority.pubkey(), 1_000_000_000)?;
        let config = pda::protocol_config();
        let ix = CreateProtocolConfig {
            authority: authority.pubkey(),
            protocol_authority: data.protocol_authority,
            tree_creation_authority: data.tree_creation_authority,
            tree_creation_is_permissionless: data.tree_creation_is_permissionless != 0,
            forester_authority: data.forester_authority,
            zone_creation_authority: data.zone_creation_authority,
            zone_creation_is_permissionless: data.zone_creation_is_permissionless != 0,
        }
        .instruction();
        self.send(&[ix], &[authority])?;
        Ok(config)
    }

    pub fn update_protocol_config(
        &mut self,
        authority: &Keypair,
        new_authority: &Keypair,
    ) -> Result<(), ProgramTestError> {
        let payer = authority.pubkey();
        let next = new_authority.pubkey().to_bytes();
        // Rotate `protocol_authority` last so the current authority signs every
        // instruction in the batch.
        let update = |variant| {
            UpdateProtocolConfig {
                authority: payer,
                update: variant,
            }
            .instruction()
        };
        let ixs = [
            update(UpdateProtocolConfigData::TreeCreationAuthority(next.into())),
            update(UpdateProtocolConfigData::ForesterAuthority(next.into())),
            update(UpdateProtocolConfigData::ZoneCreationAuthority(next.into())),
            update(UpdateProtocolConfigData::ProtocolAuthority(next.into())),
        ];
        let mut signers = vec![authority];
        if new_authority.pubkey() != authority.pubkey() {
            signers.push(new_authority);
        }
        self.send(&ixs, &signers)
    }

    pub fn pause_tree(
        &mut self,
        authority: &Keypair,
        tree: &Keypair,
        paused: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = PauseTree {
            authority: authority.pubkey(),
            tree: tree.pubkey(),
            paused,
        }
        .instruction();
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
    permissionless: bool,
) -> CreateProtocolConfigData {
    CreateProtocolConfigData {
        protocol_authority: authority.into(),
        tree_creation_authority: authority.into(),
        tree_creation_is_permissionless: u8::from(permissionless),
        forester_authority: authority.into(),
        zone_creation_authority: authority.into(),
        zone_creation_is_permissionless: u8::from(permissionless),
    }
}
