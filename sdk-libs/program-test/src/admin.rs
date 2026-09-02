use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        ClaimTreeLamports, CreateProtocolConfig, CreateProtocolConfigData, PauseTree, SetTreeFees,
        UpdateProtocolConfig, UpdateProtocolConfigData,
    },
    pda,
};

use zolana_interface::state::{default_tree_fees, nullifier_tree_params};
use zolana_tree::{NullifierTreeInitParams, TreeFeeSchedule};

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
            ring_creation_authority: data.ring_creation_authority,
            ring_creation_is_permissionless: data.ring_creation_is_permissionless != 0,
            spl_interface_creation_is_permissionless: data.spl_interface_creation_is_permissionless
                != 0,
            fee_authority: data.fee_authority,
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
            update(UpdateProtocolConfigData::RingCreationAuthority(next.into())),
            update(UpdateProtocolConfigData::ProtocolAuthority(next.into())),
        ];
        let mut signers: Vec<&dyn Signer> = vec![authority];
        if new_authority.pubkey() != authority.pubkey() {
            signers.push(new_authority);
        }
        self.send(&ixs, &signers)
    }

    pub fn send_protocol_config_update(
        &mut self,
        authority: &Keypair,
        update: UpdateProtocolConfigData,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateProtocolConfig {
            authority: authority.pubkey(),
            update,
        }
        .instruction();
        self.send(&[ix], &[authority])
    }

    pub fn pause_tree(
        &mut self,
        authority: &Keypair,
        tree: &Pubkey,
        paused: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = PauseTree {
            authority: authority.pubkey(),
            tree: *tree,
            paused,
        }
        .instruction();
        self.send(&[ix], &[authority])
    }

    pub fn create_tree(&mut self, authority: &Keypair) -> Result<Pubkey, ProgramTestError> {
        self.create_tree_with_nullifier_params(authority, nullifier_tree_params())
    }

    pub fn create_tree_with_nullifier_params(
        &mut self,
        authority: &Keypair,
        nullifier_params: NullifierTreeInitParams,
    ) -> Result<Pubkey, ProgramTestError> {
        let fees = default_tree_fees(nullifier_params.input_queue_zkp_batch_size).ok_or(
            ProgramTestError::InvalidTreeFees(nullifier_params.input_queue_zkp_batch_size),
        )?;
        self.create_tree_with_params(authority, nullifier_params, fees)
    }

    pub fn create_tree_with_params(
        &mut self,
        authority: &Keypair,
        nullifier_params: NullifierTreeInitParams,
        fees: TreeFeeSchedule,
    ) -> Result<Pubkey, ProgramTestError> {
        let payer = self.payer.pubkey();
        let creation =
            create_tree_instructions(self, &payer, &authority.pubkey(), nullifier_params, fees)?;
        self.send(&creation.instructions, &[authority])?;
        Ok(creation.tree)
    }

    pub fn set_tree_fees(
        &mut self,
        authority: &Keypair,
        tree: &Pubkey,
        fees: TreeFeeSchedule,
    ) -> Result<(), ProgramTestError> {
        let ix = SetTreeFees {
            authority: authority.pubkey(),
            tree: *tree,
            fees,
        }
        .instruction();
        self.send(&[ix], &[authority])
    }

    pub fn claim_tree_lamports(
        &mut self,
        authority: &Keypair,
        tree: &Pubkey,
        recipient: &Pubkey,
    ) -> Result<(), ProgramTestError> {
        let ix = ClaimTreeLamports {
            authority: authority.pubkey(),
            tree: *tree,
            recipient: *recipient,
        }
        .instruction();
        self.send(&[ix], &[authority])
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
        ring_creation_authority: authority.into(),
        ring_creation_is_permissionless: u8::from(permissionless),
        spl_interface_creation_is_permissionless: u8::from(permissionless),
        fee_authority: authority.into(),
    }
}
