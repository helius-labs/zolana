use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        encode_instruction, tag, CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Initialize the canonical protocol-config PDA. The program creates the PDA via
/// CPI, so the authority is the rent payer (writable signer) and the system
/// program must be present. The program account and its loader `ProgramData`
/// account trail as read-only inputs: on an upgradeable deployment with a set
/// upgrade authority, only that authority may initialize (front-run protection);
/// test/localnet deployments skip the check.
pub struct CreateProtocolConfig {
    pub authority: Pubkey,
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub tree_creation_is_permissionless: bool,
    pub forester_authority: Address,
    pub ring_creation_authority: Address,
    pub ring_creation_is_permissionless: bool,
    pub spl_interface_creation_is_permissionless: bool,
}

impl CreateProtocolConfig {
    pub fn instruction(&self) -> Instruction {
        let data = CreateProtocolConfigData {
            protocol_authority: self.protocol_authority,
            tree_creation_authority: self.tree_creation_authority,
            tree_creation_is_permissionless: self.tree_creation_is_permissionless as u8,
            forester_authority: self.forester_authority,
            ring_creation_authority: self.ring_creation_authority,
            ring_creation_is_permissionless: self.ring_creation_is_permissionless as u8,
            spl_interface_creation_is_permissionless: self.spl_interface_creation_is_permissionless
                as u8,
        };

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.authority, true),
                AccountMeta::new(pda::protocol_config(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                // The program reads its own loader state to bind initialization
                // to the deploy upgrade authority (INV-CREATE-PC-10).
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(pda::program_data(), false),
            ],
            data: encode_instruction(tag::CREATE_PROTOCOL_CONFIG, &data),
        }
    }
}

pub struct UpdateProtocolConfig {
    pub authority: Pubkey,
    pub update: UpdateProtocolConfigData,
}

impl UpdateProtocolConfig {
    pub fn instruction(&self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(pda::protocol_config(), false),
        ];
        if let UpdateProtocolConfigData::ProtocolAuthority(a) = &self.update {
            accounts.push(AccountMeta::new_readonly(
                Pubkey::new_from_array(a.to_bytes()),
                false,
            ));
        }
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: encode_instruction(tag::UPDATE_PROTOCOL_CONFIG, &self.update),
        }
    }
}

pub struct PauseTree {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub paused: bool,
}

impl PauseTree {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(pda::protocol_config(), false),
                AccountMeta::new(self.tree, false),
            ],
            data: encode_instruction(
                tag::PAUSE_TREE,
                &PauseTreeData {
                    paused: self.paused as u8,
                },
            ),
        }
    }
}
