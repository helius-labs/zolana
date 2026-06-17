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
/// program must be present.
pub struct CreateProtocolConfig {
    pub authority: Pubkey,
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub tree_creation_is_permissionless: bool,
    pub forester_authority: Address,
    pub zone_creation_authority: Address,
    pub zone_creation_is_permissionless: bool,
    pub merge_authority: Address,
}

impl CreateProtocolConfig {
    pub fn instruction(&self) -> Instruction {
        let data = CreateProtocolConfigData {
            protocol_authority: self.protocol_authority,
            tree_creation_authority: self.tree_creation_authority,
            tree_creation_is_permissionless: self.tree_creation_is_permissionless as u8,
            forester_authority: self.forester_authority,
            zone_creation_authority: self.zone_creation_authority,
            zone_creation_is_permissionless: self.zone_creation_is_permissionless as u8,
            merge_authority: self.merge_authority,
        };

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.authority, true),
                AccountMeta::new(pda::protocol_config(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
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
                true,
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
