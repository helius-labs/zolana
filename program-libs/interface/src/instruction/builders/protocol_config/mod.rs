use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        encode_instruction, tag, CreateProtocolConfigData, PauseTreeData, SetTreeFeesData,
        UpdateProtocolConfigData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Initialize the canonical protocol-config PDA. `fee_payer` funds the account;
/// `initialization_authority` must be the program's nonzero loader-v3 upgrade
/// authority. Keeping those roles separate lets a Squads vault authorize the
/// initialization through CPI while an ordinary transaction signer pays rent.
pub struct CreateProtocolConfig {
    pub fee_payer: Pubkey,
    pub initialization_authority: Pubkey,
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub tree_creation_is_permissionless: bool,
    pub forester_authority: Address,
    pub ring_creation_authority: Address,
    pub ring_activation_is_permissionless: bool,
    pub spl_interface_creation_is_permissionless: bool,
    pub fee_authority: Address,
}

impl CreateProtocolConfig {
    pub fn instruction(&self) -> Instruction {
        let data = CreateProtocolConfigData {
            protocol_authority: self.protocol_authority,
            tree_creation_authority: self.tree_creation_authority,
            tree_creation_is_permissionless: self.tree_creation_is_permissionless as u8,
            forester_authority: self.forester_authority,
            ring_creation_authority: self.ring_creation_authority,
            ring_activation_is_permissionless: self.ring_activation_is_permissionless as u8,
            spl_interface_creation_is_permissionless: self.spl_interface_creation_is_permissionless
                as u8,
            fee_authority: self.fee_authority,
        };

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.fee_payer, true),
                AccountMeta::new_readonly(self.initialization_authority, true),
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

pub struct SetTreeFees {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub fees: SetTreeFeesData,
}

impl SetTreeFees {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(self.tree, false),
            ],
            data: encode_instruction(tag::SET_TREE_FEES, &self.fees),
        }
    }
}

pub struct ClaimTreeLamports {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub recipient: Pubkey,
}

impl ClaimTreeLamports {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.recipient, false),
            ],
            data: vec![tag::CLAIM_TREE_LAMPORTS],
        }
    }
}
