#[cfg(feature = "solana")]
mod solana_builders {
    use borsh::BorshSerialize;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    use crate::{
        instruction::{
            BatchUpdateAddressTreeData, CreateAddressTreeData, InsertAddressesData,
            ShieldedPoolInstruction,
        },
        SHIELDED_POOL_PROGRAM_ID,
    };

    fn program_id() -> Pubkey {
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
    }

    fn build(accounts: Vec<AccountMeta>, instruction: ShieldedPoolInstruction) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts,
            data: instruction
                .try_to_vec()
                .expect("shielded-pool instruction serialization is infallible"),
        }
    }

    pub fn create_address_tree(
        payer: Pubkey,
        tree: Pubkey,
        queue: Pubkey,
        data: CreateAddressTreeData,
    ) -> Instruction {
        build(
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(tree, false),
                AccountMeta::new(queue, false),
            ],
            ShieldedPoolInstruction::CreateAddressTree(data),
        )
    }

    pub fn insert_addresses(
        authority: Pubkey,
        tree: Pubkey,
        queue: Pubkey,
        data: InsertAddressesData,
    ) -> Instruction {
        build(
            vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(tree, false),
                AccountMeta::new(queue, false),
            ],
            ShieldedPoolInstruction::InsertAddresses(data),
        )
    }

    pub fn batch_update_address_tree(
        authority: Pubkey,
        tree: Pubkey,
        queue: Pubkey,
        data: BatchUpdateAddressTreeData,
    ) -> Instruction {
        build(
            vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(tree, false),
                AccountMeta::new(queue, false),
            ],
            ShieldedPoolInstruction::BatchUpdateAddressTree(data),
        )
    }
}

#[cfg(feature = "solana")]
pub use solana_builders::*;
