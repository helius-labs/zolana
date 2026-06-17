use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactIxData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn transact(accounts: Vec<AccountMeta>, data: &TransactIxData) -> Instruction {
    let mut instruction_data = vec![tag::TRANSACT];
    instruction_data.extend_from_slice(
        &data
            .serialize()
            .expect("shielded-pool instruction serialization is infallible"),
    );
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts,
        data: instruction_data,
    }
}
