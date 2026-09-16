use crate::{instruction::tag, pda, PROGRAM_ID_PUBKEY};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

pub fn enable_nullifier_filter(payer: Pubkey, authority: Pubkey, tree: Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(tree, false),
            AccountMeta::new(pda::nullifier_filter(&tree).0, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: vec![tag::ENABLE_NULLIFIER_FILTER],
    }
}

pub fn retire_nullifier_filter(authority: Pubkey, tree: Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(tree, false),
        ],
        data: vec![tag::RETIRE_NULLIFIER_FILTER],
    }
}

pub fn use_nullifier_filter(
    instruction: &mut Instruction,
    tree: &Pubkey,
) -> Result<(), &'static str> {
    let pending = pda::pending_nullifiers(tree).0;
    let filter = pda::nullifier_filter(tree).0;
    if instruction
        .accounts
        .iter()
        .any(|account| account.pubkey == filter)
    {
        return Err("instruction already contains nullifier filter");
    }
    let index = instruction
        .accounts
        .iter()
        .position(|account| account.pubkey == pending)
        .ok_or("instruction does not contain pending nullifiers")?;
    instruction
        .accounts
        .insert(index + 1, AccountMeta::new(filter, false));
    Ok(())
}
