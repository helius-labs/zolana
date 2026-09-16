use crate::{
    direct_spend::{BufferInstruction, Payload, PrepareCertificate, BUFFER_SEED, MAX_PAYLOAD},
    instruction::{encode_instruction, tag},
    pda, PROGRAM_ID_PUBKEY,
};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

pub fn spend_buffer(owner: &Pubkey, nonce: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[BUFFER_SEED, owner.as_ref(), nonce], &PROGRAM_ID_PUBKEY).0
}

pub fn upload_spend(
    owner: Pubkey,
    nonce: [u8; 32],
    payload: &Payload,
) -> Result<Vec<Instruction>, &'static str> {
    let bytes = borsh::to_vec(payload).map_err(|_| "invalid spend payload")?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err("spend payload exceeds buffer capacity");
    }
    let buffer = spend_buffer(&owner, &nonce);
    let mut instructions = vec![buffer_instruction(
        owner,
        buffer,
        BufferInstruction::Create {
            nonce,
            size: bytes.len() as u16,
        },
    )];
    for (index, chunk) in bytes.chunks(800).enumerate() {
        instructions.push(buffer_instruction(
            owner,
            buffer,
            BufferInstruction::Write {
                offset: (index * 800) as u16,
                bytes: chunk.to_vec(),
            },
        ));
    }
    Ok(instructions)
}

pub fn buffer_instruction(owner: Pubkey, buffer: Pubkey, data: BufferInstruction) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: vec![
            AccountMeta::new(owner, true),
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(tag::DIRECT_SPEND_BUFFER, &data),
    }
}

pub fn prepare_certificate(
    owner: Pubkey,
    buffer: Pubkey,
    tree: Pubkey,
    data: &PrepareCertificate,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(tree, false),
        ],
        data: encode_instruction(tag::PREPARE_CERTIFICATE, data),
    }
}

pub fn commit_spend(
    owner: Pubkey,
    payment: Pubkey,
    input_tree: Pubkey,
    output_tree: Pubkey,
    certificates: &[Pubkey],
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(owner, true),
        AccountMeta::new(payment, false),
        AccountMeta::new(input_tree, false),
        AccountMeta::new(output_tree, false),
        AccountMeta::new(pda::pending_nullifiers(&input_tree).0, false),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
    ];
    accounts.extend(
        certificates
            .iter()
            .map(|key| AccountMeta::new_readonly(*key, false)),
    );
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts,
        data: vec![tag::DIRECT_SPEND],
    }
}

pub fn enable_pending_nullifiers(payer: Pubkey, authority: Pubkey, tree: Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(tree, false),
            AccountMeta::new(pda::pending_nullifiers(&tree).0, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: vec![tag::ENABLE_PENDING_NULLIFIERS],
    }
}

pub fn use_pending_nullifiers(
    instruction: &mut Instruction,
    tree: &Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<(), &'static str> {
    let addresses: Vec<_> = nullifiers
        .iter()
        .map(|nullifier| pda::nullifier_pda(tree, nullifier).0)
        .collect();
    if addresses.is_empty() {
        return Ok(());
    }
    let start = instruction
        .accounts
        .windows(addresses.len())
        .position(|window| {
            window
                .iter()
                .zip(&addresses)
                .all(|(account, address)| account.pubkey == *address)
        })
        .ok_or("instruction does not contain the nullifier account run")?;
    instruction.accounts.splice(
        start..start + addresses.len(),
        [AccountMeta::new(pda::pending_nullifiers(tree).0, false)],
    );
    Ok(())
}
