use solana_instruction::{error::InstructionError, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    direct_spend::{
        BufferInstruction, Certificate, Output, Payload, Payment, PaymentInputs,
        PrepareCertificate, Proof, Root, BUFFER_CHUNK_SIZE, BUFFER_HEADER_SIZE, MAX_PAYLOAD,
    },
    error::ShieldedPoolError,
    instruction::builders::direct_spend::{self as builders, SpendUpload},
};
use zolana_program_test::{ProgramTestError, Rejection};
use zolana_test_utils::backend::LiteSvmPoolBackend as Pool;

fn send(pool: &mut Pool, instructions: &[Instruction]) -> Result<(), ProgramTestError> {
    pool.rpc
        .create_and_send_default_payer_transaction(instructions, &[])
        .map(|_| ())
}

fn instruction(pool: &Pool, buffer: Pubkey, data: BufferInstruction) -> Instruction {
    builders::buffer_instruction(pool.rpc.payer.pubkey(), buffer, data)
}

fn allocate(pool: &mut Pool, size: usize, chunked: bool) -> Pubkey {
    let nonce = Pubkey::new_unique().to_bytes();
    let buffer = builders::spend_buffer(&pool.rpc.payer.pubkey(), &nonce);
    let data = if chunked {
        BufferInstruction::CreateChunked {
            nonce,
            size: size as u16,
        }
    } else {
        BufferInstruction::Create {
            nonce,
            size: size as u16,
        }
    };
    let create = instruction(pool, buffer, data);
    send(pool, &[create]).unwrap();
    if chunked {
        while pool.rpc.account_data(&buffer).unwrap().len() < BUFFER_HEADER_SIZE + size {
            let grow = instruction(pool, buffer, BufferInstruction::Grow);
            send(pool, &[grow]).unwrap();
        }
    }
    buffer
}

fn reject(pool: &mut Pool, buffer: Pubkey, data: BufferInstruction) {
    let before = pool.rpc.account_data(&buffer).unwrap();
    let instruction = instruction(pool, buffer, data);
    Rejection::new(InstructionError::InvalidArgument)
        .assert_litesvm(send(pool, &[instruction]).unwrap_err());
    assert_eq!(pool.rpc.account_data(&buffer).unwrap(), before);
    pool.rpc
        .last_transaction_trace()
        .unwrap()
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

fn certificate(tree: Pubkey) -> Payload {
    Payload::Certificate {
        statement: Certificate {
            tree: tree.to_bytes(),
            state_root: Root {
                index: 0,
                value: [2; 32],
            },
            nullifiers: vec![[3; 32]; 36],
            value_commitment: [4; 32],
        },
        proof: Proof {
            a: [0; 32],
            b: [0; 128],
            c: [0; 32],
        },
    }
}

#[test]
fn allocation_instructions_can_share_a_transaction() {
    let mut pool = Pool::initialized();
    let nonce = [4; 32];
    let buffer = builders::spend_buffer(&pool.rpc.payer.pubkey(), &nonce);
    let instructions = [
        BufferInstruction::CreateChunked {
            nonce,
            size: MAX_PAYLOAD as u16,
        },
        BufferInstruction::Grow,
        BufferInstruction::Grow,
        BufferInstruction::WriteChunk {
            index: 29,
            bytes: vec![1; 800],
        },
    ]
    .map(|data| instruction(&pool, buffer, data));
    send(&mut pool, &instructions).unwrap();
    let data = pool.rpc.account_data(&buffer).unwrap();
    assert_eq!(data.len(), BUFFER_HEADER_SIZE + MAX_PAYLOAD);
    assert_eq!(
        u32::from_le_bytes(data[46..50].try_into().unwrap()),
        1 << 29
    );
}

#[test]
fn reversed_chunks_and_identical_retries_preserve_payload() {
    let mut pool = Pool::initialized();
    let buffer = allocate(&mut pool, MAX_PAYLOAD, true);
    let payload: Vec<_> = (0..MAX_PAYLOAD).map(|index| (index % 251) as u8).collect();
    for (index, bytes) in payload.chunks(BUFFER_CHUNK_SIZE).enumerate().rev() {
        let write = instruction(
            &pool,
            buffer,
            BufferInstruction::WriteChunk {
                index: index as u8,
                bytes: bytes.to_vec(),
            },
        );
        send(&mut pool, &[write.clone()]).unwrap();
        let grow = instruction(&pool, buffer, BufferInstruction::Grow);
        send(&mut pool, &[write, grow]).unwrap();
    }
    let data = pool.rpc.account_data(&buffer).unwrap();
    assert_eq!(&data[BUFFER_HEADER_SIZE..], payload);
    assert_eq!(
        u16::from_le_bytes(data[42..44].try_into().unwrap()) as usize,
        payload.len()
    );
    assert_eq!(
        u32::from_le_bytes(data[46..50].try_into().unwrap()),
        (1 << 30) - 1
    );
    reject(
        &mut pool,
        buffer,
        BufferInstruction::WriteChunk {
            index: 0,
            bytes: vec![255; 800],
        },
    );
}

#[test]
fn chunks_require_full_allocation_and_exact_ranges() {
    let mut pool = Pool::initialized();
    let nonce = [1; 32];
    let buffer = builders::spend_buffer(&pool.rpc.payer.pubkey(), &nonce);
    let create = instruction(
        &pool,
        buffer,
        BufferInstruction::CreateChunked {
            nonce,
            size: MAX_PAYLOAD as u16,
        },
    );
    send(&mut pool, &[create]).unwrap();
    reject(
        &mut pool,
        buffer,
        BufferInstruction::WriteChunk {
            index: 0,
            bytes: vec![1; 800],
        },
    );
    let buffer = allocate(&mut pool, 1701, true);
    for (index, length) in [(0, 0), (0, 799), (0, 801), (2, 800), (3, 1), (255, 800)] {
        reject(
            &mut pool,
            buffer,
            BufferInstruction::WriteChunk {
                index,
                bytes: vec![1; length],
            },
        );
    }
    reject(
        &mut pool,
        buffer,
        BufferInstruction::Write {
            offset: 0,
            bytes: vec![1],
        },
    );
    let write = instruction(
        &pool,
        buffer,
        BufferInstruction::WriteChunk {
            index: 2,
            bytes: vec![1; 101],
        },
    );
    send(&mut pool, &[write]).unwrap();
}

#[test]
fn chunk_writes_authenticate_owner_and_roll_back_later_failures() {
    let mut pool = Pool::initialized();
    let buffer = allocate(&mut pool, 800, true);
    let before = pool.rpc.account_data(&buffer).unwrap();
    let outsider = pool.funded_signer(1_000_000);
    for data in [
        BufferInstruction::Grow,
        BufferInstruction::WriteChunk {
            index: 0,
            bytes: vec![1; 800],
        },
    ] {
        let write = builders::buffer_instruction(outsider.pubkey(), buffer, data);
        Rejection::new(InstructionError::InvalidArgument).assert_litesvm(
            pool.rpc
                .create_and_send_default_payer_transaction(&[write], &[&outsider])
                .unwrap_err(),
        );
        assert_eq!(pool.rpc.account_data(&buffer).unwrap(), before);
    }
    let write = instruction(
        &pool,
        buffer,
        BufferInstruction::WriteChunk {
            index: 0,
            bytes: vec![1; 800],
        },
    );
    let invalid = Instruction {
        program_id: zolana_interface::PROGRAM_ID_PUBKEY,
        accounts: vec![],
        data: vec![255],
    };
    assert!(send(&mut pool, &[write, invalid]).is_err());
    assert_eq!(pool.rpc.account_data(&buffer).unwrap(), before);
    pool.rpc
        .last_transaction_trace()
        .unwrap()
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

#[test]
fn incomplete_chunks_cannot_prepare_and_sealed_buffers_cannot_change() {
    let mut pool = Pool::initialized();
    let owner = pool.rpc.payer.pubkey();
    let payload = certificate(pool.tree);
    let upload = SpendUpload::new(owner, [2; 32], &payload).unwrap();
    let buffer = builders::spend_buffer(&owner, &[2; 32]);
    for instruction in upload.allocate_chunked() {
        send(&mut pool, &[instruction]).unwrap();
    }
    for instruction in upload.finish_chunks(&payload).unwrap() {
        send(&mut pool, &[instruction]).unwrap();
    }
    let prepare = builders::prepare_certificate(
        owner,
        buffer,
        pool.tree,
        &PrepareCertificate {
            freshness: Root {
                index: 0,
                value: [0; 32],
            },
            proof: Proof {
                a: [0; 32],
                b: [0; 128],
                c: [0; 32],
            },
        },
    );
    Rejection::new(InstructionError::InvalidAccountData)
        .assert_litesvm(send(&mut pool, &[prepare.clone()]).unwrap_err());
    let chunks = upload.start_chunks();
    for instruction in &chunks {
        send(&mut pool, &[instruction.clone()]).unwrap();
    }
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts)
        .assert_litesvm(send(&mut pool, &[prepare.clone()]).unwrap_err());
    let original = pool.rpc.svm.get_account(&buffer).unwrap();
    for status in [1, 2] {
        // Inject sealed metadata to exercise SBF mutation guards without generating proofs.
        let mut sealed = original.clone();
        sealed.data[44] = status;
        sealed.data[46..80].fill(255);
        pool.rpc.svm.set_account(buffer, sealed).unwrap();
        assert!(send(&mut pool, &[chunks[0].clone()]).is_err());
        reject(&mut pool, buffer, BufferInstruction::Grow);
        if status == 1 {
            Rejection::pool(ShieldedPoolError::InvalidTreeAccounts)
                .assert_litesvm(send(&mut pool, &[prepare.clone()]).unwrap_err());
        }
    }
}

#[test]
fn incomplete_payment_chunks_cannot_commit() {
    let mut pool = Pool::initialized();
    let owner = pool.rpc.payer.pubkey();
    let Payload::Certificate { statement, proof } = certificate(pool.tree) else {
        unreachable!()
    };
    let payload = Payload::Payment {
        statement: Payment {
            inputs: PaymentInputs::Notes {
                certificate: statement,
                freshness: Root {
                    index: 0,
                    value: [0; 32],
                },
            },
            output_tree: pool.tree.to_bytes(),
            expiry_slot: u64::MAX,
            max_forester_fee: 0,
            outputs: vec![
                Output {
                    recipient: owner.to_bytes(),
                    utxo: zolana_interface::event::OutputUtxo {
                        utxo_hash: [5; 32],
                        view_tag: owner.to_bytes(),
                        data: vec![],
                    }
                };
                2
            ],
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
        },
        proof,
    };
    let upload = SpendUpload::new(owner, [5; 32], &payload).unwrap();
    let buffer = builders::spend_buffer(&owner, &[5; 32]);
    send(&mut pool, &upload.allocate_chunked()).unwrap();
    for instruction in upload.finish_chunks(&payload).unwrap() {
        send(&mut pool, &[instruction]).unwrap();
    }
    let commit = builders::commit_spend(owner, buffer, pool.tree, pool.tree, &[]);
    Rejection::new(InstructionError::InvalidAccountData)
        .assert_litesvm(send(&mut pool, &[commit.clone()]).unwrap_err());
    for instruction in upload.start_chunks() {
        send(&mut pool, &[instruction]).unwrap();
    }
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts)
        .assert_litesvm(send(&mut pool, &[commit]).unwrap_err());
}

#[test]
fn legacy_append_upload_and_mode_guards_remain_compatible() {
    let mut pool = Pool::initialized();
    let buffer = allocate(&mut pool, 801, false);
    reject(&mut pool, buffer, BufferInstruction::Grow);
    reject(
        &mut pool,
        buffer,
        BufferInstruction::WriteChunk {
            index: 0,
            bytes: vec![1; 800],
        },
    );
    reject(
        &mut pool,
        buffer,
        BufferInstruction::Write {
            offset: 800,
            bytes: vec![1],
        },
    );
    for (offset, bytes) in [(0, vec![1; 800]), (800, vec![2])] {
        let write = instruction(&pool, buffer, BufferInstruction::Write { offset, bytes });
        send(&mut pool, &[write]).unwrap();
    }
    let data = pool.rpc.account_data(&buffer).unwrap();
    assert_eq!(
        &data[BUFFER_HEADER_SIZE..BUFFER_HEADER_SIZE + 800],
        &[1; 800]
    );
    assert_eq!(data[BUFFER_HEADER_SIZE + 800], 2);
    assert_eq!(data[45], 0);
    let payload = certificate(pool.tree);
    let nonce = [3; 32];
    for instruction in builders::upload_spend(pool.rpc.payer.pubkey(), nonce, &payload).unwrap() {
        send(&mut pool, &[instruction]).unwrap();
    }
    let buffer = builders::spend_buffer(&pool.rpc.payer.pubkey(), &nonce);
    assert_eq!(
        &pool.rpc.account_data(&buffer).unwrap()[BUFFER_HEADER_SIZE..],
        borsh::to_vec(&payload).unwrap()
    );
}
