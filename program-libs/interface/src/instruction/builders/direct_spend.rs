use crate::{
    direct_spend::{
        BufferInstruction, Payload, PrepareCertificate, BUFFER_CHUNK_SIZE, BUFFER_HEADER_SIZE,
        BUFFER_SEED, MAX_PAYLOAD,
    },
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
    let bytes = payload_bytes(payload)?;
    let buffer = spend_buffer(&owner, &nonce);
    let mut instructions = vec![buffer_instruction(
        owner,
        buffer,
        BufferInstruction::Create {
            nonce,
            size: bytes.len() as u16,
        },
    )];
    instructions.extend(write_spend(owner, buffer, 0, &bytes));
    Ok(instructions)
}

pub struct SpendUpload {
    owner: Pubkey,
    nonce: [u8; 32],
    size: usize,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl SpendUpload {
    pub fn new(owner: Pubkey, nonce: [u8; 32], payload: &Payload) -> Result<Self, &'static str> {
        let bytes = payload_bytes(payload)?;
        let (statement, suffix) = match payload {
            Payload::Certificate { statement, .. } => (borsh::to_vec(statement), Vec::new()),
            Payload::Payment { statement, .. } => (borsh::to_vec(statement), Vec::new()),
            Payload::GkrPayment {
                statement, inputs, ..
            }
            | Payload::AdmittedPayment {
                statement, inputs, ..
            }
            | Payload::DagPayment {
                statement, inputs, ..
            } => (borsh::to_vec(statement), inputs.to_le_bytes().to_vec()),
        };
        let prefix_len = 1 + statement.map_err(|_| "invalid spend statement")?.len();
        Ok(Self {
            owner,
            nonce,
            size: bytes.len(),
            prefix: bytes[..prefix_len].to_vec(),
            suffix,
        })
    }

    /// Confirm these instructions in order before submitting `finish` instructions.
    pub fn start(&self) -> Vec<Instruction> {
        let buffer = spend_buffer(&self.owner, &self.nonce);
        let mut instructions = vec![buffer_instruction(
            self.owner,
            buffer,
            BufferInstruction::Create {
                nonce: self.nonce,
                size: self.size as u16,
            },
        )];
        instructions.extend(write_spend(self.owner, buffer, 0, &self.prefix));
        instructions
    }

    pub fn finish(&self, payload: &Payload) -> Result<Vec<Instruction>, &'static str> {
        let bytes = self.validate(payload)?;
        Ok(write_spend(
            self.owner,
            spend_buffer(&self.owner, &self.nonce),
            self.prefix.len(),
            &bytes[self.prefix.len()..],
        ))
    }

    /// Execute these in order and confirm allocation before submitting chunks.
    pub fn allocate_chunked(&self) -> Vec<Instruction> {
        let buffer = spend_buffer(&self.owner, &self.nonce);
        let mut instructions = vec![buffer_instruction(
            self.owner,
            buffer,
            BufferInstruction::CreateChunked {
                nonce: self.nonce,
                size: self.size as u16,
            },
        )];
        let allocations =
            (BUFFER_HEADER_SIZE + self.size).div_ceil(crate::state::TREE_ALLOCATION_STEP);
        instructions.extend(
            (1..allocations)
                .map(|_| buffer_instruction(self.owner, buffer, BufferInstruction::Grow)),
        );
        instructions
    }

    /// Full statement chunks may arrive in any order after allocation completes.
    pub fn start_chunks(&self) -> Vec<Instruction> {
        let length = self.prefix.len() / BUFFER_CHUNK_SIZE * BUFFER_CHUNK_SIZE;
        self.chunks(0, &self.prefix[..length])
    }

    pub fn finish_chunks(&self, payload: &Payload) -> Result<Vec<Instruction>, &'static str> {
        let bytes = self.validate(payload)?;
        let offset = self.prefix.len() / BUFFER_CHUNK_SIZE * BUFFER_CHUNK_SIZE;
        Ok(self.chunks(offset, &bytes[offset..]))
    }

    fn validate(&self, payload: &Payload) -> Result<Vec<u8>, &'static str> {
        let bytes = payload_bytes(payload)?;
        if bytes.len() != self.size
            || !bytes.starts_with(&self.prefix)
            || !bytes.ends_with(&self.suffix)
        {
            return Err("spend statement changed after upload started");
        }
        Ok(bytes)
    }

    fn chunks(&self, offset: usize, bytes: &[u8]) -> Vec<Instruction> {
        let buffer = spend_buffer(&self.owner, &self.nonce);
        bytes
            .chunks(BUFFER_CHUNK_SIZE)
            .enumerate()
            .map(|(index, bytes)| {
                buffer_instruction(
                    self.owner,
                    buffer,
                    BufferInstruction::WriteChunk {
                        index: (offset / BUFFER_CHUNK_SIZE + index) as u8,
                        bytes: bytes.to_vec(),
                    },
                )
            })
            .collect()
    }
}

fn payload_bytes(payload: &Payload) -> Result<Vec<u8>, &'static str> {
    let bytes = borsh::to_vec(payload).map_err(|_| "invalid spend payload")?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err("spend payload exceeds buffer capacity");
    }
    Ok(bytes)
}

fn write_spend(owner: Pubkey, buffer: Pubkey, offset: usize, bytes: &[u8]) -> Vec<Instruction> {
    bytes
        .chunks(BUFFER_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            buffer_instruction(
                owner,
                buffer,
                BufferInstruction::Write {
                    offset: (offset + index * BUFFER_CHUNK_SIZE) as u16,
                    bytes: chunk.to_vec(),
                },
            )
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        direct_spend::{Certificate, Payment, PaymentInputs, Proof, Root},
        verifying_keys::Bsb22Commitment,
    };

    fn certificate() -> Payload {
        Payload::Certificate {
            statement: Certificate {
                tree: [1; 32],
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
    fn staged_upload_preserves_bytes_and_append_offsets() {
        let mut payload = certificate();
        let upload = SpendUpload::new(Pubkey::new_unique(), [9; 32], &payload).unwrap();
        let mut instructions = upload.start();
        if let Payload::Certificate { proof, .. } = &mut payload {
            proof.a = [7; 32];
            proof.b = [8; 128];
            proof.c = [9; 32];
        }
        instructions.extend(upload.finish(&payload).unwrap());
        let mut bytes = Vec::new();
        let mut size = None;
        for instruction in instructions {
            match borsh::from_slice::<BufferInstruction>(&instruction.data[1..]).unwrap() {
                BufferInstruction::Create { size: value, .. } => size = Some(usize::from(value)),
                BufferInstruction::Write {
                    offset,
                    bytes: chunk,
                } => {
                    assert_eq!(usize::from(offset), bytes.len());
                    bytes.extend(chunk);
                }
                _ => panic!("unexpected buffer instruction"),
            }
        }
        assert_eq!(Some(bytes.len()), size);
        assert_eq!(bytes, borsh::to_vec(&payload).unwrap());
    }

    #[test]
    fn staged_upload_rejects_statement_changes() {
        let mut payload = certificate();
        let upload = SpendUpload::new(Pubkey::new_unique(), [9; 32], &payload).unwrap();
        if let Payload::Certificate { statement, .. } = &mut payload {
            statement.nullifiers[0] = [8; 32];
        }
        assert!(upload.finish(&payload).is_err());
        assert!(upload.finish_chunks(&payload).is_err());
    }

    #[test]
    fn chunked_upload_preserves_bytes_across_the_proof_boundary() {
        for count in [1, 20, 36, 144, 512] {
            let mut payload = certificate();
            if let Payload::Certificate { statement, .. } = &mut payload {
                statement.nullifiers.resize(count, [3; 32]);
            }
            let upload = SpendUpload::new(Pubkey::new_unique(), [9; 32], &payload).unwrap();
            let allocation = upload.allocate_chunked();
            assert!(matches!(
                borsh::from_slice::<BufferInstruction>(&allocation[0].data[1..]).unwrap(),
                BufferInstruction::CreateChunked { .. }
            ));
            assert_eq!(
                allocation.len(),
                (BUFFER_HEADER_SIZE + upload.size).div_ceil(crate::state::TREE_ALLOCATION_STEP)
            );
            for instruction in &allocation[1..] {
                assert_eq!(
                    borsh::from_slice::<BufferInstruction>(&instruction.data[1..]).unwrap(),
                    BufferInstruction::Grow
                );
            }
            let mut instructions = upload.start_chunks();
            if let Payload::Certificate { proof, .. } = &mut payload {
                proof.a.fill(7);
                proof.b.fill(8);
                proof.c.fill(9);
            }
            instructions.extend(upload.finish_chunks(&payload).unwrap());
            let mut received = vec![false; upload.size.div_ceil(BUFFER_CHUNK_SIZE)];
            let mut bytes = vec![0; upload.size];
            for instruction in instructions.into_iter().rev() {
                let BufferInstruction::WriteChunk {
                    index,
                    bytes: chunk,
                } = borsh::from_slice(&instruction.data[1..]).unwrap()
                else {
                    panic!("not a chunk")
                };
                let index = usize::from(index);
                assert!(!received[index]);
                received[index] = true;
                let offset = index * BUFFER_CHUNK_SIZE;
                assert_eq!(chunk.len(), BUFFER_CHUNK_SIZE.min(upload.size - offset));
                bytes[offset..offset + chunk.len()].copy_from_slice(&chunk);
            }
            assert!(received.into_iter().all(|present| present));
            assert_eq!(bytes, borsh::to_vec(&payload).unwrap());
        }
    }

    #[test]
    fn append_buffer_instruction_tags_remain_unchanged() {
        for (tag, instruction) in [
            BufferInstruction::Create {
                nonce: [0; 32],
                size: 1,
            },
            BufferInstruction::Write {
                offset: 0,
                bytes: vec![1],
            },
            BufferInstruction::Close,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(borsh::to_vec(&instruction).unwrap()[0], tag as u8);
        }
    }

    #[test]
    fn staged_upload_binds_circuit_variant_and_capacity() {
        let Payload::Certificate { statement, proof } = certificate() else {
            unreachable!()
        };
        let statement = Payment {
            inputs: PaymentInputs::Notes {
                certificate: statement,
                freshness: Root {
                    index: 0,
                    value: [0; 32],
                },
            },
            output_tree: [5; 32],
            expiry_slot: u64::MAX,
            max_forester_fee: 0,
            outputs: Vec::new(),
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
        };
        let commitment = Bsb22Commitment {
            commitment: [0; 32],
            commitment_pok: [0; 32],
        };
        let mut payload = Payload::AdmittedPayment {
            statement: statement.clone(),
            proof: proof.clone(),
            commitment,
            inputs: 144,
        };
        let upload = SpendUpload::new(Pubkey::new_unique(), [9; 32], &payload).unwrap();
        assert!(upload.finish(&payload).is_ok());
        if let Payload::AdmittedPayment { inputs, .. } = &mut payload {
            *inputs = 512;
        }
        assert!(upload.finish(&payload).is_err());
        assert!(upload
            .finish(&Payload::GkrPayment {
                statement,
                proof,
                commitment,
                inputs: 144
            })
            .is_err());
    }
}
