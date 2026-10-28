//! Queue and deadline checks against the real SBF program, without a prover
//! or validator service. Invalid proofs exercise only the preceding gates.

use anyhow::{anyhow, Result};
use dynamic_swap_program::{
    error::DynamicSwapError,
    state::{
        discriminator::{ESCROW, PAIR},
        Escrow, Pair,
    },
};
use dynamic_swap_sdk::{
    escrow_pda, instructions::skip_expired::SkipExpired, pair_pda, tag, CancelIxData,
    CreateEscrowIxData, Groth16ProofBytes, SettleIxData,
};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::ProgramResult, Mollusk};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use zolana_interface::{
    instruction::instruction_data::transact::{TransactIxData, TransactProof},
    verifying_keys::CircuitId,
};

struct QueueFixture {
    pair_address: Address,
    escrow_address: Address,
    recipient: Address,
    pair: Pair,
    escrow: Escrow,
}

impl QueueFixture {
    fn new() -> Self {
        let authority = Address::new_unique();
        let recipient = Address::new_unique();
        let pair_address = pair_pda(&authority, 1, 2);
        Self {
            pair_address,
            escrow_address: escrow_pda(&pair_address, 0),
            recipient,
            pair: Pair {
                discriminator: PAIR,
                bump: 0,
                _pad: [0; 6],
                authority,
                source_asset_id: 1,
                destination_asset_id: 2,
                price: 10,
                expiry_slots: 100,
                max_order_size: 10,
                price_tolerance: 1,
                min_order_amount: 1,
                available_liquidity: 100,
                open_reservations: 2,
                next_order_id: 2,
                head_order_id: 0,
                source_asset: [1; 32],
                destination_asset: [2; 32],
                maker_receipt_owner_hash: [3; 32],
                maker_encryption_pubkey: [4; 33],
                _pad2: [0; 7],
            },
            escrow: Escrow {
                discriminator: ESCROW,
                bump: 0,
                cancelled: 0,
                _pad: [0; 5],
                pair: pair_address,
                order_utxo_hash: [5; 32],
                owner: recipient,
                expires_at: 10,
                execution_price: 10,
                order_id: 0,
            },
        }
    }

    fn accounts(&self) -> Vec<(Address, Account)> {
        vec![
            (self.pair_address, state_account(&self.pair)),
            (self.escrow_address, state_account(&self.escrow)),
            (self.recipient, funded_account()),
            (self.pair.authority, funded_account()),
        ]
    }

    fn skip(&self) -> Instruction {
        SkipExpired {
            pair: self.pair_address,
            escrow: self.escrow_address,
            rent_recipient: self.recipient,
        }
        .instruction()
    }

    fn resolve(&self, settle: bool) -> Result<Instruction> {
        let (instruction_tag, serialized) = if settle {
            (
                tag::SETTLE,
                wincode::serialize(&SettleIxData {
                    proof: invalid_proof(),
                    transact: empty_transact(),
                })?,
            )
        } else {
            (
                tag::CANCEL,
                wincode::serialize(&CancelIxData {
                    proof: invalid_proof(),
                    transact: empty_transact(),
                })?,
            )
        };
        let mut instruction_data = vec![instruction_tag];
        instruction_data.extend(serialized);
        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts: vec![
                AccountMeta::new(self.pair.authority, true),
                AccountMeta::new(self.pair_address, false),
                AccountMeta::new(self.escrow_address, false),
                AccountMeta::new(self.recipient, false),
            ],
            data: instruction_data,
        })
    }
}

fn state_account(state: &impl bytemuck::Pod) -> Account {
    Account {
        data: bytemuck::bytes_of(state).to_vec(),
        owner: dynamic_swap_program::ID,
        ..funded_account()
    }
}

fn funded_account() -> Account {
    Account {
        lamports: 1_000_000_000,
        ..Account::default()
    }
}

fn runtime(slot: u64) -> Result<Mollusk> {
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../target/deploy/dynamic_swap_program.so"
    ))?;
    let mut mollusk = Mollusk::default();
    mollusk.add_program_with_loader_and_elf(&dynamic_swap_program::ID, &LOADER_V3, &elf);
    mollusk.sysvars.clock.slot = slot;
    Ok(mollusk)
}

fn invalid_proof() -> Groth16ProofBytes {
    Groth16ProofBytes {
        proof_a: [0; 32],
        proof_b: [0; 64],
        proof_c: [0; 32],
    }
}

fn empty_transact() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 0),
        tx_viewing_pk: [4; 33],
        salt: [0; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![],
        tree_contexts: vec![],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![],
        messages: vec![],
    }
}

#[test]
fn skip_rejects_at_deadline_and_preserves_the_refund_after_it() -> Result<()> {
    let fixture = QueueFixture::new();
    let accounts = fixture.accounts();
    let mut mollusk = runtime(fixture.escrow.expires_at)?;
    let rejected = mollusk.process_instruction(&fixture.skip(), &accounts);
    assert_eq!(
        (rejected.program_result, rejected.resulting_accounts),
        (
            ProgramResult::Failure(DynamicSwapError::NotYetExpired.into()),
            accounts.clone(),
        ),
        "expiry advancement must reject at the inclusive settlement deadline"
    );

    mollusk.sysvars.clock.slot += 1;
    let skipped = mollusk.process_instruction(&fixture.skip(), &accounts);
    let mut expected = accounts;
    let pair_account = expected
        .iter_mut()
        .find(|(address, _)| *address == fixture.pair_address)
        .ok_or_else(|| anyhow!("missing pair fixture"))?;
    pair_account.1 = state_account(&Pair {
        head_order_id: 1,
        ..fixture.pair
    });
    assert_eq!(
        (skipped.program_result, skipped.resulting_accounts),
        (ProgramResult::Success, expected),
        "skipping must change only the head, retaining the refund and reservation"
    );
    Ok(())
}

#[test]
fn settlement_and_cancellation_partition_the_stored_deadline() -> Result<()> {
    let fixture = QueueFixture::new();
    let accounts = fixture.accounts();
    let mut mollusk = runtime(fixture.escrow.expires_at)?;
    let cancellation = mollusk.process_instruction(&fixture.resolve(false)?, &accounts);
    assert_eq!(
        cancellation.program_result,
        ProgramResult::Failure(DynamicSwapError::NotYetExpired.into()),
        "cancellation is unavailable at the settlement deadline"
    );
    // The empty input list rejects only after the deadline check, before the
    // invalid settlement proof is verified.
    let settlement = mollusk.process_instruction(&fixture.resolve(true)?, &accounts);
    assert_eq!(
        settlement.program_result,
        ProgramResult::Failure(DynamicSwapError::InvalidInstructionData.into()),
        "settlement must pass the deadline gate at the exact deadline"
    );
    mollusk.sysvars.clock.slot += 1;
    let settlement = mollusk.process_instruction(&fixture.resolve(true)?, &accounts);
    assert_eq!(
        (settlement.program_result, settlement.resulting_accounts),
        (
            ProgramResult::Failure(DynamicSwapError::Expired.into()),
            accounts,
        ),
        "settlement after expiry must preserve every account"
    );
    Ok(())
}

#[test]
fn creation_rejects_an_overflowing_deadline_before_accepting_funds() -> Result<()> {
    let mut fixture = QueueFixture::new();
    fixture.pair.expiry_slots = u64::MAX;
    let system_program = Address::default();
    let new_escrow = escrow_pda(&fixture.pair_address, fixture.pair.next_order_id);
    let mut instruction_data = vec![tag::CREATE_ESCROW];
    instruction_data.extend(wincode::serialize(&CreateEscrowIxData {
        proof: invalid_proof(),
        public_price_floor: 9,
        transact: empty_transact(),
    })?);
    let instruction = Instruction {
        program_id: dynamic_swap_program::ID,
        accounts: vec![
            AccountMeta::new(fixture.recipient, true),
            AccountMeta::new(fixture.pair_address, false),
            AccountMeta::new(new_escrow, false),
            AccountMeta::new_readonly(system_program, false),
        ],
        data: instruction_data,
    };
    let accounts = vec![
        (fixture.recipient, funded_account()),
        (fixture.pair_address, state_account(&fixture.pair)),
        (new_escrow, Account::default()),
        (system_program, Account::default()),
    ];
    let rejected = runtime(1)?.process_instruction(&instruction, &accounts);
    assert_eq!(
        (rejected.program_result, rejected.resulting_accounts),
        (
            ProgramResult::Failure(ProgramError::ArithmeticOverflow),
            accounts,
        ),
        "an unrepresentable deadline must not allocate an escrow or reserve funds"
    );
    Ok(())
}
