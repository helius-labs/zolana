//! `transact` negatives.
//!
//! Everything asserted here is pre-CPI: the instruction ends in a CPI to SPP,
//! whose binary is not loaded into mollusk, so the successful forward is covered
//! by the localnet end-to-end test. The proof-rejection cases below do run the
//! real BSB22 verifier against the committed verifying key, which is what proves
//! the recomputed public-input hash path is reached.

use custom_ring_program::{
    error::CustomRingError,
    instructions::transact::{AuditProof, CustomRingTransactIxData, AUDITOR_MESSAGE_LEN},
    tag,
};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{CircuitId, MessageData, TransactIxData, TransactProof},
    verifying_keys::{Bsb22Commitment, RingP256ProofData},
    N_PUBLIC_SLOTS,
};
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, auditor_pubkey, authority, config_pda, initialized_config_account, payer, program_id,
    ring_auth_pda, setup_mollusk, spp_program_account, substitute_account,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The auditor key this fixture's config account carries, and the view tag its
/// messages must use: the compressed key minus its SEC1 prefix.
fn config_auditor_pubkey() -> [u8; 33] {
    auditor_pubkey(2)
}

fn auditor_view_tag() -> [u8; 32] {
    let key = config_auditor_pubkey();
    let mut view_tag = [0u8; 32];
    view_tag.copy_from_slice(key.get(1..33).expect("compressed key x-coordinate"));
    view_tag
}

fn auditor_message(data_len: usize) -> MessageData {
    MessageData {
        view_tag: auditor_view_tag(),
        data: vec![4u8; data_len],
    }
}

fn other_message() -> MessageData {
    MessageData {
        view_tag: [88u8; 32],
        data: vec![5u8; 8],
    }
}

/// Wire-valid `RingEddsa` payload; callers override the fields they attack.
fn transact(messages: Vec<MessageData>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [1; 32],
        circuit: CircuitId::RingEddsa(2, 3, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages,
    }
}

/// A syntactically well-formed proof that cannot verify. Zeroed points decompress
/// to the identity, so a `0xFF` commitment is the first point the verifier fails
/// on, which exercises the BSB22 commitment path itself.
fn bogus_proof() -> AuditProof {
    AuditProof {
        proof_a: [0; 32],
        proof_b: [0; 64],
        proof_c: [0; 32],
        commitment: [0xFF; 32],
        commitment_pok: [0xFF; 32],
    }
}

fn instruction_data(proof: AuditProof, transact: TransactIxData) -> Vec<u8> {
    let mut data = vec![tag::TRANSACT];
    data.extend_from_slice(
        &wincode::serialize(&CustomRingTransactIxData { proof, transact })
            .expect("serialize transact body"),
    );
    data
}

/// `[payer(w,s), config]` followed by SPP's `RING_TRANSACT` list: `payer(w,s),
/// input_tree(w), output_tree(w), spp_program, system_program, ring_config`. The
/// caller supplies the config account so negatives can pass an uninitialized one.
fn transact_fixture(config: Account, data: Vec<u8>) -> (Instruction, Vec<(Pubkey, Account)>) {
    let (config_key, _) = config_pda();
    let (ring_auth, _) = ring_auth_pda();
    let input_tree = Pubkey::new_from_array([41; 32]);
    let output_tree = Pubkey::new_from_array([42; 32]);
    let (system_program, system_program_account) =
        mollusk_svm::program::keyed_account_for_system_program();
    let (spp_id, spp_account) = spp_program_account();

    (
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(payer(), true),
                AccountMeta::new_readonly(config_key, false),
                AccountMeta::new(payer(), true),
                AccountMeta::new(input_tree, false),
                AccountMeta::new(output_tree, false),
                AccountMeta::new_readonly(spp_id, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new_readonly(ring_auth, false),
            ],
            data,
        },
        vec![
            (payer(), account(1_000_000_000)),
            (config_key, config),
            (input_tree, account(1_000_000_000)),
            (output_tree, account(1_000_000_000)),
            (spp_id, spp_account),
            (system_program, system_program_account),
            (ring_auth, account(1_000_000_000)),
        ],
    )
}

fn valid_config() -> Account {
    initialized_config_account(authority(), config_auditor_pubkey())
}

/// Fixture whose only defect is the caller-supplied message list.
fn fixture_with_messages(messages: Vec<MessageData>) -> (Instruction, Vec<(Pubkey, Account)>) {
    transact_fixture(
        valid_config(),
        instruction_data(bogus_proof(), transact(messages)),
    )
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    instruction.data.truncate(instruction.data.len() / 2);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

#[test]
fn garbage_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    instruction.data = vec![tag::TRANSACT, 7, 7, 7, 7];
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    instruction.data.push(0);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

#[test]
fn uninitialized_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = transact_fixture(
        account(0),
        instruction_data(
            bogus_proof(),
            transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]),
        ),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ConfigNotInitialized),
    );
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    substitute_account(
        &mut instruction,
        &mut accounts,
        5,
        Pubkey::new_from_array([81; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

/// The P256 ownership rail is a different proof shape with ownership semantics
/// this ring never reviewed, so it is refused instead of forwarded.
#[test]
fn ring_p256_circuit_selector_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    data.circuit = CircuitId::RingP256(
        2,
        3,
        N_PUBLIC_SLOTS as u8,
        RingP256ProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [6; 32],
                commitment_pok: [7; 32],
            },
            default_owner_tag: None,
        },
    );
    let (instruction, accounts) =
        transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnsupportedCircuit),
    );
}

#[test]
fn missing_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture_with_messages(Vec::new());
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::MissingAuditorMessage),
    );
}

#[test]
fn message_without_the_auditor_view_tag_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture_with_messages(vec![other_message()]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::MissingAuditorMessage),
    );
}

#[test]
fn short_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN - 1)]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidAuditorMessage),
    );
}

#[test]
fn long_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN + 1)]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidAuditorMessage),
    );
}

/// Exactly one message may claim the auditor's view tag: the proof covers one
/// ciphertext, so a second tagged payload could be mistaken for the proven one.
#[test]
fn two_auditor_messages_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture_with_messages(vec![
        auditor_message(AUDITOR_MESSAGE_LEN),
        auditor_message(AUDITOR_MESSAGE_LEN),
    ]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidAuditorMessage),
    );
}

/// The auditor message must be the last entry; free-form messages may only
/// precede it.
#[test]
fn auditor_message_before_the_last_entry_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN), other_message()]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidAuditorMessage),
    );
}

/// A well-formed auditor message and a wire-valid proof that cannot verify: the
/// program recomputes the public-input hash and the BSB22 verifier rejects. This
/// is the case that proves the verifier is reached at all.
#[test]
fn unverifiable_proof_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) =
        fixture_with_messages(vec![other_message(), auditor_message(AUDITOR_MESSAGE_LEN)]);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ProofVerificationFailed),
    );
}

/// Same, with an all-zero commitment: the decompressions succeed and the
/// rejection comes from the pairing check rather than from point decoding.
#[test]
fn zeroed_proof_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = transact_fixture(
        valid_config(),
        instruction_data(
            AuditProof {
                proof_a: [0; 32],
                proof_b: [0; 64],
                proof_c: [0; 32],
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]),
        ),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ProofVerificationFailed),
    );
}
