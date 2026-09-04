//! `transact` negatives.
//!
//! Everything asserted here is pre-CPI: the instruction ends in a CPI to SPP,
//! whose binary is not loaded into mollusk, so the successful forward is covered
//! by the localnet end-to-end test. The proof-rejection cases below do run the
//! real BSB22 verifier against the committed verifying key, which is what proves
//! the recomputed public-input hash path is reached.

use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData, AUDITOR_MESSAGE_LEN};
use custom_ring_program::CustomRingError;
use solana_account::Account;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_interface::{
    instruction::{
        CircuitId, MessageData, OwnerTag, TransactIxData, TransactOutput, TransactProof,
    },
    output_data::{CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG},
    verifying_keys::{Bsb22Commitment, RingP256ProofData},
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, auditor_pubkey, authority, initialized_config_account, setup_mollusk,
    transact_fixture, Fixture,
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
    let mut data = Vec::from(auditor_pubkey(3));
    data.extend_from_slice(&[4u8; 32]);
    data.resize(data_len, 4);
    MessageData {
        view_tag: auditor_view_tag(),
        data,
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
        tx_viewing_pk: auditor_pubkey(3),
        salt: [3; 16],
        interface_transfers: Vec::new(),
        outputs: Vec::new(),
        messages,
        data_hash: None,
        ring_data_hash: None,
        circuit: CircuitId::RingEddsa(2, 3, N_PUBLIC_SLOTS as u8),
        proof: TransactProof::zeroed(),
        private_tx_hash: [1; 32],
        inputs: Vec::new(),
    }
}

/// A syntactically well-formed proof that cannot verify. Zeroed points decompress
/// to the identity, so a `0xFF` commitment is the first point the verifier fails
/// on, which exercises the BSB22 commitment path itself.
fn bogus_proof() -> CustomRingProof {
    CustomRingProof {
        proof_a: [0; 32],
        proof_b: [0; 64],
        proof_c: [0; 32],
        commitment: [0xFF; 32],
        commitment_pok: [0xFF; 32],
    }
}

fn instruction_data(proof: CustomRingProof, transact: TransactIxData) -> Vec<u8> {
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
fn valid_config() -> Account {
    initialized_config_account(authority(), config_auditor_pubkey())
}

/// Fixture whose only defect is the caller-supplied message list.
fn fixture_with_messages(messages: Vec<MessageData>) -> Fixture {
    transact_fixture(
        valid_config(),
        instruction_data(bogus_proof(), transact(messages)),
    )
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    let half = fixture.data_mut().len() / 2;
    fixture.data_mut().truncate(half);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn garbage_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    *fixture.data_mut() = vec![tag::TRANSACT, 7, 7, 7, 7];
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    fixture.data_mut().push(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn uninitialized_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = transact_fixture(
        account(0),
        instruction_data(
            bogus_proof(),
            transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
}

#[test]
fn non_canonical_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    fixture.substitute("config", Pubkey::new_from_array([73; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidConfigPda));
}

#[test]
fn config_with_a_wrong_bump_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut config = valid_config();
    let state =
        bytemuck::from_bytes_mut::<custom_ring_interface::RingProgramConfig>(&mut config.data);
    state.bump ^= 1;
    let fixture = transact_fixture(
        config,
        instruction_data(
            bogus_proof(),
            transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidConfigPda));
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    fixture.substitute("spp_program", Pubkey::new_from_array([81; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

/// The eddsa ring reviewed exactly one proof shape, every other selector is
/// refused instead of forwarded.
#[test]
fn non_ring_eddsa_circuit_selectors_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let slots = N_PUBLIC_SLOTS as u8;
    let p256 = CircuitId::RingP256(
        2,
        3,
        slots,
        RingP256ProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [6; 32],
                commitment_pok: [7; 32],
            },
            default_owner_tag: None,
        },
    );
    for circuit in [
        p256,
        CircuitId::RingAuthority(2, 3, slots),
        CircuitId::ConfidentialEddsa(2, 3, slots),
    ] {
        let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
        data.circuit = circuit;
        let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
        fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    }
}

#[test]
fn an_unexecutable_spp_program_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    fixture.set_account("spp_program", account(1));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn an_unsigned_payer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    // The spp_payer meta shares the pubkey, one signing meta would keep the
    // account's merged signer privilege.
    fixture.unsign("payer");
    fixture.unsign("spp_payer");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn missing_forwarded_accounts_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    fixture.truncate(2);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

fn encrypted_output(scheme: u8) -> TransactOutput {
    let mut body = vec![scheme];
    body.extend_from_slice(&auditor_pubkey(3));
    body.push(9);
    let mut data = vec![1];
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(&body);
    TransactOutput {
        utxo_hash: [4; 32],
        owner_tag: OwnerTag::Inline([5; 32]),
        data: Some(data),
    }
}

fn confidential_output(scheme: u8, key: [u8; 33], ciphertext: &[u8]) -> TransactOutput {
    let mut output = encrypted_output(scheme);
    let mut body = vec![scheme];
    body.extend_from_slice(&key);
    body.extend_from_slice(ciphertext);
    let mut data = vec![1];
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(&body);
    output.data = Some(data);
    output
}

#[test]
fn anonymous_scheme_output_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    data.outputs = vec![
        encrypted_output(RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG),
        encrypted_output(1),
    ];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn output_without_ciphertext_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    let mut output = encrypted_output(3);
    output.data = None;
    data.outputs = vec![output];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn confidential_output_with_an_invalid_key_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    data.outputs = vec![confidential_output(
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        [0u8; 33],
        &[9],
    )];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn confidential_output_with_empty_ciphertext_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    data.outputs = vec![confidential_output(
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        auditor_pubkey(7),
        &[],
    )];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn confidential_outputs_reach_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]);
    data.outputs = vec![
        encrypted_output(RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG),
        encrypted_output(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG),
    ];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn missing_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(Vec::new());
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingAuditorMessage));
}

#[test]
fn message_without_the_auditor_view_tag_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![other_message()]);
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingAuditorMessage));
}

#[test]
fn short_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN - 1)]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

#[test]
fn long_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN + 1)]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

/// Exactly one message may claim the auditor's view tag: the proof covers one
/// ciphertext, so a second tagged payload could be mistaken for the proven one.
#[test]
fn two_auditor_messages_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![
        auditor_message(AUDITOR_MESSAGE_LEN),
        auditor_message(AUDITOR_MESSAGE_LEN),
    ]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

/// The auditor message must be the last entry; free-form messages may only
/// precede it.
#[test]
fn auditor_message_before_the_last_entry_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture =
        fixture_with_messages(vec![auditor_message(AUDITOR_MESSAGE_LEN), other_message()]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

/// A well-formed auditor message and a wire-valid proof that cannot verify: the
/// program recomputes the public-input hash and the BSB22 verifier rejects. This
/// is the case that proves the verifier is reached at all.
#[test]
fn unverifiable_proof_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture =
        fixture_with_messages(vec![other_message(), auditor_message(AUDITOR_MESSAGE_LEN)]);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// Same, with an all-zero commitment: the decompressions succeed and the
/// rejection comes from the pairing check rather than from point decoding.
#[test]
fn zeroed_proof_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = transact_fixture(
        valid_config(),
        instruction_data(
            CustomRingProof {
                proof_a: [0; 32],
                proof_b: [0; 64],
                proof_c: [0; 32],
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            transact(vec![auditor_message(AUDITOR_MESSAGE_LEN)]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}
