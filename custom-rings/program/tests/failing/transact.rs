//! `transact` negatives.
//!
//! Everything asserted here is pre-CPI: the instruction ends in a CPI to SPP,
//! whose binary is not loaded into mollusk, so the successful forward is covered
//! by the localnet end-to-end test. The proof-rejection cases below do run the
//! real BSB22 verifier against the committed verifying key, which is what proves
//! the recomputed public-input hash path is reached.

use custom_ring_interface::{tag, CustomRingProof, DisclosureShape, PlainGroth16Proof};
use custom_ring_program::CustomRingError;
use solana_account::Account;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_interface::{
    event::{
        CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG,
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    },
    instruction::{
        instruction_data::transact::InputUtxo, CircuitId, MessageData, OwnerTag, TransactIxData,
        TransactOutput, TransactProof, TreeContext,
    },
    verifying_keys::{Bsb22Commitment, RingP256ProofData},
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, anonymous_config_account, audit_ix_data, auditor_message_len, auditor_pubkey,
    authority, config_account_in_mode, disclosed_message_len, encode_transact,
    initialized_config_account, legacy_auditor_pubkey, namespace_pda, policy_ix_data,
    setup_mollusk, transact_fixture, velocity_policy_config_account, Fixture,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The auditor key this fixture's config account carries, and the view tag its
/// messages must use: the key minus its tag byte.
fn config_auditor_pubkey() -> [u8; 33] {
    auditor_pubkey(4)
}

fn auditor_view_tag() -> [u8; 32] {
    let key = config_auditor_pubkey();
    let mut view_tag = [0u8; 32];
    view_tag.copy_from_slice(key.get(1..33).expect("key u-coordinate"));
    view_tag
}

pub(crate) fn auditor_message(data_len: usize) -> MessageData {
    let mut data = Vec::from(auditor_pubkey(4));
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

/// Wire-valid `RingEddsa` content; callers override the fields they attack.
pub(crate) fn transact(messages: Vec<MessageData>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [1; 32],
        circuit: CircuitId::RingEddsa(2, 2, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: auditor_pubkey(4),
        salt: [3; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![encrypted_output(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG)],
        messages,
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    }
}

/// A syntactically well-formed proof that cannot verify. Zeroed points decompress
/// to the identity, so a `0xFF` commitment is the first point the verifier fails
/// on, which exercises the BSB22 commitment path itself.
pub(crate) fn bogus_proof() -> CustomRingProof {
    CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
        commitment: [0xFF; 32],
        commitment_pok: [0xFF; 32],
    }
}

/// The policy layout, one policy tree.
pub(crate) fn instruction_data(proof: CustomRingProof, transact: TransactIxData) -> Vec<u8> {
    encode_transact(tag::TRANSACT, &policy_ix_data(proof, transact))
}

/// The audit-only layout, no policy trees.
pub(crate) fn audit_instruction_data(proof: CustomRingProof, transact: TransactIxData) -> Vec<u8> {
    encode_transact(tag::TRANSACT, &audit_ix_data(proof, transact))
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
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
    let half = fixture.data_mut().len() / 2;
    fixture.data_mut().truncate(half);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn garbage_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
    *fixture.data_mut() = vec![tag::TRANSACT, 7, 7, 7, 7];
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
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
            transact(vec![auditor_message(auditor_message_len(1))]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
}

#[test]
fn non_canonical_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
    // A foreign address holds no valid config, so the load fails before the
    // canonicality check.
    fixture.substitute("config", Pubkey::new_from_array([73; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
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
            transact(vec![auditor_message(auditor_message_len(1))]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidConfigPda));
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
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
        2,
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
        CircuitId::RingAuthority(2, 2, slots),
        CircuitId::ConfidentialEddsa(2, 2, slots),
    ] {
        let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
        data.circuit = circuit;
        let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
        fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    }
}

#[test]
fn an_unexecutable_spp_program_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
    fixture.set_account("spp_program", account(1));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn an_unsigned_payer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
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
    let mut fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1))]);
    fixture.truncate(2);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

fn encrypted_output(scheme: u8) -> TransactOutput {
    let mut body = vec![scheme];
    body.extend_from_slice(&auditor_pubkey(4));
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
    let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
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
    let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
    let mut output = encrypted_output(3);
    output.data = None;
    data.outputs = vec![output];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn confidential_output_with_an_invalid_key_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut low_order = [0u8; 33];
    low_order[0] = 4;
    let mut alias = auditor_pubkey(4);
    alias[32] |= 0x80;
    for key in [[0u8; 33], low_order, alias] {
        let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
        data.outputs = vec![confidential_output(
            RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            key,
            &[9],
        )];
        let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
        fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
    }
}

#[test]
fn confidential_output_with_a_p256_key_tag_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
    data.outputs = vec![confidential_output(
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        auditor_pubkey(2),
        &[9],
    )];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), data));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedOutputScheme));
}

#[test]
fn confidential_output_with_empty_ciphertext_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
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
    let mut data = transact(vec![auditor_message(auditor_message_len(2))]);
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
    let fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1) - 1)]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

#[test]
fn long_auditor_message_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![auditor_message(auditor_message_len(1) + 1)]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

/// Exactly one message may claim the auditor's view tag: the proof covers one
/// ciphertext, so a second tagged ciphertext could be mistaken for the proven one.
#[test]
fn two_auditor_messages_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![
        auditor_message(auditor_message_len(1)),
        auditor_message(auditor_message_len(1)),
    ]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

/// The auditor message must be the last entry; free-form messages may only
/// precede it.
#[test]
fn auditor_message_before_the_last_entry_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![
        auditor_message(auditor_message_len(1)),
        other_message(),
    ]);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

/// A well-formed auditor message and a wire-valid proof that cannot verify: the
/// program recomputes the public-input hash and the BSB22 verifier rejects. This
/// is the case that proves the verifier is reached at all.
#[test]
fn unverifiable_proof_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = fixture_with_messages(vec![
        other_message(),
        auditor_message(auditor_message_len(1)),
    ]);
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
                groth16: PlainGroth16Proof {
                    proof_a: [0; 32],
                    proof_b: [0; 64],
                    proof_c: [0; 32],
                },
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            transact(vec![auditor_message(auditor_message_len(1))]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_legacy_auditor_key_is_refused_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = transact_fixture(
        initialized_config_account(authority(), legacy_auditor_pubkey()),
        instruction_data(
            bogus_proof(),
            transact(vec![auditor_message(auditor_message_len(1))]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::LegacyAuditorKey));
}

#[test]
fn an_unknown_ring_mode_is_refused_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = transact_fixture(
        config_account_in_mode(3),
        instruction_data(
            bogus_proof(),
            transact(vec![auditor_message(auditor_message_len(1))]),
        ),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidRingMode));
}

#[test]
fn an_approval_flag_needs_amount_controls_and_a_boolean_exactly() {
    let (mollusk, _) = setup_mollusk();
    for approval_required in [1, 2] {
        let mut ix = policy_ix_data(
            bogus_proof(),
            transact(vec![auditor_message(auditor_message_len(1))]),
        );
        ix.approval_required = approval_required;
        let fixture = transact_fixture(valid_config(), encode_transact(tag::TRANSACT, &ix));
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
    }
}

#[test]
fn a_registry_index_without_key_escrow_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = policy_ix_data(
        bogus_proof(),
        transact(vec![auditor_message(auditor_message_len(1))]),
    );
    ix.key_registry_root_index = 1;
    let fixture = transact_fixture(valid_config(), encode_transact(tag::TRANSACT, &ix));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

/// Only the windowed statement verifies a record, so no other statement may
/// publish a message a recovery would read as one.
#[test]
fn record_messages_outside_the_windowed_statement_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let namespace = namespace_pda().0.to_bytes();
    let record_tag =
        zolana_ring_policy::spend_record_message_tag(&namespace).expect("record message tag");
    for view_tag in [namespace, record_tag] {
        let fixture = fixture_with_messages(vec![
            MessageData {
                view_tag,
                data: vec![1; 8],
            },
            auditor_message(auditor_message_len(1)),
        ]);
        fixture.expect_err(&mollusk, custom(CustomRingError::UnexpectedRecordMessage));
    }
}

fn hidden_output() -> TransactOutput {
    TransactOutput {
        owner_tag: OwnerTag::Inline([0; 32]),
        ..encrypted_output(RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG)
    }
}

/// A hidden-owner transfer as an anonymous ring admits it.
fn anonymous_transact(inputs: u8, outputs: u8) -> TransactIxData {
    let shape = DisclosureShape {
        anonymous: true,
        inputs: usize::from(inputs),
        outputs: usize::from(outputs),
    };
    let mut data = transact(vec![auditor_message(disclosed_message_len(shape))]);
    data.circuit = CircuitId::RingEd25519(
        inputs,
        outputs,
        N_PUBLIC_SLOTS as u8,
        Bsb22Commitment {
            commitment: [6; 32],
            commitment_pok: [7; 32],
        },
    );
    data.inputs = (0..inputs)
        .map(|index| InputUtxo {
            nullifier_hash: [index + 1; 32],
            tree_index: 0,
        })
        .collect();
    data.outputs = (0..outputs).map(|_| hidden_output()).collect();
    data
}

fn anonymous_fixture(data: TransactIxData) -> Fixture {
    transact_fixture(
        anonymous_config_account(),
        instruction_data(bogus_proof(), data),
    )
}

#[test]
fn anonymous_hidden_owner_transfers_reach_the_proof() {
    let (mollusk, _) = setup_mollusk();
    for (inputs, outputs) in [(2, 2), (2, 4), (3, 4), (4, 2)] {
        anonymous_fixture(anonymous_transact(inputs, outputs))
            .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    }
}

#[test]
fn an_anonymous_ring_refuses_every_other_rail_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut eddsa = anonymous_transact(2, 2);
    eddsa.circuit = CircuitId::RingEddsa(2, 2, N_PUBLIC_SLOTS as u8);
    anonymous_fixture(eddsa).expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    anonymous_fixture(anonymous_transact(1, 2))
        .expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    let mut hidden = anonymous_transact(2, 2);
    hidden.messages = vec![auditor_message(auditor_message_len(2))];
    let fixture = transact_fixture(valid_config(), instruction_data(bogus_proof(), hidden));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
}

#[test]
fn an_anonymous_output_with_an_owner_tag_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut data = anonymous_transact(2, 2);
    data.outputs[1].owner_tag = OwnerTag::Inline([5; 32]);
    anonymous_fixture(data).expect_err(&mollusk, custom(CustomRingError::InvalidAnonymousOutput));
    let mut data = anonymous_transact(2, 2);
    data.outputs[0].owner_tag = OwnerTag::Account(0);
    anonymous_fixture(data).expect_err(&mollusk, custom(CustomRingError::InvalidAnonymousOutput));
}

/// Any signer besides the payer would publish an owner the hidden rail hides.
#[test]
fn an_anonymous_transaction_with_another_signer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut signed_tree = anonymous_fixture(anonymous_transact(2, 2));
    signed_tree.sign("input_tree");
    signed_tree.expect_err(&mollusk, custom(CustomRingError::InvalidAnonymousSigner));
    let mut other_payer = anonymous_fixture(anonymous_transact(2, 2));
    other_payer.substitute("spp_payer", Pubkey::new_from_array([78; 32]));
    other_payer.expect_err(&mollusk, custom(CustomRingError::InvalidAnonymousSigner));
}

#[test]
fn an_anonymous_disclosure_must_cover_the_inputs_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut data = anonymous_transact(2, 2);
    data.messages = vec![auditor_message(auditor_message_len(2))];
    anonymous_fixture(data).expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

#[test]
fn an_anonymous_ring_refuses_a_windowed_velocity_policy_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = anonymous_fixture(anonymous_transact(2, 2));
    fixture.set_account("policy_config", velocity_policy_config_account());
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::UnsupportedAnonymousPolicy),
    );
}
