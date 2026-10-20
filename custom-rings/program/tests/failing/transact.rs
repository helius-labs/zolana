//! `transact` negatives.
//!
//! Everything asserted here is pre-CPI: the instruction ends in a CPI to SPP,
//! whose binary is not loaded into mollusk, so the successful forward is covered
//! by the localnet end-to-end test. The proof-rejection cases below do run the
//! real BSB22 verifier against the committed verifying key, which is what proves
//! the recomputed public-input hash path is reached.

use custom_ring_interface::CustomRingError;
use custom_ring_interface::{tag, CustomRingProof, DisclosureShape, PlainGroth16Proof};
use solana_account::Account;
use solana_instruction::AccountMeta;
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
    verifying_keys::{AnonymousRingEddsaProofData, Bsb22Commitment},
    N_PUBLIC_SLOTS,
};

use crate::common::{
    account, anonymous_config_account, audit_ix_data, auditor_message_len, auditor_pubkey,
    authority, config_account_in_mode, disclosed_message_len, encode_transact,
    initialized_config_account, limit_policy_config_account, policy_ix_data, setup_mollusk,
    transact_fixture, Fixture, Slot,
};

const PROOF_DATA: AnonymousRingEddsaProofData = AnonymousRingEddsaProofData {
    bsb22_commitment: Bsb22Commitment {
        commitment: [6; 32],
        commitment_pok: [7; 32],
    },
    default_owner_tag: None,
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

/// Wire-valid `ConfidentialRingEddsa` content; callers override the fields they attack.
pub(crate) fn transact(messages: Vec<MessageData>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [1; 32],
        circuit: CircuitId::ConfidentialRingEddsa(2, 2, N_PUBLIC_SLOTS as u8),
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

/// Owner and discriminator stand in for the address, the program creates
/// configs only at the canonical PDA.
#[test]
fn a_foreign_owned_or_mistagged_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut foreign = valid_config();
    foreign.owner = Pubkey::new_from_array([69; 32]);
    let mut mistagged = valid_config();
    mistagged.data[0] = custom_ring_interface::POLICY_CONFIG;
    for config in [foreign, mistagged] {
        let fixture = transact_fixture(
            config,
            instruction_data(
                bogus_proof(),
                transact(vec![auditor_message(auditor_message_len(1))]),
            ),
        );
        fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
    }
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
    let anonymous = CircuitId::AnonymousRingEddsa(2, 2, slots, PROOF_DATA);
    for circuit in [
        anonymous,
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
    let mut alias = auditor_pubkey(4);
    alias[32] |= 0x80;
    for key in [[0u8; 33], alias] {
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

/// Output framing checks canonical encoding; decryptability is the recipient's responsibility.
#[test]
fn a_canonical_low_order_output_key_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut key = [0u8; 33];
    key[0] = custom_ring_interface::VIEWING_PUBKEY_TAG;
    let mut data = transact(vec![auditor_message(auditor_message_len(1))]);
    data.outputs = vec![confidential_output(
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        key,
        &[9],
    )];
    transact_fixture(valid_config(), instruction_data(bogus_proof(), data))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn confidential_output_with_a_reserved_key_tag_is_rejected() {
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

/// A SEC1 P-256 tag or a u-coordinate at or above the field prime is not a viewing key.
#[test]
fn confidential_output_with_a_non_x25519_key_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut noncanonical = auditor_pubkey(4);
    noncanonical[32] |= 0x80;
    for key in [auditor_pubkey(2), auditor_pubkey(3), noncanonical] {
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
fn an_approval_flag_needs_amount_controls() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = policy_ix_data(
        bogus_proof(),
        transact(vec![auditor_message(auditor_message_len(1))]),
    );
    ix.approval_required = true;
    let fixture = transact_fixture(valid_config(), encode_transact(tag::TRANSACT, &ix));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnexpectedApproval));
}

#[test]
fn a_stale_policy_registry_index_without_key_escrow_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = policy_ix_data(
        bogus_proof(),
        transact(vec![auditor_message(auditor_message_len(1))]),
    );
    ix.registry_root_index = 1;
    let fixture = transact_fixture(valid_config(), encode_transact(tag::TRANSACT, &ix));
    fixture.expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));
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
    data.circuit = CircuitId::AnonymousRingEddsa(inputs, outputs, N_PUBLIC_SLOTS as u8, PROOF_DATA);
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
    anonymous_fixture_with_config(data, anonymous_config_account())
}

fn anonymous_fixture_with_config(data: TransactIxData, config: Account) -> Fixture {
    let input_count = data.inputs.len();
    let mut fixture = transact_fixture(config, instruction_data(bogus_proof(), data));
    for index in 0..input_count {
        fixture.push(Slot {
            label: "nullifier_pda",
            meta: AccountMeta::new(Pubkey::new_from_array([80 + index as u8; 32]), false),
            account: account(1_000_000_000),
        });
    }
    fixture
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
    let mut confidential = anonymous_transact(2, 2);
    confidential.circuit = CircuitId::ConfidentialRingEddsa(2, 2, N_PUBLIC_SLOTS as u8);
    anonymous_fixture(confidential)
        .expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    anonymous_fixture(anonymous_transact(8, 4))
        .expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    let mut hidden = anonymous_transact(2, 2);
    hidden.messages = vec![auditor_message(auditor_message_len(2))];
    let fixture = anonymous_fixture_with_config(hidden, valid_config());
    fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
}

/// An anonymous output's owner tag is its view tag, bound by the SPP proof.
#[test]
fn an_anonymous_output_view_tag_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    for (index, tag) in [(1, OwnerTag::Inline([5; 32])), (0, OwnerTag::Account(0))] {
        let mut data = anonymous_transact(2, 2);
        data.outputs[index].owner_tag = tag;
        anonymous_fixture(data)
            .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    }
}

/// Any signer besides the payer would publish an owner the hidden rail hides.
#[test]
fn an_anonymous_transaction_with_another_signer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut signed_tree = anonymous_fixture(anonymous_transact(2, 2));
    signed_tree.sign("input_tree");
    signed_tree.expect_err(&mollusk, custom(CustomRingError::InvalidAnonymousSigner));
}

/// The public sponsor is independent of the ring co-signer slots.
#[test]
fn an_anonymous_transaction_with_another_payer_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut other_payer = anonymous_fixture(anonymous_transact(2, 2));
    other_payer.substitute("spp_payer", Pubkey::new_from_array([78; 32]));
    other_payer.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn an_anonymous_disclosure_must_cover_the_inputs_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut data = anonymous_transact(2, 2);
    data.messages = vec![auditor_message(auditor_message_len(2))];
    anonymous_fixture(data).expect_err(&mollusk, custom(CustomRingError::InvalidAuditorMessage));
}

#[test]
fn an_anonymous_ring_with_outflow_limits_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = anonymous_fixture(anonymous_transact(2, 2));
    fixture.set_account("policy_config", limit_policy_config_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}
