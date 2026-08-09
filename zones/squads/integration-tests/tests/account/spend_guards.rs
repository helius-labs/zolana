//! Rejection tests for the guards every spend path runs before it verifies a
//! proof. Each case stops at its guard, so the forwarded proofs are zeroed
//! placeholders and no prover is needed. The happy paths live in
//! `transact_e2e`, `fold_transact_e2e`, and `execute_proposal_e2e`.

use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_BLOCKED,
    },
    error::SquadsZoneError,
    instruction::{
        builders::{ExecuteProposal, FoldTransact, Transact},
        instruction_data::{EncryptedUtxos, InputContext},
        ExecuteProposalIxData, FoldTransactIxData, FoldTransactLeg, TransactIxData,
    },
    state::{proposal::Proposal, viewing_key_account::ViewingKeyAccount, zone_config::ZoneConfig},
    types::Address,
    RING_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};

/// A BN254-range field element. The on-chain Poseidon rejects a value above the
/// modulus before the guard under test would run.
fn field(seed: u8) -> [u8; 32] {
    let mut f = [seed; 32];
    f[0] = 0;
    f
}

fn ring_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], program_id).0
}

fn seed_zone_config(test: &mut SquadsZoneTest, co_signer: &Pubkey) -> Pubkey {
    let pda = Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], &test.program_id).0;
    let config = ZoneConfig::new(
        Address::new_from_array([1u8; 32]),
        Address::new_from_array(co_signer.to_bytes()),
        3_600,
        vec![[9u8; 33]],
        vec![],
    );
    test.set_program_account(&pda, config.serialize().expect("serialize zone config"))
        .expect("seed zone config");
    pda
}

/// A keypair-owned account, so no path demands an owner signature. Only the
/// fields the guards read carry meaning.
fn seed_vka(test: &mut SquadsZoneTest, owner: [u8; 32], state: u8) -> Pubkey {
    let address = Keypair::new().pubkey();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner),
        state,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: [2u8; 33],
        shared_viewing_key_commitment: field(4),
        key_nonce: 0,
        nullifier_pubkey: field(5),
        key_ciphertext_ephemeral: [0u8; 33],
        encrypted_nullifier_secret: [0u8; 31],
        recovery_keys: vec![],
        recovery_key_ciphertexts: vec![],
        auditor_keys: vec![],
        auditor_key_ciphertexts: vec![],
    };
    test.set_program_account(&address, account.serialize().expect("serialize vka"))
        .expect("seed vka");
    address
}

fn input_context(seed: u8) -> InputContext {
    InputContext {
        nullifier: [seed; 32],
        tree_index: 0,
        utxo_root_index: 0,
        nullifier_root_index: 0,
    }
}

fn transfer_utxos() -> EncryptedUtxos {
    EncryptedUtxos {
        tx_viewing_pk: [2u8; 33],
        sender_ciphertext: [3u8; 40],
        recipient_ciphertexts: vec![[4u8; 71]],
    }
}

/// A `(2, 2)` transfer, the shape the operation names when `public_amount` is
/// absent.
fn transact_data(expiry: i64) -> TransactIxData {
    TransactIxData {
        zone_proof: [0u8; 192],
        spp_proof: [0u8; 192],
        public_amount: None,
        spl_interface_bump: 0,
        private_tx_hash: field(6),
        expiry,
        salt: [7u8; 16],
        output_view_tags: vec![[8u8; 32], [9u8; 32]],
        output_utxo_hashes: vec![[10u8; 32], [11u8; 32]],
        input_contexts: vec![input_context(12), input_context(13)],
        encrypted_utxos: transfer_utxos(),
    }
}

/// The zone config, the sender and recipient accounts, and the co-signer every
/// spend path reads.
struct Fixture {
    co_signer: Keypair,
    zone_config: Pubkey,
    sender: Pubkey,
    recipient: Pubkey,
}

fn fixture(test: &mut SquadsZoneTest, sender_state: u8, recipient_state: u8) -> Fixture {
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co-signer");
    let zone_config = seed_zone_config(test, &co_signer.pubkey());
    let sender = seed_vka(test, field(20), sender_state);
    let recipient = seed_vka(test, field(21), recipient_state);
    Fixture {
        co_signer,
        zone_config,
        sender,
        recipient,
    }
}

fn transact_ix(
    test: &SquadsZoneTest,
    f: &Fixture,
    co_signer: Pubkey,
    data: TransactIxData,
) -> Instruction {
    Transact {
        payer: test.payer.pubkey(),
        co_signer,
        zone_config: f.zone_config,
        sender_viewing_key_account: f.sender,
        recipient_viewing_key_account: Some(f.recipient),
        withdrawal: None,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data,
    }
    .instruction()
}

#[test]
fn transact_rejects_a_missing_payer_signature() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    // A relayer that is not the transaction fee payer, with its signer flag
    // dropped.
    let relayer = Keypair::new();
    let mut ix = transact_ix(&test, &f, f.co_signer.pubkey(), transact_data(i64::MAX));
    ix.accounts[0] = solana_instruction::AccountMeta::new(relayer.pubkey(), false);

    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected MissingAuthoritySignature");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MissingAuthoritySignature as u32
    );
}

#[test]
fn transact_rejects_a_missing_co_signer_signature() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let mut ix = transact_ix(&test, &f, f.co_signer.pubkey(), transact_data(i64::MAX));
    ix.accounts[1].is_signer = false;

    let err = test
        .send(&[ix], &[])
        .expect_err("expected MissingCoSignerSignature");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MissingCoSignerSignature as u32
    );
}

#[test]
fn transact_rejects_a_foreign_co_signer() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let impostor = Keypair::new();
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let ix = transact_ix(&test, &f, impostor.pubkey(), transact_data(i64::MAX));

    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("expected CoSignerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::CoSignerMismatch as u32);
}

#[test]
fn transact_rejects_a_blocked_sender() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_BLOCKED,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let ix = transact_ix(&test, &f, f.co_signer.pubkey(), transact_data(i64::MAX));
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ViewingKeyAccountBlocked");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ViewingKeyAccountBlocked as u32
    );
}

#[test]
fn transact_rejects_a_blocked_recipient() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_BLOCKED,
    );

    let ix = transact_ix(&test, &f, f.co_signer.pubkey(), transact_data(i64::MAX));
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ViewingKeyAccountBlocked");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ViewingKeyAccountBlocked as u32
    );
}

#[test]
fn transact_rejects_an_expired_transaction() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let expiry = test.unix_timestamp() + 60;
    test.warp_unix_timestamp(expiry + 1);

    let ix = transact_ix(&test, &f, f.co_signer.pubkey(), transact_data(expiry));
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected TransactionExpired");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::TransactionExpired as u32
    );
}

/// The transfer operation names the `(2, 2)` shape. Instruction data that names
/// another would let the SPP proof describe a spend the zone proof never
/// covered.
#[test]
fn transact_rejects_a_shape_the_operation_does_not_name() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let mut data = transact_data(i64::MAX);
    data.input_contexts.push(input_context(14));

    let ix = transact_ix(&test, &f, f.co_signer.pubkey(), data);
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ProofShapeMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ProofShapeMismatch as u32
    );
}

fn fold_leg() -> FoldTransactLeg {
    FoldTransactLeg {
        spp_proof: [0u8; 192],
        private_tx_hash: field(6),
        salt: [7u8; 16],
        output_view_tags: vec![[8u8; 32], [9u8; 32]],
        output_utxo_hashes: vec![[10u8; 32], [11u8; 32]],
        input_contexts: vec![input_context(12), input_context(13)],
        encrypted_utxos: transfer_utxos(),
    }
}

fn fold_ix(
    test: &SquadsZoneTest,
    f: &Fixture,
    co_signer: Pubkey,
    data: FoldTransactIxData,
) -> Instruction {
    FoldTransact {
        payer: test.payer.pubkey(),
        co_signer,
        zone_config: f.zone_config,
        sender_viewing_key_account: f.sender,
        recipient_viewing_key_account: f.recipient,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data,
    }
    .instruction()
}

fn fold_data(expiry: i64, legs: usize) -> FoldTransactIxData {
    FoldTransactIxData {
        zone_fold_proof: [0u8; 192],
        expiry,
        legs: vec![fold_leg(); legs],
    }
}

#[test]
fn fold_transact_rejects_a_foreign_co_signer() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let impostor = Keypair::new();
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let ix = fold_ix(&test, &f, impostor.pubkey(), fold_data(i64::MAX, 2));
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("expected CoSignerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::CoSignerMismatch as u32);
}

#[test]
fn fold_transact_rejects_a_blocked_sender() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_BLOCKED,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let ix = fold_ix(&test, &f, f.co_signer.pubkey(), fold_data(i64::MAX, 2));
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ViewingKeyAccountBlocked");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ViewingKeyAccountBlocked as u32
    );
}

#[test]
fn fold_transact_rejects_an_expired_transaction() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let expiry = test.unix_timestamp() + 60;
    test.warp_unix_timestamp(expiry + 1);

    let ix = fold_ix(&test, &f, f.co_signer.pubkey(), fold_data(expiry, 2));
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected TransactionExpired");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::TransactionExpired as u32
    );
}

/// The fold verifying keys cover two and three legs only.
#[test]
fn fold_transact_rejects_an_unsupported_leg_count() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let ix = fold_ix(&test, &f, f.co_signer.pubkey(), fold_data(i64::MAX, 4));
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected InvalidInstructionData");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::InvalidInstructionData as u32
    );
}

/// A leg whose forwarded vectors name a different SPP circuit than the proved
/// leg shape.
#[test]
fn fold_transact_rejects_a_leg_shape_the_fold_key_does_not_prove() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );

    let mut data = fold_data(i64::MAX, 2);
    data.legs[1].input_contexts.push(input_context(14));

    let ix = fold_ix(&test, &f, f.co_signer.pubkey(), data);
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ProofShapeMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ProofShapeMismatch as u32
    );
}

fn seed_proposal(test: &mut SquadsZoneTest, owner: [u8; 32], expiry: i64) -> (Pubkey, Pubkey) {
    let address = Keypair::new().pubkey();
    let rent_payer = Keypair::new().pubkey();
    let record = Proposal::new(
        Address::new_from_array(owner),
        Address::new_from_array([30u8; 32]),
        Address::default(),
        field(31),
        [32u8; 88],
        expiry,
        Address::new_from_array(rent_payer.to_bytes()),
    );
    test.set_program_account(&address, record.serialize().expect("serialize proposal"))
        .expect("seed proposal");
    (address, rent_payer)
}

fn execute_proposal_data() -> ExecuteProposalIxData {
    ExecuteProposalIxData {
        zone_proof: [0u8; 192],
        spp_proof: [0u8; 192],
        public_amount: None,
        spl_interface_bump: 0,
        private_tx_hash: field(6),
        salt: [7u8; 16],
        output_view_tags: vec![[8u8; 32], [9u8; 32]],
        output_utxo_hashes: vec![[10u8; 32], [11u8; 32]],
        input_contexts: vec![input_context(12), input_context(13)],
        encrypted_utxos: transfer_utxos(),
    }
}

fn execute_proposal_ix(
    test: &SquadsZoneTest,
    f: &Fixture,
    co_signer: Pubkey,
    proposal: Pubkey,
    rent_recipient: Pubkey,
) -> Instruction {
    ExecuteProposal {
        payer: test.payer.pubkey(),
        co_signer,
        zone_config: f.zone_config,
        proposal,
        sender_viewing_key_account: f.sender,
        recipient_viewing_key_account: Some(f.recipient),
        withdrawal: None,
        rent_recipient,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: execute_proposal_data(),
    }
    .instruction()
}

#[test]
fn execute_proposal_rejects_a_foreign_co_signer() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );
    let (proposal, rent_payer) = seed_proposal(&mut test, field(20), i64::MAX);

    let impostor = Keypair::new();
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let ix = execute_proposal_ix(&test, &f, impostor.pubkey(), proposal, rent_payer);
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("expected CoSignerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::CoSignerMismatch as u32);
}

#[test]
fn execute_proposal_rejects_a_blocked_sender() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_BLOCKED,
        VIEWING_KEY_STATE_ACTIVE,
    );
    let (proposal, rent_payer) = seed_proposal(&mut test, field(20), i64::MAX);

    let ix = execute_proposal_ix(&test, &f, f.co_signer.pubkey(), proposal, rent_payer);
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ViewingKeyAccountBlocked");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ViewingKeyAccountBlocked as u32
    );
}

#[test]
fn execute_proposal_rejects_an_expired_proposal() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );
    let expiry = test.unix_timestamp() + 60;
    let (proposal, rent_payer) = seed_proposal(&mut test, field(20), expiry);
    test.warp_unix_timestamp(expiry + 1);

    let ix = execute_proposal_ix(&test, &f, f.co_signer.pubkey(), proposal, rent_payer);
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected ProposalExpired");
    assert_eq!(custom_code(&err), SquadsZoneError::ProposalExpired as u32);
}

#[test]
fn execute_proposal_rejects_a_missing_co_signer_signature() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let f = fixture(
        &mut test,
        VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_ACTIVE,
    );
    let (proposal, rent_payer) = seed_proposal(&mut test, field(20), i64::MAX);

    let mut ix = execute_proposal_ix(&test, &f, f.co_signer.pubkey(), proposal, rent_payer);
    ix.accounts[1].is_signer = false;
    let err = test
        .send(&[ix], &[])
        .expect_err("expected MissingCoSignerSignature");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MissingCoSignerSignature as u32
    );
}
