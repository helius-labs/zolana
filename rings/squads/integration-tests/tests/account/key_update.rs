//! LiteSVM tests for the key-update rotation lifecycle,
//! `update_viewing_key_account` (tag 6), `fill_key_update` (tag 7),
//! `execute_key_update` (tag 14), and `cancel_key_update` (tag 15).
//!
//! These exercise the no-proof paths. `execute_key_update` needs a real
//! key-encryption Groth16 proof, so its full lifecycle is covered in
//! `key_update_e2e.rs`.
//!
//! The `ViewingKeyAccount` and `SquadsRingConfig` fixtures are seeded directly
//! with `set_program_account`. The proposal processors check only program
//! ownership, discriminator, and the recorded identities, so no creation
//! flow is needed.
//!
//! Tests skip when the prebuilt program `.so` is missing.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, KEY_OP_ADD, KEY_OP_UPDATE_AUDITOR, OWNER_KIND_SMART_ACCOUNT,
        VIEWING_KEY_STATE_ACTIVE,
    },
    error::SquadsRingError,
    instruction::{
        builders::{CancelKeyUpdate, ExecuteKeyUpdate, FillKeyUpdate, UpdateViewingKeyAccount},
        ExecuteKeyUpdateIxData, FillKeyUpdateIxData, UpdateViewingKeyAccountIxData,
    },
    state::{
        key_update_proposal::{KeyOperation, KeyUpdateProposal, OpenKeyUpdateProposal},
        ring_config::SquadsRingConfig,
        viewing_key_account::ViewingKeyAccount,
    },
    types::Address,
    KEY_UPDATE_PROPOSAL_PDA_SEED, RING_CONFIG_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED,
};

const AUDITOR_KEY: [u8; 33] = [9u8; 33];

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

/// Every fixture here starts at key nonce 0, the nonce the proposal PDA is
/// seeded with.
fn proposal_pda(program_id: &Pubkey, target: &Pubkey, domain: u16) -> Pubkey {
    Pubkey::find_program_address(
        &[
            KEY_UPDATE_PROPOSAL_PDA_SEED,
            target.as_ref(),
            &domain.to_le_bytes(),
            &0u64.to_le_bytes(),
        ],
        program_id,
    )
    .0
}

fn vka_fixture(owner: &Pubkey, recovery: usize) -> ViewingKeyAccount {
    ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(
            zolana_hasher::primitives::hash_bytes(&owner.to_bytes()).expect("owner field"),
        ),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_SMART_ACCOUNT,
        shared_viewing_key: [2u8; 33],
        shared_viewing_key_commitment: [3u8; 32],
        key_nonce: 0,
        nullifier_pubkey: [4u8; 32],
        key_ciphertext_ephemeral: [5u8; 33],
        encrypted_nullifier_secret: [6u8; 31],
        recovery_keys: vec![[7u8; 33]; recovery],
        recovery_key_ciphertexts: vec![[8u8; 32]; recovery],
        auditor_keys: vec![AUDITOR_KEY],
        auditor_key_ciphertexts: vec![[10u8; 32]],
    }
}

fn ring_config_fixture(co_signer: &Pubkey, auditor: [u8; 33]) -> SquadsRingConfig {
    SquadsRingConfig::new(
        Address::new_from_array([1u8; 32]),
        Address::new_from_array(co_signer.to_bytes()),
        3_600,
        vec![auditor],
        vec![],
    )
}

fn seed_vka(test: &mut SquadsRingTest, recovery: usize) -> (Keypair, Pubkey) {
    let owner = Keypair::new();
    let pda = vka_pda(&test.program_id, &owner.pubkey());
    let bytes = vka_fixture(&owner.pubkey(), recovery)
        .serialize()
        .expect("serialize vka fixture");
    test.set_program_account(&pda, bytes).expect("seed vka");
    (owner, pda)
}

fn seed_ring_config(test: &mut SquadsRingTest, co_signer: &Pubkey, auditor: [u8; 33]) -> Pubkey {
    let pda = ring_config_pda(&test.program_id);
    let bytes = ring_config_fixture(co_signer, auditor)
        .serialize()
        .expect("serialize ring config fixture");
    test.set_program_account(&pda, bytes)
        .expect("seed ring config");
    pda
}

fn add_op(key: u8) -> KeyOperation {
    KeyOperation {
        op: KEY_OP_ADD,
        index: 0,
        key: [key; 33],
    }
}

#[test]
fn update_viewing_key_account_creates_noop_rotation_proposal() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let (proposer, target) = seed_vka(&mut test, 1);
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 1u16;
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();

    // A no-op recipient update rotates the encrypted material without changing
    // the existing recovery or auditor recipient set. K = R + A = 2.
    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![],
            expiry: i64::MAX,
            executor: executor.pubkey(),
        },
    }
    .instruction();

    test.send(&[ix], &[&proposer])
        .expect("update_viewing_key_account");

    let data = test.account_data(&proposal).expect("proposal exists");
    let parsed = KeyUpdateProposal::deserialize(&data).expect("deserialize proposal");
    assert_eq!(parsed.discriminator, KeyUpdateProposal::DISCRIMINATOR);
    assert_eq!(parsed.domain, domain);
    assert_eq!(parsed.target.to_bytes(), target.to_bytes());
    assert!(parsed.operations.is_empty());
    assert!(parsed.new_key_ciphertexts.is_empty());
    assert_eq!(parsed.expiry, i64::MAX);
    assert_eq!(parsed.key_nonce, 0);
    assert_eq!(parsed.executor.to_bytes(), executor.pubkey().to_bytes());
    assert_eq!(parsed.rent_payer.to_bytes(), proposer.pubkey().to_bytes());

    // The account is funded for the full K=2 buffer even though the stored data is
    // the empty-buffer length.
    let full_space = KeyUpdateProposal::account_size(0, 2);
    assert!(test.lamports(&proposal).expect("funded") >= test.rent_exempt(full_space));
    assert_eq!(data.len(), KeyUpdateProposal::account_size(0, 0));
}

#[test]
fn update_viewing_key_account_rejects_unauthenticated_recovery_update() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (proposer, target) = seed_vka(&mut test, 0);
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);
    let domain = 5u16;
    let proposal = proposal_pda(&test.program_id, &target, domain);

    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![add_op(20)],
            expiry: i64::MAX,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&proposer])
        .expect_err("recovery update without owner authentication must fail closed");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::RecoveryKeyUpdateUnsupported as u32,
    );
    assert!(test.account_data(&proposal).is_none());
}

#[test]
fn update_viewing_key_account_rejects_mixed_operations() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let (proposer, target) = seed_vka(&mut test, 0);
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 2u16;
    let proposal = proposal_pda(&program_id, &target, domain);

    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![
                add_op(20),
                KeyOperation {
                    op: KEY_OP_UPDATE_AUDITOR,
                    index: 0,
                    key: [0u8; 33],
                },
            ],
            expiry: i64::MAX,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&proposer])
        .expect_err("expected MixedKeyOperationTypes");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MixedKeyOperationTypes as u32
    );
}

#[test]
fn update_viewing_key_account_auditor_update_requires_co_signer() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let (proposer, target) = seed_vka(&mut test, 0);
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    // The proposer owns the target and the ring auditor differs from the
    // target's auditor, so the only failing check is the co-signer identity.
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), [11u8; 33]);

    let domain = 3u16;
    let proposal = proposal_pda(&program_id, &target, domain);

    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![KeyOperation {
                op: KEY_OP_UPDATE_AUDITOR,
                index: 0,
                key: [0u8; 33],
            }],
            expiry: i64::MAX,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&proposer])
        .expect_err("expected CoSignerMismatch");
    assert_eq!(custom_code(&err), SquadsRingError::CoSignerMismatch as u32);
}

#[test]
fn update_viewing_key_account_auditor_update_rejects_unchanged_auditor() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co_signer");

    let (_owner, target) = seed_vka(&mut test, 0);
    // The ring auditor equals the target's auditor (AUDITOR_KEY), so the auditor
    // update is a no-op and must be rejected.
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 4u16;
    let proposal = proposal_pda(&program_id, &target, domain);

    let ix = UpdateViewingKeyAccount {
        proposer: co_signer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![KeyOperation {
                op: KEY_OP_UPDATE_AUDITOR,
                index: 0,
                key: [0u8; 33],
            }],
            expiry: i64::MAX,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&co_signer])
        .expect_err("expected AuditorNotChanged");
    assert_eq!(custom_code(&err), SquadsRingError::AuditorNotChanged as u32);
}

/// The proposal address is derived from caller-chosen seeds. An unbound creator
/// could park one on a victim's target and block every later rotation at that
/// domain, so an unrelated signer must be refused.
#[test]
fn update_viewing_key_account_rejects_a_squatted_proposal() {
    let mut test = SquadsRingTest::new().expect("boot");
    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let (_owner, target) = seed_vka(&mut test, 1);
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 0u16;
    let proposal = proposal_pda(&test.program_id, &target, domain);
    let ix = UpdateViewingKeyAccount {
        proposer: attacker.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![],
            expiry: i64::MAX,
            executor: attacker.pubkey(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("an unrelated signer must not open a proposal on this target");
    assert_eq!(custom_code(&err), SquadsRingError::OwnerMismatch as u32);
    assert!(test.account_data(&proposal).is_none());
}

/// The co-signer is the recovery party, so it can clear a proposal on an
/// account whose owner cannot sign.
#[test]
fn cancel_key_update_accepts_the_co_signer() {
    let mut test = SquadsRingTest::new().expect("boot");
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co-signer");
    let (_owner, target) = seed_vka(&mut test, 1);
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 30u16;
    let proposal = proposal_pda(&test.program_id, &target, domain);
    let create = UpdateViewingKeyAccount {
        proposer: co_signer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![],
            expiry: i64::MAX,
            executor: co_signer.pubkey(),
        },
    }
    .instruction();
    test.send(&[create], &[&co_signer])
        .expect("create proposal");

    let cancel = CancelKeyUpdate {
        authority: co_signer.pubkey(),
        target,
        key_update_proposal: proposal,
        rent_recipient: co_signer.pubkey(),
        ring_config,
    }
    .instruction();
    test.send(&[cancel], &[&co_signer])
        .expect("the co-signer must be able to cancel");
    assert_eq!(
        test.account_data(&proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
}

/// A settled rotation advances the account's key nonce, which strands every
/// proposal opened before it.
#[test]
fn execute_key_update_rejects_a_stale_proposal() {
    let mut test = SquadsRingTest::new().expect("boot");
    let co_signer = Keypair::new();
    let executor = Keypair::new();
    test.airdrop(&executor.pubkey(), 1_000_000_000)
        .expect("fund executor");

    // The account already rotated once, so its nonce is ahead of the proposal.
    let owner = Keypair::new();
    let target = vka_pda(&test.program_id, &owner.pubkey());
    let mut account = vka_fixture(&owner.pubkey(), 1);
    account.key_nonce = 1;
    test.set_program_account(&target, account.serialize().expect("serialize vka"))
        .expect("seed vka");
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let proposal_address = proposal_pda(&test.program_id, &target, 40);
    let mut proposal = KeyUpdateProposal::from(OpenKeyUpdateProposal {
        domain: 40,
        target: Address::new_from_array(target.to_bytes()),
        key_nonce: 0,
        operations: vec![],
        expiry: i64::MAX,
        executor: Address::new_from_array(executor.pubkey().to_bytes()),
        rent_payer: Address::new_from_array(executor.pubkey().to_bytes()),
    });
    proposal.new_key_ciphertexts = vec![[0u8; 32]; 2];
    test.set_program_account(
        &proposal_address,
        proposal.serialize().expect("serialize proposal"),
    )
    .expect("seed proposal");

    let ix = ExecuteKeyUpdate {
        executor: executor.pubkey(),
        co_signer: co_signer.pubkey(),
        viewing_key_account: target,
        ring_config,
        key_update_proposal: proposal_address,
        rent_recipient: executor.pubkey(),
        system_program: Pubkey::default(),
        data: ExecuteKeyUpdateIxData {
            rotation_proof: [0u8; 192],
            new_shared_viewing_key: [0u8; 33],
            new_shared_viewing_key_commitment: [0u8; 32],
            new_nullifier_pubkey: account.nullifier_pubkey,
            new_key_ciphertext_ephemeral: [0u8; 33],
            new_encrypted_nullifier_secret: [0u8; 31],
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&executor, &co_signer])
        .expect_err("a proposal from an earlier nonce must not settle");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::StaleKeyUpdateProposal as u32
    );
}

/// A no-op proposal funded for K = 2 ciphertexts (R = 1, A = 1).
fn seed_proposal(test: &mut SquadsRingTest, domain: u16) -> (Pubkey, Keypair) {
    seed_proposal_with_expiry(test, domain, i64::MAX)
}

fn seed_proposal_with_expiry(
    test: &mut SquadsRingTest,
    domain: u16,
    expiry: i64,
) -> (Pubkey, Keypair) {
    let program_id = test.program_id;
    let (proposer, target) = seed_vka(test, 1);
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(test, &co_signer.pubkey(), AUDITOR_KEY);
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();
    test.airdrop(&executor.pubkey(), 1_000_000_000)
        .expect("fund executor");

    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![],
            expiry,
            executor: executor.pubkey(),
        },
    }
    .instruction();
    test.send(&[ix], &[&proposer]).expect("create proposal");
    (proposal, executor)
}

/// A target account and a filled proposal, ready for `execute_key_update` to
/// reach its identity and lifecycle guards. The rotation proof is zeroed, so
/// every case here stops before verification.
struct ExecuteFixture {
    proposal: Pubkey,
    executor: Keypair,
    co_signer: Keypair,
    target: Pubkey,
    ring_config: Pubkey,
}

fn seed_execute_fixture(test: &mut SquadsRingTest, domain: u16, expiry: i64) -> ExecuteFixture {
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co-signer");
    let executor = Keypair::new();
    test.airdrop(&executor.pubkey(), 1_000_000_000)
        .expect("fund executor");
    let (_owner, target) = seed_vka(test, 1);
    let ring_config = seed_ring_config(test, &co_signer.pubkey(), AUDITOR_KEY);

    let proposal_address = proposal_pda(&test.program_id, &target, domain);
    let mut proposal = KeyUpdateProposal::from(OpenKeyUpdateProposal {
        domain,
        target: Address::new_from_array(target.to_bytes()),
        key_nonce: 0,
        operations: vec![],
        expiry,
        executor: Address::new_from_array(executor.pubkey().to_bytes()),
        rent_payer: Address::new_from_array(executor.pubkey().to_bytes()),
    });
    proposal.new_key_ciphertexts = vec![[0u8; 32]; 2];
    test.set_program_account(
        &proposal_address,
        proposal.serialize().expect("serialize proposal"),
    )
    .expect("seed proposal");

    ExecuteFixture {
        proposal: proposal_address,
        executor,
        co_signer,
        target,
        ring_config,
    }
}

fn execute_key_update_ix(f: &ExecuteFixture, co_signer: Pubkey) -> solana_instruction::Instruction {
    ExecuteKeyUpdate {
        executor: f.executor.pubkey(),
        co_signer,
        viewing_key_account: f.target,
        ring_config: f.ring_config,
        key_update_proposal: f.proposal,
        rent_recipient: f.executor.pubkey(),
        system_program: Pubkey::default(),
        data: ExecuteKeyUpdateIxData {
            rotation_proof: [0u8; 192],
            new_shared_viewing_key: [0u8; 33],
            new_shared_viewing_key_commitment: [0u8; 32],
            new_nullifier_pubkey: vka_fixture(&Pubkey::default(), 0).nullifier_pubkey,
            new_key_ciphertext_ephemeral: [0u8; 33],
            new_encrypted_nullifier_secret: [0u8; 31],
        },
    }
    .instruction()
}

/// The executor is the only signer that may append to the buffer.
#[test]
fn fill_key_update_rejects_a_missing_executor_signature() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (proposal, executor) = seed_proposal(&mut test, 13);

    let mut ix = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: vec![[21u8; 32]],
        },
    }
    .instruction();
    ix.accounts[0].is_signer = false;
    let err = test
        .send(&[ix], &[])
        .expect_err("expected MissingExecutorSignature");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MissingExecutorSignature as u32
    );
}

/// A buffer filled after the proposal expired would otherwise sit ready for a
/// settlement the owner no longer authorized.
#[test]
fn fill_key_update_rejects_an_expired_proposal() {
    let mut test = SquadsRingTest::new().expect("boot");
    let expiry = test.unix_timestamp() + 60;
    let (proposal, executor) = seed_proposal_with_expiry(&mut test, 14, expiry);
    test.warp_unix_timestamp(expiry + 1);

    let ix = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: vec![[21u8; 32]],
        },
    }
    .instruction();
    let err = test
        .send(&[ix], &[&executor])
        .expect_err("expected ProposalExpired");
    assert_eq!(custom_code(&err), SquadsRingError::ProposalExpired as u32);
}

#[test]
fn execute_key_update_rejects_a_missing_executor_signature() {
    let mut test = SquadsRingTest::new().expect("boot");
    let f = seed_execute_fixture(&mut test, 41, i64::MAX);

    let mut ix = execute_key_update_ix(&f, f.co_signer.pubkey());
    ix.accounts[0].is_signer = false;
    let err = test
        .send(&[ix], &[&f.co_signer])
        .expect_err("expected MissingExecutorSignature");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MissingExecutorSignature as u32
    );
}

#[test]
fn execute_key_update_rejects_a_missing_co_signer_signature() {
    let mut test = SquadsRingTest::new().expect("boot");
    let f = seed_execute_fixture(&mut test, 42, i64::MAX);

    let mut ix = execute_key_update_ix(&f, f.co_signer.pubkey());
    ix.accounts[1].is_signer = false;
    let err = test
        .send(&[ix], &[&f.executor])
        .expect_err("expected MissingCoSignerSignature");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MissingCoSignerSignature as u32
    );
}

#[test]
fn execute_key_update_rejects_a_foreign_co_signer() {
    let mut test = SquadsRingTest::new().expect("boot");
    let f = seed_execute_fixture(&mut test, 43, i64::MAX);

    let impostor = Keypair::new();
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let ix = execute_key_update_ix(&f, impostor.pubkey());
    let err = test
        .send(&[ix], &[&f.executor, &impostor])
        .expect_err("expected CoSignerMismatch");
    assert_eq!(custom_code(&err), SquadsRingError::CoSignerMismatch as u32);
}

#[test]
fn execute_key_update_rejects_an_expired_proposal() {
    let mut test = SquadsRingTest::new().expect("boot");
    let expiry = test.unix_timestamp() + 60;
    let f = seed_execute_fixture(&mut test, 44, expiry);
    test.warp_unix_timestamp(expiry + 1);

    let ix = execute_key_update_ix(&f, f.co_signer.pubkey());
    let err = test
        .send(&[ix], &[&f.executor, &f.co_signer])
        .expect_err("expected ProposalExpired");
    assert_eq!(custom_code(&err), SquadsRingError::ProposalExpired as u32);
}

#[test]
fn fill_key_update_appends_ciphertexts() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (proposal, executor) = seed_proposal(&mut test, 10);

    let fill1 = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: vec![[21u8; 32]],
        },
    }
    .instruction();
    test.send(&[fill1], &[&executor]).expect("fill chunk 1");

    let data = test.account_data(&proposal).expect("proposal exists");
    let parsed = KeyUpdateProposal::deserialize(&data).expect("deserialize");
    assert_eq!(parsed.new_key_ciphertexts, vec![[21u8; 32]]);

    let fill2 = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: vec![[22u8; 32]],
        },
    }
    .instruction();
    test.send(&[fill2], &[&executor]).expect("fill chunk 2");

    let data = test.account_data(&proposal).expect("proposal exists");
    let parsed = KeyUpdateProposal::deserialize(&data).expect("deserialize");
    assert_eq!(parsed.new_key_ciphertexts, vec![[21u8; 32], [22u8; 32]]);
    assert_eq!(data.len(), KeyUpdateProposal::account_size(0, 2));
}

#[test]
fn fill_key_update_rejects_wrong_executor() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (proposal, _executor) = seed_proposal(&mut test, 11);

    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let ix = FillKeyUpdate {
        executor: attacker.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: vec![[21u8; 32]],
        },
    }
    .instruction();
    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("expected ExecutorMismatch");
    assert_eq!(custom_code(&err), SquadsRingError::ExecutorMismatch as u32);
}

#[test]
fn fill_key_update_rejects_buffer_overflow() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (proposal, executor) = seed_proposal(&mut test, 12);

    // The account is funded for K = 2 ciphertexts, so appending 3 exceeds the
    // funded rent.
    let ix = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: vec![[21u8; 32], [22u8; 32], [23u8; 32]],
        },
    }
    .instruction();
    let err = test
        .send(&[ix], &[&executor])
        .expect_err("expected KeyBufferOverflow");
    assert_eq!(custom_code(&err), SquadsRingError::KeyBufferOverflow as u32);
}

#[test]
fn cancel_key_update_closes_and_refunds() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let (owner, target) = seed_vka(&mut test, 0);
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);
    let domain = 20u16;
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();

    let create = UpdateViewingKeyAccount {
        proposer: owner.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![],
            expiry: i64::MAX,
            executor: executor.pubkey(),
        },
    }
    .instruction();
    test.send(&[create], &[&owner]).expect("create proposal");

    let closed_lamports = test.lamports(&proposal).expect("proposal funded");
    assert!(closed_lamports > 0);
    let before = test.lamports(&owner.pubkey()).unwrap_or(0);

    let cancel = CancelKeyUpdate {
        authority: owner.pubkey(),
        target,
        key_update_proposal: proposal,
        rent_recipient: owner.pubkey(),
        ring_config,
    }
    .instruction();
    test.send(&[cancel], &[&owner]).expect("cancel_key_update");

    assert_eq!(
        test.account_data(&proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
    let after = test.lamports(&owner.pubkey()).unwrap_or(0);
    assert_eq!(after, before + closed_lamports);
}

#[test]
fn cancel_key_update_rejects_target_mismatch() {
    let mut test = SquadsRingTest::new().expect("boot");
    let program_id = test.program_id;
    let (owner, target) = seed_vka(&mut test, 0);
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let co_signer = Keypair::new();
    let ring_config = seed_ring_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);
    let domain = 21u16;
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();

    let create = UpdateViewingKeyAccount {
        proposer: owner.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        ring_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![],
            expiry: i64::MAX,
            executor: executor.pubkey(),
        },
    }
    .instruction();
    test.send(&[create], &[&owner]).expect("create proposal");

    let (other_owner, other_target) = seed_vka(&mut test, 0);
    let cancel = CancelKeyUpdate {
        authority: other_owner.pubkey(),
        target: other_target,
        key_update_proposal: proposal,
        rent_recipient: owner.pubkey(),
        ring_config,
    }
    .instruction();
    let err = test
        .send(&[cancel], &[&other_owner])
        .expect_err("expected ProposalTargetMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::ProposalTargetMismatch as u32
    );

    let cancel_bad_recipient = CancelKeyUpdate {
        authority: owner.pubkey(),
        target,
        key_update_proposal: proposal,
        rent_recipient: Pubkey::new_from_array([99u8; 32]),
        ring_config,
    }
    .instruction();
    let err = test
        .send(&[cancel_bad_recipient], &[&owner])
        .expect_err("expected RentRecipientMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::RentRecipientMismatch as u32
    );
}
