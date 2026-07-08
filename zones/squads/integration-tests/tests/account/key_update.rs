//! LiteSVM integration tests for the Squads zone key-update ROTATION lifecycle:
//! `update_viewing_key_account` (tag 6), `fill_key_update` (tag 7),
//! `execute_key_update` (tag 14), and `cancel_key_update` (tag 15).
//!
//! These exercise the NO-PROOF paths: creating a `KeyUpdateProposal`, filling its
//! buffer, cancelling it, and the access-control error paths. `execute_key_update`
//! requires a real key-encryption (rotation) Groth16 proof, so its full lifecycle
//! is covered with the prover in `tests/key_update_e2e.rs`.
//!
//! As in `viewing_key.rs`, the `ViewingKeyAccount` and `ZoneConfig` fixtures are
//! seeded directly into LiteSVM with `set_program_account` (the proposal
//! processors only check program ownership, discriminator, and the recorded
//! identities -- they do not re-derive those PDAs), so no creation proof is
//! needed.
//!
//! Requires the prebuilt program binary; build it with
//! `cd zones/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, KEY_OP_ADD, KEY_OP_UPDATE_AUDITOR, OWNER_KIND_KEYPAIR,
        VIEWING_KEY_STATE_ACTIVE,
    },
    error::SquadsZoneError,
    instruction::{
        builders::{CancelKeyUpdate, FillKeyUpdate, UpdateViewingKeyAccount},
        FillKeyUpdateIxData, UpdateViewingKeyAccountIxData,
    },
    state::{
        key_update_proposal::{KeyOperation, KeyUpdateProposal},
        viewing_key_account::ViewingKeyAccount,
        zone_config::ZoneConfig,
    },
    types::Address,
    KEY_UPDATE_PROPOSAL_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};

const AUDITOR_KEY: [u8; 33] = [9u8; 33];

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn proposal_pda(program_id: &Pubkey, target: &Pubkey, domain: u16) -> Pubkey {
    Pubkey::find_program_address(
        &[
            KEY_UPDATE_PROPOSAL_PDA_SEED,
            target.as_ref(),
            &domain.to_le_bytes(),
        ],
        program_id,
    )
    .0
}

/// A viewing key account fixture with `recovery` recovery keys and one auditor.
fn vka_fixture(owner: &Pubkey, recovery: usize) -> ViewingKeyAccount {
    ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner.to_bytes()),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
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

/// A zone config fixture with the given co-signer and auditor key.
fn zone_config_fixture(co_signer: &Pubkey, auditor: [u8; 33]) -> ZoneConfig {
    ZoneConfig::new(
        Address::new_from_array([1u8; 32]),
        Address::new_from_array(co_signer.to_bytes()),
        3_600,
        vec![auditor],
        vec![],
    )
}

/// Seed a viewing key account fixture at its PDA, returning (owner, pda).
fn seed_vka(test: &mut SquadsZoneTest, recovery: usize) -> (Keypair, Pubkey) {
    let owner = Keypair::new();
    let pda = vka_pda(&test.program_id, &owner.pubkey());
    let bytes = vka_fixture(&owner.pubkey(), recovery)
        .serialize()
        .expect("serialize vka fixture");
    test.set_program_account(&pda, bytes).expect("seed vka");
    (owner, pda)
}

/// Seed a zone config fixture at the singleton PDA, returning its pubkey.
fn seed_zone_config(test: &mut SquadsZoneTest, co_signer: &Pubkey, auditor: [u8; 33]) -> Pubkey {
    let pda = zone_config_pda(&test.program_id);
    let bytes = zone_config_fixture(co_signer, auditor)
        .serialize()
        .expect("serialize zone config fixture");
    test.set_program_account(&pda, bytes)
        .expect("seed zone config");
    pda
}

/// Build a single ADD recovery-key operation.
fn add_op(key: u8) -> KeyOperation {
    KeyOperation {
        op: KEY_OP_ADD,
        index: 0,
        key: [key; 33],
    }
}

// ---------------------------------------------------------------------------
// update_viewing_key_account (tag 6)
// ---------------------------------------------------------------------------

#[test]
fn update_viewing_key_account_creates_proposal() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");

    // A recovery-ops proposal needs the proposer to be a smart-account holder; the
    // program does not bind that identity for the recovery path, only signer.
    let (_owner, target) = seed_vka(&mut test, 0);
    let co_signer = Keypair::new();
    let zone_config = seed_zone_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 1u16;
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();

    // One ADD op: R' = 1, so the buffer holds K = R' + A = 2 ciphertexts.
    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![add_op(20)],
            expiry: 1_700_000_000,
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
    assert_eq!(parsed.operations, vec![add_op(20)]);
    // The buffer starts empty; fill_key_update appends to it.
    assert!(parsed.new_key_ciphertexts.is_empty());
    assert_eq!(parsed.expiry, 1_700_000_000);
    assert_eq!(parsed.executor.to_bytes(), executor.pubkey().to_bytes());
    assert_eq!(parsed.rent_payer.to_bytes(), proposer.pubkey().to_bytes());

    // The account is funded for the full K=2 buffer even though the stored data is
    // the empty-buffer length.
    let full_space = KeyUpdateProposal::account_size(1, 2);
    assert!(test.lamports(&proposal).expect("funded") >= test.rent_exempt(full_space));
    assert_eq!(data.len(), KeyUpdateProposal::account_size(1, 0));
}

#[test]
fn update_viewing_key_account_rejects_mixed_operations() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");

    let (_owner, target) = seed_vka(&mut test, 0);
    let co_signer = Keypair::new();
    let zone_config = seed_zone_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 2u16;
    let proposal = proposal_pda(&program_id, &target, domain);

    // An auditor-update op mixed with a recovery op is rejected.
    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
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
            expiry: 1_700_000_000,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&proposer])
        .expect_err("expected MixedKeyOperationTypes");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MixedKeyOperationTypes as u32
    );
    assert_eq!(custom_code(&err), 8027);
}

#[test]
fn update_viewing_key_account_auditor_update_requires_co_signer() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    // A non-co-signer proposer drives a single auditor-update op.
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");

    let (_owner, target) = seed_vka(&mut test, 0);
    let co_signer = Keypair::new();
    // The zone auditor differs from the target's auditor, so the only failing
    // check is the co-signer identity.
    let zone_config = seed_zone_config(&mut test, &co_signer.pubkey(), [11u8; 33]);

    let domain = 3u16;
    let proposal = proposal_pda(&program_id, &target, domain);

    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![KeyOperation {
                op: KEY_OP_UPDATE_AUDITOR,
                index: 0,
                key: [0u8; 33],
            }],
            expiry: 1_700_000_000,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&proposer])
        .expect_err("expected CoSignerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::CoSignerMismatch as u32);
    assert_eq!(custom_code(&err), 8020);
}

#[test]
fn update_viewing_key_account_auditor_update_rejects_unchanged_auditor() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co_signer");

    let (_owner, target) = seed_vka(&mut test, 0);
    // The zone auditor equals the target's auditor (AUDITOR_KEY), so the auditor
    // update is a no-op and must be rejected.
    let zone_config = seed_zone_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);

    let domain = 4u16;
    let proposal = proposal_pda(&program_id, &target, domain);

    let ix = UpdateViewingKeyAccount {
        proposer: co_signer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![KeyOperation {
                op: KEY_OP_UPDATE_AUDITOR,
                index: 0,
                key: [0u8; 33],
            }],
            expiry: 1_700_000_000,
            executor: Pubkey::default(),
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&co_signer])
        .expect_err("expected AuditorNotChanged");
    assert_eq!(custom_code(&err), SquadsZoneError::AuditorNotChanged as u32);
    assert_eq!(custom_code(&err), 8028);
}

// ---------------------------------------------------------------------------
// fill_key_update (tag 7)
// ---------------------------------------------------------------------------

/// Create a proposal with one ADD op (R'=1, K=2) and return (proposal pda,
/// executor keypair).
fn seed_proposal(test: &mut SquadsZoneTest, domain: u16) -> (Pubkey, Keypair) {
    let program_id = test.program_id;
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let (_owner, target) = seed_vka(test, 0);
    let co_signer = Keypair::new();
    let zone_config = seed_zone_config(test, &co_signer.pubkey(), AUDITOR_KEY);
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();
    test.airdrop(&executor.pubkey(), 1_000_000_000)
        .expect("fund executor");

    let ix = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![add_op(20)],
            expiry: 1_700_000_000,
            executor: executor.pubkey(),
        },
    }
    .instruction();
    test.send(&[ix], &[&proposer]).expect("create proposal");
    (proposal, executor)
}

#[test]
fn fill_key_update_appends_ciphertexts() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (proposal, executor) = seed_proposal(&mut test, 10);

    // Append the two ciphertexts (K=2) in two chunks.
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
    assert_eq!(data.len(), KeyUpdateProposal::account_size(1, 2));
}

#[test]
fn fill_key_update_rejects_wrong_executor() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
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
    assert_eq!(custom_code(&err), SquadsZoneError::ExecutorMismatch as u32);
    assert_eq!(custom_code(&err), 8019);
}

#[test]
fn fill_key_update_rejects_buffer_overflow() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (proposal, executor) = seed_proposal(&mut test, 12);

    // The account is funded for K=2 ciphertexts; appending 3 exceeds the funded
    // rent and must be rejected.
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
    assert_eq!(custom_code(&err), SquadsZoneError::KeyBufferOverflow as u32);
    assert_eq!(custom_code(&err), 8033);
}

// ---------------------------------------------------------------------------
// cancel_key_update (tag 15)
// ---------------------------------------------------------------------------

#[test]
fn cancel_key_update_closes_and_refunds() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let (owner, target) = seed_vka(&mut test, 0);
    let co_signer = Keypair::new();
    let zone_config = seed_zone_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);
    let domain = 20u16;
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();

    let create = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![add_op(20)],
            expiry: 1_700_000_000,
            executor: executor.pubkey(),
        },
    }
    .instruction();
    test.send(&[create], &[&proposer]).expect("create proposal");

    let closed_lamports = test.lamports(&proposal).expect("proposal funded");
    assert!(closed_lamports > 0);
    // rent_payer is the proposer; refund flows back to it.
    let before = test.lamports(&proposer.pubkey()).unwrap_or(0);

    let cancel = CancelKeyUpdate {
        owner: owner.pubkey(),
        target,
        key_update_proposal: proposal,
        rent_recipient: proposer.pubkey(),
    }
    .instruction();
    test.send(&[cancel], &[&owner]).expect("cancel_key_update");

    assert_eq!(
        test.account_data(&proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
    let after = test.lamports(&proposer.pubkey()).unwrap_or(0);
    assert_eq!(after, before + closed_lamports);
}

#[test]
fn cancel_key_update_rejects_target_mismatch() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let (owner, target) = seed_vka(&mut test, 0);
    let co_signer = Keypair::new();
    let zone_config = seed_zone_config(&mut test, &co_signer.pubkey(), AUDITOR_KEY);
    let domain = 21u16;
    let proposal = proposal_pda(&program_id, &target, domain);
    let executor = Keypair::new();

    let create = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            operations: vec![add_op(20)],
            expiry: 1_700_000_000,
            executor: executor.pubkey(),
        },
    }
    .instruction();
    test.send(&[create], &[&proposer]).expect("create proposal");

    // A different viewing key account passed as `target` does not match the
    // proposal's recorded target.
    let (other_owner, other_target) = seed_vka(&mut test, 0);
    let cancel = CancelKeyUpdate {
        owner: other_owner.pubkey(),
        target: other_target,
        key_update_proposal: proposal,
        rent_recipient: proposer.pubkey(),
    }
    .instruction();
    let err = test
        .send(&[cancel], &[&other_owner])
        .expect_err("expected ProposalTargetMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ProposalTargetMismatch as u32
    );
    assert_eq!(custom_code(&err), 8037);

    // And a correct target but a wrong rent recipient is rejected.
    let _ = owner;
    let cancel_bad_recipient = CancelKeyUpdate {
        owner: owner.pubkey(),
        target,
        key_update_proposal: proposal,
        rent_recipient: Pubkey::new_from_array([99u8; 32]),
    }
    .instruction();
    let err = test
        .send(&[cancel_bad_recipient], &[&owner])
        .expect_err("expected RentRecipientMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::RentRecipientMismatch as u32
    );
    assert_eq!(custom_code(&err), 8038);
}

// `execute_key_update` (tag 14) needs a real key-encryption (rotation) Groth16
// proof; its full lifecycle (tags 6 -> 7 -> 14) is covered end to end with the
// prover in `tests/key_update_e2e.rs`.
