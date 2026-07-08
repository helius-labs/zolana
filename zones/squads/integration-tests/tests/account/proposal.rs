//! LiteSVM integration tests for the Squads zone async proposal lifecycle:
//! `create_proposal` (tag 11), `cancel_proposal` (tag 12), and `execute_proposal`
//! (tag 13).
//!
//! These exercise the NO-PROOF paths: `create_proposal` creates the Proposal PDA
//! (asserting the stored fields), `cancel_proposal` closes it and refunds the
//! rent, and the access-control error paths (`OwnerMismatch`,
//! `ProposalOwnershipMismatch`, `RentRecipientMismatch`). `execute_proposal`
//! requires a real zone Groth16 proof and the SPP CPI, so its happy path is
//! `#[ignore]`d until the SDK witness builder and the SPP zone instructions exist.
//!
//! As in `key_update.rs`, the `ViewingKeyAccount` fixture is seeded directly into
//! LiteSVM with `set_program_account` (the proposal processors only check program
//! ownership, discriminator, and the recorded identities), so no creation proof is
//! needed. The Proposal account itself is created by `create_proposal`, which
//! derives its PDA at `[b"proposal", owner, cipher_text[0..33]]`.
//!
//! Requires the prebuilt program binary; build it with
//! `cd zones/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_keypair::hash::hash_field;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{
        builders::{CancelProposal, CreateProposal},
        CreateProposalIxData,
    },
    state::{proposal::Proposal, viewing_key_account::ViewingKeyAccount},
    types::Address,
    PROPOSAL_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED,
};

/// A distinctive 88-byte proposal ciphertext; its first 33 bytes seed the PDA.
fn cipher_text(tag: u8) -> [u8; 88] {
    let mut ct = [tag; 88];
    // Vary the first bytes so the PDA seed (`cipher_text[0..33]`) is distinctive.
    for (i, b) in ct.iter_mut().enumerate().take(33) {
        *b = tag.wrapping_add(i as u8);
    }
    ct
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

/// The owner-identity field the program stores and hashes signers against:
/// `hash_field(pubkey)` == the SDK `owner_pk_field` for an ed25519 key.
fn owner_field(owner: &Pubkey) -> [u8; 32] {
    hash_field(&owner.to_bytes()).expect("owner pk field hash")
}

/// The Proposal PDA is derived from the owner FIELD (`vka.owner`), not the raw
/// signer pubkey, since the program seeds it with `vka.owner`.
fn proposal_pda(program_id: &Pubkey, owner_field: &[u8; 32], cipher_text: &[u8; 88]) -> Pubkey {
    Pubkey::find_program_address(
        &[PROPOSAL_PDA_SEED, owner_field, &cipher_text[..32]],
        program_id,
    )
    .0
}

/// A viewing key account fixture (auditor-only, no recovery keys) for `owner`.
fn vka_fixture(owner: &Pubkey) -> ViewingKeyAccount {
    ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner_field(owner)),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: [2u8; 33],
        shared_viewing_key_commitment: [3u8; 32],
        key_nonce: 0,
        nullifier_pubkey: [4u8; 32],
        key_ciphertext_ephemeral: [5u8; 33],
        encrypted_nullifier_secret: [6u8; 31],
        recovery_keys: vec![],
        recovery_key_ciphertexts: vec![],
        auditor_keys: vec![[9u8; 33]],
        auditor_key_ciphertexts: vec![[10u8; 32]],
    }
}

/// Seed a viewing key account fixture at its PDA, returning (owner, pda).
fn seed_vka(test: &mut SquadsZoneTest) -> (Keypair, Pubkey) {
    let owner = Keypair::new();
    let pda = vka_pda(&test.program_id, &owner.pubkey());
    let bytes = vka_fixture(&owner.pubkey())
        .serialize()
        .expect("serialize vka fixture");
    test.set_program_account(&pda, bytes).expect("seed vka");
    (owner, pda)
}

fn create_ix_data(ct: [u8; 88]) -> CreateProposalIxData {
    CreateProposalIxData {
        recipient: Address::new_from_array([7u8; 32]),
        asset: Address::default(),
        proposal_hash: [8u8; 32],
        cipher_text: ct,
        expiry: 1_900_000_000,
    }
}

// ---------------------------------------------------------------------------
// create_proposal (tag 11)
// ---------------------------------------------------------------------------

#[test]
fn create_proposal_creates_account() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let fee_payer = Keypair::new();
    test.airdrop(&fee_payer.pubkey(), 1_000_000_000)
        .expect("fund fee_payer");

    let (owner, vka) = seed_vka(&mut test);
    let ct = cipher_text(1);
    let proposal = proposal_pda(&program_id, &owner_field(&owner.pubkey()), &ct);
    let data = create_ix_data(ct);

    let ix = CreateProposal {
        fee_payer: fee_payer.pubkey(),
        proposal,
        viewing_key_account: vka,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data,
    }
    .instruction();

    test.send(&[ix], &[&fee_payer, &owner])
        .expect("create_proposal");

    let bytes = test.account_data(&proposal).expect("proposal exists");
    assert_eq!(bytes.len(), Proposal::SIZE);
    let parsed = Proposal::deserialize(&bytes).expect("deserialize proposal");
    assert_eq!(
        parsed,
        Proposal {
            discriminator: Proposal::DISCRIMINATOR,
            owner: Address::new_from_array(owner_field(&owner.pubkey())),
            recipient: data.recipient,
            asset: data.asset,
            proposal_hash: data.proposal_hash,
            cipher_text: data.cipher_text,
            expiry: data.expiry,
            rent_payer: Address::new_from_array(fee_payer.pubkey().to_bytes()),
        }
    );
}

#[test]
fn create_proposal_rejects_owner_mismatch() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let program_id = test.program_id;
    let fee_payer = Keypair::new();
    test.airdrop(&fee_payer.pubkey(), 1_000_000_000)
        .expect("fund fee_payer");

    let (_owner, vka) = seed_vka(&mut test);
    // A different signer than the viewing key account's recorded owner.
    let wrong_owner = Keypair::new();
    let ct = cipher_text(2);
    // The program errors at the owner check before deriving the PDA; the address
    // passed here is never validated.
    let proposal = proposal_pda(&program_id, &owner_field(&wrong_owner.pubkey()), &ct);

    let ix = CreateProposal {
        fee_payer: fee_payer.pubkey(),
        proposal,
        viewing_key_account: vka,
        system_program: Pubkey::default(),
        owner: wrong_owner.pubkey(),
        data: create_ix_data(ct),
    }
    .instruction();

    let err = test
        .send(&[ix], &[&fee_payer, &wrong_owner])
        .expect_err("expected OwnerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::OwnerMismatch as u32);
    assert_eq!(custom_code(&err), 8018);
}

// ---------------------------------------------------------------------------
// cancel_proposal (tag 12)
// ---------------------------------------------------------------------------

/// Create a proposal owned by `owner`, returning its PDA.
fn seed_proposal(test: &mut SquadsZoneTest, owner: &Keypair, vka: &Pubkey, ct: [u8; 88]) -> Pubkey {
    let proposal = proposal_pda(&test.program_id, &owner_field(&owner.pubkey()), &ct);
    let fee_payer = Keypair::new();
    test.airdrop(&fee_payer.pubkey(), 1_000_000_000)
        .expect("fund fee_payer");
    let ix = CreateProposal {
        fee_payer: fee_payer.pubkey(),
        proposal,
        viewing_key_account: *vka,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data: create_ix_data(ct),
    }
    .instruction();
    test.send(&[ix], &[&fee_payer, owner])
        .expect("create proposal");
    proposal
}

#[test]
fn cancel_proposal_closes_and_refunds() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (owner, vka) = seed_vka(&mut test);
    // The rent_payer is the fee_payer of create_proposal; create it here so we can
    // assert the refund flows back to it.
    let rent_payer = Keypair::new();
    test.airdrop(&rent_payer.pubkey(), 1_000_000_000)
        .expect("fund rent_payer");
    let ct = cipher_text(3);
    let proposal = proposal_pda(&test.program_id, &owner_field(&owner.pubkey()), &ct);
    let create = CreateProposal {
        fee_payer: rent_payer.pubkey(),
        proposal,
        viewing_key_account: vka,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data: create_ix_data(ct),
    }
    .instruction();
    test.send(&[create], &[&rent_payer, &owner])
        .expect("create proposal");

    let closed_lamports = test.lamports(&proposal).expect("proposal funded");
    assert!(closed_lamports > 0);
    let before = test.lamports(&rent_payer.pubkey()).unwrap_or(0);

    let cancel = CancelProposal {
        owner: owner.pubkey(),
        viewing_key_account: vka,
        proposal,
        rent_recipient: rent_payer.pubkey(),
    }
    .instruction();
    test.send(&[cancel], &[&owner]).expect("cancel_proposal");

    assert_eq!(
        test.account_data(&proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
    let after = test.lamports(&rent_payer.pubkey()).unwrap_or(0);
    assert_eq!(after, before + closed_lamports);
}

#[test]
fn cancel_proposal_rejects_owner_mismatch() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (owner, vka) = seed_vka(&mut test);
    let ct = cipher_text(4);
    let proposal = seed_proposal(&mut test, &owner, &vka, ct);

    // A different viewing key account, owned by a different key, whose owner signs.
    // The proposal's recorded owner does not match this vka's owner.
    let (other_owner, other_vka) = seed_vka(&mut test);

    let cancel = CancelProposal {
        owner: other_owner.pubkey(),
        viewing_key_account: other_vka,
        proposal,
        rent_recipient: owner.pubkey(),
    }
    .instruction();
    let err = test
        .send(&[cancel], &[&other_owner])
        .expect_err("expected ProposalOwnershipMismatch");
    // `owner.address() == vka.owner` passes (other_owner owns other_vka), but the
    // proposal's recorded owner differs from that vka -> ProposalOwnershipMismatch.
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ProposalOwnershipMismatch as u32
    );
    assert_eq!(custom_code(&err), 8036);
}

#[test]
fn cancel_proposal_rejects_rent_recipient_mismatch() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (owner, vka) = seed_vka(&mut test);
    let ct = cipher_text(5);
    let proposal = seed_proposal(&mut test, &owner, &vka, ct);

    // The recorded rent_payer is the create_proposal fee_payer (seeded inside
    // `seed_proposal`); a wrong rent_recipient is rejected.
    let cancel = CancelProposal {
        owner: owner.pubkey(),
        viewing_key_account: vka,
        proposal,
        rent_recipient: Pubkey::new_from_array([99u8; 32]),
    }
    .instruction();
    let err = test
        .send(&[cancel], &[&owner])
        .expect_err("expected RentRecipientMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::RentRecipientMismatch as u32
    );
    assert_eq!(custom_code(&err), 8038);
}

// `execute_proposal` (tag 13) needs a real zone Groth16 proof; its zone-proof
// verification + proposal close/refund is covered end to end with the prover in
// `tests/execute_proposal_e2e.rs` (the SPP CPI remains stubbed, so SPP settlement
// is not asserted at this stage).
