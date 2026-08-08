//! The `ViewingKeyAccount` fixture is seeded directly into LiteSVM with
//! `set_program_account`. The proposal processors check only program
//! ownership, the discriminator, and the recorded identities, so no creation
//! proof is needed.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_SMART_ACCOUNT, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{
        builders::{CancelProposal, CreateProposal},
        CreateProposalIxData,
    },
    state::{proposal::Proposal, viewing_key_account::ViewingKeyAccount, zone_config::ZoneConfig},
    types::Address,
    PROPOSAL_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};

/// The first 32 bytes seed the proposal PDA, so they must differ per tag.
fn cipher_text(tag: u8) -> [u8; 88] {
    let mut ct = [tag; 88];
    for (i, b) in ct.iter_mut().enumerate().take(33) {
        *b = tag.wrapping_add(i as u8);
    }
    ct
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

fn seed_zone_config(test: &mut SquadsZoneTest) -> Pubkey {
    let pda = Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], &test.program_id).0;
    let config = ZoneConfig::new(
        Address::new_from_array([11u8; 32]),
        Address::new_from_array([12u8; 32]),
        3_600,
        vec![[2u8; 33]],
        vec![],
    );
    test.set_program_account(&pda, config.serialize().expect("serialize zone config"))
        .expect("seed zone config");
    pda
}

/// The owner-identity field the program stores. For an ed25519 key it equals
/// the SDK `owner_pk_field`.
fn owner_field(owner: &Pubkey) -> [u8; 32] {
    zolana_hasher::primitives::hash_bytes(&owner.to_bytes()).expect("owner pk field hash")
}

/// The program seeds the proposal PDA with the owner field (`vka.owner`),
/// not the raw signer pubkey.
fn proposal_pda(program_id: &Pubkey, owner_field: &[u8; 32], cipher_text: &[u8; 88]) -> Pubkey {
    Pubkey::find_program_address(
        &[PROPOSAL_PDA_SEED, owner_field, &cipher_text[..32]],
        program_id,
    )
    .0
}

fn vka_fixture(owner: &Pubkey) -> ViewingKeyAccount {
    ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner_field(owner)),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_SMART_ACCOUNT,
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

fn seed_vka(test: &mut SquadsZoneTest) -> (Keypair, Pubkey) {
    let owner = Keypair::new();
    let pda = vka_pda(&test.program_id, &owner.pubkey());
    let bytes = vka_fixture(&owner.pubkey())
        .serialize()
        .expect("serialize vka fixture");
    test.set_program_account(&pda, bytes).expect("seed vka");
    (owner, pda)
}

fn create_ix_data(test: &SquadsZoneTest, ct: [u8; 88]) -> CreateProposalIxData {
    let now = test.svm.get_sysvar::<solana_clock::Clock>().unix_timestamp;
    CreateProposalIxData {
        recipient: Address::new_from_array([7u8; 32]),
        asset: Address::default(),
        proposal_hash: [8u8; 32],
        cipher_text: ct,
        expiry: now + 1_800,
    }
}

#[test]
fn create_proposal_creates_account() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let program_id = test.program_id;
    let (owner, vka) = seed_vka(&mut test);
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let ct = cipher_text(1);
    let proposal = proposal_pda(&program_id, &owner_field(&owner.pubkey()), &ct);
    let data = create_ix_data(&test, ct);
    let zone_config = seed_zone_config(&mut test);

    let ix = CreateProposal {
        proposal,
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data,
    }
    .instruction();

    test.send(&[ix], &[&owner]).expect("create_proposal");

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
            rent_payer: Address::new_from_array(owner.pubkey().to_bytes()),
        }
    );
}

#[test]
fn create_proposal_rejects_owner_mismatch() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let program_id = test.program_id;
    let (_owner, vka) = seed_vka(&mut test);
    let wrong_owner = Keypair::new();
    test.airdrop(&wrong_owner.pubkey(), 1_000_000_000)
        .expect("fund wrong owner");
    let ct = cipher_text(2);
    // The program errors at the owner check before it derives the PDA, so this
    // address is never validated.
    let proposal = proposal_pda(&program_id, &owner_field(&wrong_owner.pubkey()), &ct);
    let zone_config = seed_zone_config(&mut test);

    let ix = CreateProposal {
        proposal,
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        owner: wrong_owner.pubkey(),
        data: create_ix_data(&test, ct),
    }
    .instruction();

    let err = test
        .send(&[ix], &[&wrong_owner])
        .expect_err("expected OwnerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::OwnerMismatch as u32);
    assert_eq!(custom_code(&err), 8018);
}

#[test]
fn create_proposal_rejects_distinct_fee_payer() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let program_id = test.program_id;
    let (owner, vka) = seed_vka(&mut test);
    let unrelated_payer = Keypair::new();
    test.airdrop(&unrelated_payer.pubkey(), 1_000_000_000)
        .expect("fund unrelated payer");

    let ct = cipher_text(6);
    let proposal = proposal_pda(&program_id, &owner_field(&owner.pubkey()), &ct);
    let zone_config = seed_zone_config(&mut test);
    let mut ix = CreateProposal {
        proposal,
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data: create_ix_data(&test, ct),
    }
    .instruction();
    // The public builder cannot express a distinct fee payer, so the test edits
    // the wire account list directly.
    ix.accounts[0].pubkey = unrelated_payer.pubkey();

    let err = test
        .send(&[ix], &[&unrelated_payer, &owner])
        .expect_err("expected ProposalPayerMismatch");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ProposalPayerMismatch as u32
    );
    assert_eq!(custom_code(&err), 8056);
}

fn seed_proposal(test: &mut SquadsZoneTest, owner: &Keypair, vka: &Pubkey, ct: [u8; 88]) -> Pubkey {
    let proposal = proposal_pda(&test.program_id, &owner_field(&owner.pubkey()), &ct);
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let zone_config = seed_zone_config(test);
    let ix = CreateProposal {
        proposal,
        viewing_key_account: *vka,
        zone_config,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data: create_ix_data(test, ct),
    }
    .instruction();
    test.send(&[ix], &[owner]).expect("create proposal");
    proposal
}

#[test]
fn cancel_proposal_closes_and_refunds() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let (owner, vka) = seed_vka(&mut test);
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let ct = cipher_text(3);
    let proposal = proposal_pda(&test.program_id, &owner_field(&owner.pubkey()), &ct);
    let zone_config = seed_zone_config(&mut test);
    let create = CreateProposal {
        proposal,
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        owner: owner.pubkey(),
        data: create_ix_data(&test, ct),
    }
    .instruction();
    test.send(&[create], &[&owner]).expect("create proposal");

    let closed_lamports = test.lamports(&proposal).expect("proposal funded");
    assert!(closed_lamports > 0);
    let before = test.lamports(&owner.pubkey()).unwrap_or(0);

    let cancel = CancelProposal {
        authority: owner.pubkey(),
        viewing_key_account: vka,
        proposal,
        rent_recipient: owner.pubkey(),
        zone_config,
    }
    .instruction();
    test.send(&[cancel], &[&owner]).expect("cancel_proposal");

    assert_eq!(
        test.account_data(&proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
    let after = test.lamports(&owner.pubkey()).unwrap_or(0);
    assert_eq!(after, before + closed_lamports);
}

#[test]
fn cancel_proposal_rejects_owner_mismatch() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let (owner, vka) = seed_vka(&mut test);
    let ct = cipher_text(4);
    let zone_config = seed_zone_config(&mut test);
    let proposal = seed_proposal(&mut test, &owner, &vka, ct);

    let (other_owner, other_vka) = seed_vka(&mut test);

    let cancel = CancelProposal {
        authority: other_owner.pubkey(),
        viewing_key_account: other_vka,
        proposal,
        rent_recipient: owner.pubkey(),
        zone_config,
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
    let mut test = SquadsZoneTest::new().expect("boot");
    let (owner, vka) = seed_vka(&mut test);
    let ct = cipher_text(5);
    let zone_config = seed_zone_config(&mut test);
    let proposal = seed_proposal(&mut test, &owner, &vka, ct);

    // The recorded rent_payer is the creation owner, so any other
    // rent_recipient is rejected.
    let cancel = CancelProposal {
        authority: owner.pubkey(),
        viewing_key_account: vka,
        proposal,
        rent_recipient: Pubkey::new_from_array([99u8; 32]),
        zone_config,
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

// `execute_proposal` (tag 13) needs a real zone Groth16 proof and is
// covered end to end in `execute_proposal_e2e.rs`.
