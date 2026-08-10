//! The toggle and close processors check only program ownership, the
//! discriminator, and the authority match, and do not re-derive the PDA, so the
//! tests seed the `ViewingKeyAccount` fixture directly at its PDA instead of
//! running the proof-gated create path.

use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT,
        VIEWING_KEY_STATE_ACTIVE, VIEWING_KEY_STATE_BLOCKED,
    },
    error::SquadsRingError,
    instruction::{
        builders::{CloseViewingKeyAccount, ToggleViewingKeyAccount},
        ToggleViewingKeyAccountIxData,
    },
    state::{ring_config::SquadsRingConfig, viewing_key_account::ViewingKeyAccount},
    types::Address,
    RING_CONFIG_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED,
};

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

fn fixture(owner: &Pubkey, state: u8, owner_kind: u8) -> ViewingKeyAccount {
    ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(
            zolana_hasher::primitives::hash_bytes(&owner.to_bytes()).expect("owner field"),
        ),
        state,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind,
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

/// Seeds the singleton ring config and one viewing key account, and returns the
/// account's owner keypair, its address, and the co-signer keypair.
fn seed(
    test: &mut SquadsRingTest,
    state: u8,
    owner_kind: u8,
) -> (Keypair, Pubkey, Keypair, Pubkey) {
    let owner = Keypair::new();
    let pda = vka_pda(&test.program_id, &owner.pubkey());
    let bytes = fixture(&owner.pubkey(), state, owner_kind)
        .serialize()
        .expect("serialize fixture");
    test.set_program_account(&pda, bytes)
        .expect("seed viewing key account");

    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co-signer");
    let ring_config = ring_config_pda(&test.program_id);
    let config = SquadsRingConfig::new(
        Address::new_from_array([1u8; 32]),
        Address::new_from_array(co_signer.pubkey().to_bytes()),
        3_600,
        vec![[9u8; 33]],
        vec![],
    );
    test.set_program_account(&ring_config, config.serialize().expect("serialize config"))
        .expect("seed ring config");

    (owner, pda, co_signer, ring_config)
}

fn seed_smart_account(test: &mut SquadsRingTest, state: u8) -> (Keypair, Pubkey, Keypair, Pubkey) {
    seed(test, state, OWNER_KIND_SMART_ACCOUNT)
}

fn close_ix(
    authority: Pubkey,
    viewing_key_account: Pubkey,
    rent_recipient: Pubkey,
    ring_config: Pubkey,
) -> Instruction {
    CloseViewingKeyAccount {
        authority,
        viewing_key_account,
        rent_recipient,
        ring_config,
    }
    .instruction()
}

fn toggle_ix(
    authority: Pubkey,
    viewing_key_account: Pubkey,
    ring_config: Pubkey,
    state: u8,
) -> Instruction {
    ToggleViewingKeyAccount {
        authority,
        viewing_key_account,
        ring_config,
        data: ToggleViewingKeyAccountIxData { state },
    }
    .instruction()
}

#[test]
fn toggle_viewing_key_account_blocks_and_unblocks() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let block = toggle_ix(owner.pubkey(), pda, ring_config, VIEWING_KEY_STATE_BLOCKED);
    test.send(&[block], &[&owner]).expect("toggle to blocked");

    let data = test.account_data(&pda).expect("vka exists");
    let account = ViewingKeyAccount::deserialize(&data).expect("deserialize vka");
    assert_eq!(account.state, VIEWING_KEY_STATE_BLOCKED);
    assert_eq!(
        account.owner.to_bytes(),
        zolana_hasher::primitives::hash_bytes(&owner.pubkey().to_bytes()).expect("owner field")
    );

    let unblock = toggle_ix(owner.pubkey(), pda, ring_config, VIEWING_KEY_STATE_ACTIVE);
    test.send(&[unblock], &[&owner]).expect("toggle to active");

    let data = test.account_data(&pda).expect("vka exists");
    let account = ViewingKeyAccount::deserialize(&data).expect("deserialize vka");
    assert_eq!(account.state, VIEWING_KEY_STATE_ACTIVE);
}

#[test]
fn toggle_viewing_key_account_rejects_invalid_state() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let ix = toggle_ix(owner.pubkey(), pda, ring_config, 7);
    let err = test
        .send(&[ix], &[&owner])
        .expect_err("expected InvalidViewingKeyState");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidViewingKeyState as u32
    );
}

#[test]
fn toggle_viewing_key_account_rejects_wrong_owner() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (_owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let ix = toggle_ix(
        attacker.pubkey(),
        pda,
        ring_config,
        VIEWING_KEY_STATE_BLOCKED,
    );
    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("expected OwnerMismatch");
    assert_eq!(custom_code(&err), SquadsRingError::OwnerMismatch as u32);
}

#[test]
fn toggle_viewing_key_account_rejects_a_missing_signature() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let mut ix = toggle_ix(owner.pubkey(), pda, ring_config, VIEWING_KEY_STATE_BLOCKED);
    ix.accounts[0].is_signer = false;
    let err = test
        .send(&[ix], &[])
        .expect_err("expected MissingOwnerSignature");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MissingOwnerSignature as u32
    );
}

#[test]
fn close_viewing_key_account_refunds_rent() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let closed_lamports = test.lamports(&pda).expect("vka funded");
    assert!(closed_lamports > 0);

    let rent_recipient = Pubkey::new_from_array([42u8; 32]);
    let before = test.lamports(&rent_recipient).unwrap_or(0);

    let ix = close_ix(owner.pubkey(), pda, rent_recipient, ring_config);
    test.send(&[ix], &[&owner])
        .expect("close viewing key account");

    assert_eq!(test.account_data(&pda).map(|d| d.len()).unwrap_or(0), 0);
    let after = test.lamports(&rent_recipient).unwrap_or(0);
    assert_eq!(after, before + closed_lamports);
}

#[test]
fn close_viewing_key_account_rejects_wrong_owner() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (_owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let ix = close_ix(
        attacker.pubkey(),
        pda,
        Pubkey::new_from_array([42u8; 32]),
        ring_config,
    );
    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("expected OwnerMismatch");
    assert_eq!(custom_code(&err), SquadsRingError::OwnerMismatch as u32);
}

#[test]
fn close_viewing_key_account_rejects_a_missing_signature() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (owner, pda, _co_signer, ring_config) =
        seed_smart_account(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let mut ix = close_ix(
        owner.pubkey(),
        pda,
        Pubkey::new_from_array([42u8; 32]),
        ring_config,
    );
    ix.accounts[0].is_signer = false;
    let err = test
        .send(&[ix], &[])
        .expect_err("expected MissingOwnerSignature");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::MissingOwnerSignature as u32
    );
}

/// An owner kind outside the known set names no settlement rail, so the loader
/// must refuse the account instead of letting a branch pick a default.
#[test]
fn an_unknown_owner_kind_is_refused_at_load() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (owner, pda, _co_signer, ring_config) = seed(&mut test, VIEWING_KEY_STATE_ACTIVE, 7);

    let ix = toggle_ix(owner.pubkey(), pda, ring_config, VIEWING_KEY_STATE_BLOCKED);
    let err = test
        .send(&[ix], &[&owner])
        .expect_err("an unknown owner kind must fail closed");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidOwnerKind as u32);
}

/// A keypair owner's stored identity is a hash of its address, so no signer can
/// ever satisfy the owner test. The co-signer is the account's only lifecycle
/// authority.
#[test]
fn co_signer_blocks_and_closes_a_keypair_owned_account() {
    let mut test = SquadsRingTest::new().expect("boot");
    let (_owner, pda, co_signer, ring_config) =
        seed(&mut test, VIEWING_KEY_STATE_ACTIVE, OWNER_KIND_KEYPAIR);

    let block = toggle_ix(
        co_signer.pubkey(),
        pda,
        ring_config,
        VIEWING_KEY_STATE_BLOCKED,
    );
    test.send(&[block], &[&co_signer])
        .expect("the co-signer must be able to block");

    let data = test.account_data(&pda).expect("vka exists");
    let account = ViewingKeyAccount::deserialize(&data).expect("deserialize vka");
    assert_eq!(account.state, VIEWING_KEY_STATE_BLOCKED);

    let rent_recipient = Pubkey::new_from_array([42u8; 32]);
    let close = close_ix(co_signer.pubkey(), pda, rent_recipient, ring_config);
    test.send(&[close], &[&co_signer])
        .expect("the co-signer must be able to close");
    assert_eq!(test.account_data(&pda).map(|d| d.len()).unwrap_or(0), 0);
}
