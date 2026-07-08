//! LiteSVM integration tests for the Squads zone NO-PROOF viewing-key
//! instructions: `toggle_viewing_key_account` (tag 9) and
//! `close_viewing_key_account` (tag 8).
//!
//! A real `ViewingKeyAccount` is normally created by `create_viewing_key_account`
//! (tag 5), which requires a key-encryption Groth16 proof. The SDK witness
//! builder for that proof is not yet available, so instead of going through the
//! create path we seed the account fixture directly into LiteSVM at its PDA with
//! `set_account` (the toggle/close processors only check program ownership,
//! discriminator, and owner match -- they do not re-derive the PDA), exercising
//! those processors without a proof.
//!
//! Requires the prebuilt program binary; build it with
//! `cd zones/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_instruction::{AccountMeta, Instruction};
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
    instruction::{builders::ToggleViewingKeyAccount, tag, ToggleViewingKeyAccountIxData},
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    PROGRAM_ID_PUBKEY, VIEWING_KEY_ACCOUNT_PDA_SEED,
};

/// Build the `close_viewing_key_account` (tag 8) instruction with the exact
/// 3-account layout the program expects: `[owner (signer), viewing_key_account
/// (writable), rent_recipient (writable)]`.
///
/// NOTE: the interface `CloseViewingKeyAccount` builder appends a PROVISIONAL
/// 4th account (the program id, for a future self-CPI event). The current
/// `process_close_viewing_key_account_ix` matches exactly three accounts and
/// rejects the 4-account form with `InvalidInstructionData` (8000), so the
/// builder cannot drive the program today. This local builder mirrors the
/// program's real account list; when the close self-CPI lands, switch to the
/// interface builder.
fn close_ix(owner: Pubkey, viewing_key_account: Pubkey, rent_recipient: Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID_PUBKEY,
        accounts: vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(viewing_key_account, false),
            AccountMeta::new(rent_recipient, false),
        ],
        data: vec![tag::CLOSE_VIEWING_KEY_ACCOUNT],
    }
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

/// Build a minimal active `ViewingKeyAccount` fixture owned by `owner` with no
/// recovery keys and one auditor entry.
fn fixture(owner: &Pubkey, state: u8) -> ViewingKeyAccount {
    ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner.to_bytes()),
        state,
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

/// Seed a `ViewingKeyAccount` fixture at its PDA and return (owner keypair, pda).
fn seed_vka(test: &mut SquadsZoneTest, state: u8) -> (Keypair, Pubkey) {
    let owner = Keypair::new();
    let pda = vka_pda(&test.program_id, &owner.pubkey());
    let bytes = fixture(&owner.pubkey(), state)
        .serialize()
        .expect("serialize fixture");
    test.set_program_account(&pda, bytes)
        .expect("seed viewing key account");
    (owner, pda)
}

#[test]
fn toggle_viewing_key_account_blocks_and_unblocks() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (owner, pda) = seed_vka(&mut test, VIEWING_KEY_STATE_ACTIVE);

    // Active -> blocked.
    let block = ToggleViewingKeyAccount {
        owner: owner.pubkey(),
        viewing_key_account: pda,
        data: ToggleViewingKeyAccountIxData {
            state: VIEWING_KEY_STATE_BLOCKED,
        },
    }
    .instruction();
    test.send(&[block], &[&owner]).expect("toggle to blocked");

    let data = test.account_data(&pda).expect("vka exists");
    let account = ViewingKeyAccount::deserialize(&data).expect("deserialize vka");
    assert_eq!(account.state, VIEWING_KEY_STATE_BLOCKED);
    assert_eq!(account.owner.to_bytes(), owner.pubkey().to_bytes());

    // Blocked -> active.
    let unblock = ToggleViewingKeyAccount {
        owner: owner.pubkey(),
        viewing_key_account: pda,
        data: ToggleViewingKeyAccountIxData {
            state: VIEWING_KEY_STATE_ACTIVE,
        },
    }
    .instruction();
    test.send(&[unblock], &[&owner]).expect("toggle to active");

    let data = test.account_data(&pda).expect("vka exists");
    let account = ViewingKeyAccount::deserialize(&data).expect("deserialize vka");
    assert_eq!(account.state, VIEWING_KEY_STATE_ACTIVE);
}

#[test]
fn toggle_viewing_key_account_rejects_invalid_state() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (owner, pda) = seed_vka(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let ix = ToggleViewingKeyAccount {
        owner: owner.pubkey(),
        viewing_key_account: pda,
        data: ToggleViewingKeyAccountIxData { state: 7 },
    }
    .instruction();
    let err = test
        .send(&[ix], &[&owner])
        .expect_err("expected InvalidViewingKeyState");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::InvalidViewingKeyState as u32
    );
    assert_eq!(custom_code(&err), 8024);
}

#[test]
fn toggle_viewing_key_account_rejects_wrong_owner() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (_owner, pda) = seed_vka(&mut test, VIEWING_KEY_STATE_ACTIVE);

    // A different signer that is not the recorded owner.
    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let ix = ToggleViewingKeyAccount {
        owner: attacker.pubkey(),
        viewing_key_account: pda,
        data: ToggleViewingKeyAccountIxData {
            state: VIEWING_KEY_STATE_BLOCKED,
        },
    }
    .instruction();
    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("expected OwnerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::OwnerMismatch as u32);
    assert_eq!(custom_code(&err), 8018);
}

#[test]
fn close_viewing_key_account_refunds_rent() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (owner, pda) = seed_vka(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let closed_lamports = test.lamports(&pda).expect("vka funded");
    assert!(closed_lamports > 0);

    let rent_recipient = Pubkey::new_from_array([42u8; 32]);
    let before = test.lamports(&rent_recipient).unwrap_or(0);

    let ix = close_ix(owner.pubkey(), pda, rent_recipient);
    test.send(&[ix], &[&owner])
        .expect("close viewing key account");

    // The closed account is now system-owned with zero data; rent flowed to the
    // recipient.
    assert_eq!(test.account_data(&pda).map(|d| d.len()).unwrap_or(0), 0);
    let after = test.lamports(&rent_recipient).unwrap_or(0);
    assert_eq!(after, before + closed_lamports);
}

#[test]
fn close_viewing_key_account_rejects_wrong_owner() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let (_owner, pda) = seed_vka(&mut test, VIEWING_KEY_STATE_ACTIVE);

    let attacker = Keypair::new();
    test.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let ix = close_ix(attacker.pubkey(), pda, Pubkey::new_from_array([42u8; 32]));
    let err = test
        .send(&[ix], &[&attacker])
        .expect_err("expected OwnerMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::OwnerMismatch as u32);
    assert_eq!(custom_code(&err), 8018);
}
