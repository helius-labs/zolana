//! LiteSVM boundary tests for the `deposit` and `full_withdrawal` settlement
//! paths.
//!
//! Neither path needs a prover. `deposit` reaches the SPP CPI before any
//! proof, and `full_withdrawal` carries no ring proof, so both reach the CPI
//! directly. The CPI rejects the placeholder `spp_program` with
//! `InvalidSppProgram`, which shows the ring-side flow completed. The
//! proof-bearing withdrawal legs are covered by `transact_e2e` and
//! `execute_proposal_e2e`.
//!
//! Tests skip when the prebuilt program `.so` is missing.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE,
        VIEWING_KEY_STATE_BLOCKED,
    },
    error::SquadsRingError,
    instruction::{
        builders::{Deposit, DepositSettlement, FullWithdrawal, TransactWithdrawal},
        DepositIxData, EncryptedUtxos, FullWithdrawalIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    RING_AUTH_PDA_SEED,
};

fn junk_pubkey(seed: u8) -> Pubkey {
    Pubkey::new_from_array([seed; 32])
}

/// A 32-byte value inside the BN254 field range (top byte cleared) so the
/// on-chain Poseidon over the recipient owner never rejects it.
fn field(seed: u8) -> [u8; 32] {
    let mut f = [seed; 32];
    f[0] = 0;
    f
}

/// Only the fields the settlement paths read (owner, discriminator, state,
/// nullifier_pubkey) matter. The rest are zero or empty.
fn install_vka(test: &mut SquadsRingTest, owner: [u8; 32], state: u8) -> Pubkey {
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
        .expect("install vka");
    address
}

/// The deposit recipient owner is an opaque field element that the deposit
/// re-hashes, not a Solana signer.
fn install_recipient_vka(test: &mut SquadsRingTest) -> Pubkey {
    install_vka(test, field(9), VIEWING_KEY_STATE_ACTIVE)
}

fn deposit_data() -> DepositIxData {
    DepositIxData {
        view_tag: field(1),
        asset: zolana_interface::instruction::DepositAssetKind::Sol,
        amount: 1,
        blinding: [2u8; 32],
        encrypted: zolana_interface::instruction::EncryptedRingDepositData {
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            ciphertext: Vec::new(),
        },
    }
}

#[test]
fn deposit_sol_reaches_spp_cpi() {
    let mut test = SquadsRingTest::new().expect("boot");
    let recipient_vka = install_recipient_vka(&mut test);
    let ring_auth = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id).0;

    let ix = Deposit {
        depositor: test.payer.pubkey(),
        recipient_viewing_key_account: recipient_vka,
        ring_auth,
        spp_program: test.program_id,
        tree: junk_pubkey(4),
        settlement: DepositSettlement::Sol {
            sol_interface: junk_pubkey(5),
        },
        data: deposit_data(),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("deposit reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32,);
}

/// A blocked account can only exit through `full_withdrawal`, so no deposit may
/// push new funds into it.
#[test]
fn deposit_rejects_a_blocked_recipient() {
    let mut test = SquadsRingTest::new().expect("boot");
    let recipient_vka = install_vka(&mut test, field(9), VIEWING_KEY_STATE_BLOCKED);
    let ring_auth = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id).0;

    let ix = Deposit {
        depositor: test.payer.pubkey(),
        recipient_viewing_key_account: recipient_vka,
        ring_auth,
        spp_program: test.program_id,
        tree: junk_pubkey(4),
        settlement: DepositSettlement::Sol {
            sol_interface: junk_pubkey(5),
        },
        data: deposit_data(),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("a blocked recipient must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::ViewingKeyAccountBlocked as u32
    );
}

#[test]
fn deposit_spl_reaches_spp_cpi() {
    let mut test = SquadsRingTest::new().expect("boot");
    let recipient_vka = install_recipient_vka(&mut test);
    let ring_auth = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id).0;

    let ix = Deposit {
        depositor: test.payer.pubkey(),
        recipient_viewing_key_account: recipient_vka,
        ring_auth,
        spp_program: test.program_id,
        tree: junk_pubkey(4),
        settlement: DepositSettlement::Spl {
            user_token: junk_pubkey(5),
            vault: junk_pubkey(6),
            registry: junk_pubkey(7),
            token_program: junk_pubkey(8),
        },
        data: deposit_data(),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("deposit reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32,);
}

fn full_withdrawal_data() -> FullWithdrawalIxData {
    FullWithdrawalIxData {
        spp_proof: [0u8; 192],
        public_amount: 1,
        spl_interface_bump: 0,
        private_tx_hash: [0u8; 32],
        expiry: i64::MAX,
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32]],
        output_utxo_hashes: vec![[0u8; 32]],
        input_contexts: vec![],
        encrypted_utxos: EncryptedUtxos {
            tx_viewing_pk: [0u8; 33],
            sender_ciphertext: [0u8; 40],
            recipient_ciphertexts: vec![],
        },
    }
}

#[test]
fn full_withdrawal_sol_reaches_spp_cpi() {
    let mut test = SquadsRingTest::new().expect("boot");
    // The signer is only a fee payer. The SPP proof authorizes the spend, so
    // no viewing key account or owner-signature match is needed.
    let ring_auth = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id).0;

    let ix = FullWithdrawal {
        payer: test.payer.pubkey(),
        ring_auth,
        spp_program: test.program_id,
        tree: junk_pubkey(4),
        settlement: TransactWithdrawal::Sol {
            sol_interface: junk_pubkey(5),
            recipient: junk_pubkey(6),
        },
        data: full_withdrawal_data(),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("full_withdrawal reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32,);
}

#[test]
fn full_withdrawal_spl_reaches_spp_cpi() {
    let mut test = SquadsRingTest::new().expect("boot");
    let ring_auth = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id).0;

    let ix = FullWithdrawal {
        payer: test.payer.pubkey(),
        ring_auth,
        spp_program: test.program_id,
        tree: junk_pubkey(4),
        settlement: TransactWithdrawal::Spl {
            cpi_authority: junk_pubkey(5),
            mint: junk_pubkey(6),
            spl_interface: junk_pubkey(7),
            user_token_account: junk_pubkey(8),
            token_program: junk_pubkey(9),
        },
        data: full_withdrawal_data(),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("full_withdrawal reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32,);
}
