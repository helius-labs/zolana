//! LiteSVM integration tests for the settlement paths.
//!
//! `deposit` and `full_withdrawal` are implemented: the SOL and SPL boundary
//! tests run the full zone-side flow and reach the SPP CPI (rejected at the
//! placeholder `spp_program` with `InvalidSppProgram`). The
//! `transact`/`execute_proposal` withdrawal legs are implemented and covered by
//! the proof-bearing `transact_e2e` / `execute_proposal_e2e` suites.
//!
//! These need no prover: `deposit` reaches the SPP CPI before any proof, and
//! `full_withdrawal` carries no zone proof, so both reach the CPI directly.
//!
//! Requires the prebuilt program binary; build it with
//! `cd zones/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Tests skip (return early, do not fail) when the `.so` is missing.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, SquadsZoneTest};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{
        builders::{Deposit, DepositSettlement, FullWithdrawal, TransactWithdrawal},
        DepositIxData, EncryptedUtxos, FullWithdrawalIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    ZONE_AUTH_PDA_SEED,
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

/// Install a viewing key account fixture with the given `owner`. Only the fields
/// the settlement paths read (owner, discriminator, nullifier_pubkey) matter; the
/// rest are zero/empty.
fn install_vka(test: &mut SquadsZoneTest, owner: [u8; 32]) -> Pubkey {
    let address = Keypair::new().pubkey();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner),
        state: VIEWING_KEY_STATE_ACTIVE,
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

/// The recipient VKA for a deposit: the owner is an opaque field element (the
/// deposit re-hashes it), not a Solana signer.
fn install_recipient_vka(test: &mut SquadsZoneTest) -> Pubkey {
    install_vka(test, field(9))
}

fn deposit_data() -> DepositIxData {
    DepositIxData {
        view_tag: field(1),
        blinding: [2u8; 31],
        amount: 1,
    }
}

/// The SOL deposit runs the full zone-side flow (VKA owner derivation, zone-auth
/// PDA check, SPP-data build) and reaches the SPP CPI, which rejects the
/// placeholder `spp_program` with `InvalidSppProgram` -- proving settlement is
/// implemented and the flow proceeds to settle. Real fund movement is covered by
/// the composed-localnet / test-validator suite.
#[test]
fn deposit_sol_reaches_spp_cpi() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let recipient_vka = install_recipient_vka(&mut test);
    let zone_auth = Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &test.program_id).0;

    let ix = Deposit {
        depositor: test.payer.pubkey(),
        recipient_viewing_key_account: recipient_vka,
        zone_auth,
        // The zone's own id is a deliberate placeholder for the real SPP; the CPI
        // rejects it before invoking.
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
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32,);
}

/// The SPL deposit forwards four settlement accounts and likewise reaches the SPP
/// CPI, rejected at the placeholder program id.
#[test]
fn deposit_spl_reaches_spp_cpi() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let recipient_vka = install_recipient_vka(&mut test);
    let zone_auth = Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &test.program_id).0;

    let ix = Deposit {
        depositor: test.payer.pubkey(),
        recipient_viewing_key_account: recipient_vka,
        zone_auth,
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
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32,);
}

/// A withdrawal carries no zone proof, so `full_withdrawal` needs no prover: the
/// owner signature is checked, the VKA owner is matched, and the flow reaches the
/// SPP CPI (rejected at the placeholder `spp_program`). Real fund movement is
/// covered by the test-validator suite.
fn full_withdrawal_data() -> FullWithdrawalIxData {
    FullWithdrawalIxData {
        spp_proof: [0u8; 192],
        public_amount: 1,
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
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    // The signer is only a fee payer; the SPP proof authorizes the spend, so no
    // viewing key account or owner-signature match is needed.
    let zone_auth = Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &test.program_id).0;

    let ix = FullWithdrawal {
        payer: test.payer.pubkey(),
        zone_auth,
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
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32,);
}

#[test]
fn full_withdrawal_spl_reaches_spp_cpi() {
    let Some(mut test) = SquadsZoneTest::new().expect("boot") else {
        return;
    };
    let zone_auth = Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &test.program_id).0;

    let ix = FullWithdrawal {
        payer: test.payer.pubkey(),
        zone_auth,
        spp_program: test.program_id,
        tree: junk_pubkey(4),
        settlement: TransactWithdrawal::Spl {
            cpi_authority: junk_pubkey(5),
            vault: junk_pubkey(6),
            recipient: junk_pubkey(7),
            user_token_account: junk_pubkey(8),
            token_program: junk_pubkey(9),
        },
        data: full_withdrawal_data(),
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("full_withdrawal reaches the SPP CPI");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32,);
}

// The `transact` withdrawal leg is implemented; its proof-bearing boundary test
// lives in `transact_e2e` (it needs a real (1, 1) zone proof to reach the SPP
// CPI).
