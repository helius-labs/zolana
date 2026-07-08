//! End-to-end on-chain test for `transact` (tag 0): build a REAL zone Groth16
//! proof with the squads SDK (prover feature), install the sender/recipient
//! viewing key account fixtures and the zone config, send `transact` through
//! LiteSVM, and assert the program VERIFIED THE ZONE PROOF ON-CHAIN.
//!
//! The SPP CPI (`spp_transact`) is now real, but this test still passes the
//! zone program's own id as `spp_program` -- a deliberate placeholder, not the
//! real SPP -- since a genuine settlement needs a real SPP program plus an
//! initialized tree and zone-config bootstrap (this crate's
//! composed localnet suite owns that). `spp_transact` validates the exact SPP
//! program id BEFORE attempting any CPI, so this placeholder is rejected with
//! `InvalidSppProgram` -- proving the zone-proof verification path completed
//! and the flow proceeded to attempt settlement, without needing a real SPP.
//! `transact_rejects_tampered_zone_proof` is the discriminating counterpart:
//! a tampered proof fails earlier, in zone-proof verification itself, and
//! never reaches the SPP CPI attempt at all.
//!
//! GATING: requires the prebuilt program `.so` (skips if missing) AND a reachable
//! prover server (skips if `spawn_prover` fails). The first proof request
//! lazy-loads a large proving key and can take minutes.
//!
//! Build the program first:
//!   cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
//! Run with:
//!   cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests --test transact_e2e -- --nocapture

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, prover_url, SquadsZoneTest};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{
        builders::{CreateZoneConfig, Transact, TransactWithdrawal},
        instruction_data::EncryptedUtxos,
        CreateZoneConfigIxData, TransactIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::zone::{
    derive_change_blinding, ZoneRecipient, ZoneUtxo, ZoneWitness,
};

/// A random BN254-range field element (top byte cleared so it is < the field
/// modulus and a valid P-256 scalar). Used for owner hashes, nullifier secrets,
/// and blindings.
fn random_field() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

/// `nullifier_pubkey = Poseidon([nullifier_secret])` (view_key.go:54).
fn nullifier_pubkey(secret: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[secret.as_slice()]).expect("poseidon")
}

/// A `u64` as a 32-byte big-endian field element (the withdrawal public amount
/// the circuit folds into the public-input chain).
fn fe_u64(x: u64) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[24..32].copy_from_slice(&x.to_be_bytes());
    fe
}

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn zone_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id).0
}

/// Boot LiteSVM with the program; returns `None` if the `.so` is missing or the
/// prover server is unreachable (clean skip in both cases).
fn boot_with_prover() -> Option<SquadsZoneTest> {
    let test = SquadsZoneTest::new().expect("boot")?;
    if spawn_prover().is_err() {
        eprintln!("skipping transact_e2e: prover server not reachable");
        return None;
    }
    Some(test)
}

/// Install the zone config with the given co-signer (one dummy auditor key; the
/// program enforces length 1).
fn create_zone_config(test: &mut SquadsZoneTest, co_signer: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let zone_config = zone_config_pda(&test.program_id);
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let ix = CreateZoneConfig {
        creator: creator.pubkey(),
        zone_config,
        system_program: Pubkey::default(),
        data: CreateZoneConfigIxData {
            authority: Pubkey::new_from_array([7u8; 32]),
            co_signer: *co_signer,
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![*auditor.as_bytes()],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_zone_config");
    zone_config
}

/// Install a viewing key account fixture carrying the exact public identity the
/// zone proof binds: `owner` (the owner-key-hash field element), the shared-key
/// commitment, and the nullifier pubkey. Fields `transact` never reads (key
/// ciphertexts, recovery/auditor keys) are left empty/zero.
fn install_vka(
    test: &mut SquadsZoneTest,
    owner_key_hash: [u8; 32],
    shared_viewing_key: [u8; 33],
    commitment: [u8; 32],
    nullifier_pubkey: [u8; 32],
) -> Pubkey {
    let address = Keypair::new().pubkey();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner_key_hash),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key,
        shared_viewing_key_commitment: commitment,
        key_nonce: 0,
        nullifier_pubkey,
        key_ciphertext_ephemeral: [0u8; 33],
        encrypted_nullifier_secret: [0u8; 31],
        recovery_keys: vec![],
        recovery_key_ciphertexts: vec![],
        auditor_keys: vec![],
        auditor_key_ciphertexts: vec![],
    };
    let account_data = account.serialize().expect("serialize vka");
    test.set_program_account(&address, account_data)
        .expect("install vka");
    address
}

/// A plain input UTXO; only the first input's fields feed the change-blinding KDF
/// chain, but every input's hash binds into `private_tx_hash`.
fn input_utxo(amount: u64, owner_key_hash: [u8; 32], nullifier_pubkey: [u8; 32]) -> ZoneUtxo {
    ZoneUtxo {
        owner_key_hash,
        nullifier_pubkey,
        asset: [0u8; 32],
        amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: [0u8; 32],
        is_dummy: false,
    }
}

/// Fixtures and instruction data for a `(2, 2)` transfer with a real zone proof.
struct TransferSetup {
    zone_config: Pubkey,
    sender_vka: Pubkey,
    recipient_vka: Pubkey,
    co_signer: Keypair,
    data: TransactIxData,
}

/// Build a real transfer zone proof, install all fixtures, and assemble the
/// matching `transact` instruction data.
fn build_transfer(test: &mut SquadsZoneTest) -> TransferSetup {
    // Sender identity. The owner-key-hash is a field element, stored verbatim as
    // the viewing key account `owner` the proof reads back.
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    // Recipient identity (public-only to the prover).
    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_viewing_bytes = *recipient_viewing.as_bytes();
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();

    // Two inputs summing to 1000; change 600 + recipient 400, public_amount 0.
    let inputs = vec![
        input_utxo(700, sender_owner, sender_nullifier_pk),
        input_utxo(300, sender_owner, sender_nullifier_pk),
    ];
    let first_input = inputs.first().expect("at least one input");
    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, first_input)
            .expect("derive change blinding");
    let change_output = ZoneUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: [0u8; 32],
        amount: 600,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: [0u8; 32],
        is_dummy: false,
    };
    let recipient_output = ZoneUtxo {
        owner_key_hash: recipient_owner,
        nullifier_pubkey: recipient_nullifier_pk,
        asset: [0u8; 32],
        amount: 400,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: [0u8; 32],
        is_dummy: false,
    };

    let witness = ZoneWitness {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output, recipient_output],
        external_data_hash: random_field(),
        recipient: Some(ZoneRecipient {
            owner_key_hash: recipient_owner,
            nullifier_pubkey: recipient_nullifier_pk,
            viewing_pubkey: recipient_viewing,
        }),
        proposal: None,
        public_amount: [0u8; 32],
    };
    let proof_result = witness
        .prove(&prover_url(SERVER_ADDRESS))
        .expect("proof generation must succeed");

    // Assemble the EncryptedUtxos exactly as the proof committed them.
    let encrypted_utxos = EncryptedUtxos {
        tx_viewing_pk: proof_result
            .tx_viewing_pk
            .expect("transfer carries a tx_viewing_pk"),
        sender_ciphertext: proof_result
            .sender_ciphertext
            .as_slice()
            .try_into()
            .expect("40-byte sender ciphertext"),
        recipient_ciphertexts: vec![proof_result
            .recipient_ciphertext
            .as_slice()
            .try_into()
            .expect("71-byte recipient ciphertext")],
    };

    // Fixtures: zone config (co-signer), sender + recipient viewing key accounts.
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co_signer");
    let zone_config = create_zone_config(test, &co_signer.pubkey());
    let sender_vka = install_vka(
        test,
        sender_owner,
        sender_viewing_pk,
        proof_result.commitment,
        sender_nullifier_pk,
    );
    let recipient_vka = install_vka(
        test,
        recipient_owner,
        recipient_viewing_bytes,
        // The recipient's commitment is not read on the recipient side.
        [0u8; 32],
        recipient_nullifier_pk,
    );

    let ix_data = TransactIxData {
        zone_proof: proof_result.proof,
        // Forwarded to the SPP CPI, which this test never reaches (see the
        // module doc comment): `spp_program` is a deliberate placeholder.
        spp_proof: [0u8; 192],
        public_amount: None,
        private_tx_hash: proof_result.private_tx_hash,
        expiry: i64::MAX,
        // Not read on the zone-verification path (forwarded to the SPP CPI).
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32], [0u8; 32]],
        output_utxo_hashes: vec![],
        input_contexts: vec![],
        encrypted_utxos,
    };

    TransferSetup {
        zone_config,
        sender_vka,
        recipient_vka,
        co_signer,
        data: ix_data,
    }
}

/// Build the `transact` instruction for a transfer. `spp_program` is the zone
/// program's own id -- a deliberate placeholder the real SPP-address check in
/// `spp_transact` rejects (see the module doc comment); `tree_accounts` needs
/// one (arbitrary, never-loaded) account so the zone's own account parsing
/// succeeds and the flow reaches that check.
fn transact_ix(
    test: &SquadsZoneTest,
    setup: &TransferSetup,
    ix_data: TransactIxData,
) -> Instruction {
    Transact {
        payer: test.payer.pubkey(),
        co_signer: setup.co_signer.pubkey(),
        zone_config: setup.zone_config,
        sender_viewing_key_account: setup.sender_vka,
        recipient_viewing_key_account: Some(setup.recipient_vka),
        withdrawal: None,
        zone_auth: zone_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: ix_data,
    }
    .instruction()
}

#[test]
fn transact_transfer_verifies_real_zone_proof_then_attempts_spp_cpi() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let setup = build_transfer(&mut test);
    let ix = transact_ix(&test, &setup, setup.data.clone());

    // On-chain BSB22 Groth16 verification happens HERE; raise the CU limit above
    // the 200k default for the pairing-heavy verify. The zone proof verifies,
    // so the flow proceeds to attempt the SPP CPI, where the placeholder
    // `spp_program` is rejected (see the module doc comment).
    // `transact_rejects_tampered_zone_proof` is the discriminating counterpart:
    // a tampered proof fails earlier and never reaches this check.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

/// Fixtures and instruction data for a `(1, 1)` withdrawal with a real zone proof.
struct WithdrawalSetup {
    zone_config: Pubkey,
    sender_vka: Pubkey,
    co_signer: Keypair,
    data: TransactIxData,
}

/// Build a real `(1, 1)` withdrawal zone proof for a SYNC `transact` (no
/// proposal), install the zone config + sender viewing key account, and assemble
/// the matching `transact` instruction data. Sync `transact` sets
/// `proposal_hash = 0` on-chain (processor.rs:131), so the witness uses
/// `proposal: None` (SDK `proposal_hash = 0`, zone.rs:590-593) with the withdrawn
/// value carried in the independent `public_amount` chain element
/// (zone.rs:538) -- exactly what the program recomputes.
fn build_withdrawal(test: &mut SquadsZoneTest) -> WithdrawalSetup {
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    // One input of 1000; change 300 + public withdrawal 700.
    let withdrawn = 700u64;
    let inputs = vec![input_utxo(1000, sender_owner, sender_nullifier_pk)];
    let first_input = inputs.first().expect("at least one input");
    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, first_input)
            .expect("derive change blinding");
    let change_output = ZoneUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: [0u8; 32],
        amount: 300,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: [0u8; 32],
        is_dummy: false,
    };

    let public_amount = fe_u64(withdrawn);
    let witness = ZoneWitness {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output],
        external_data_hash: random_field(),
        recipient: None,
        // Sync transact binds no proposal, so proposal_hash must be 0.
        proposal: None,
        public_amount,
    };
    let proof_result = witness
        .prove(&prover_url(SERVER_ADDRESS))
        .expect("proof generation must succeed");

    // A withdrawal carries only the sender ciphertext; the ephemeral tx_viewing_pk
    // is unused (no recipient) so it is left zero.
    let encrypted_utxos = EncryptedUtxos {
        tx_viewing_pk: [0u8; 33],
        sender_ciphertext: proof_result
            .sender_ciphertext
            .as_slice()
            .try_into()
            .expect("40-byte sender ciphertext"),
        recipient_ciphertexts: vec![],
    };

    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co_signer");
    let zone_config = create_zone_config(test, &co_signer.pubkey());
    let sender_vka = install_vka(
        test,
        sender_owner,
        sender_viewing_pk,
        proof_result.commitment,
        sender_nullifier_pk,
    );

    let ix_data = TransactIxData {
        zone_proof: proof_result.proof,
        spp_proof: [0u8; 192],
        // `Some` selects the (1, 1) withdrawal shape on-chain.
        public_amount: Some(withdrawn),
        private_tx_hash: proof_result.private_tx_hash,
        expiry: i64::MAX,
        salt: [0u8; 16],
        // The withdrawal SPP-data builder requires exactly one view tag (sender
        // only); its value is forwarded to the CPI, never bound by the proof.
        output_view_tags: vec![[0u8; 32]],
        output_utxo_hashes: vec![],
        input_contexts: vec![],
        encrypted_utxos,
    };

    WithdrawalSetup {
        zone_config,
        sender_vka,
        co_signer,
        data: ix_data,
    }
}

/// Build the `transact` instruction for a withdrawal. No recipient viewing key
/// account; `withdrawal` supplies the settlement account tail (junk pubkeys --
/// the zone never loads them, only forwards them to the SPP CPI that the
/// placeholder `spp_program` rejects). One (arbitrary, never-loaded) tree account.
fn transact_withdrawal_ix(
    test: &SquadsZoneTest,
    setup: &WithdrawalSetup,
    ix_data: TransactIxData,
    withdrawal: TransactWithdrawal,
) -> Instruction {
    Transact {
        payer: test.payer.pubkey(),
        co_signer: setup.co_signer.pubkey(),
        zone_config: setup.zone_config,
        sender_viewing_key_account: setup.sender_vka,
        recipient_viewing_key_account: None,
        withdrawal: Some(withdrawal),
        zone_auth: zone_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: ix_data,
    }
    .instruction()
}

#[test]
fn transact_withdrawal_reaches_spp_cpi() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let setup = build_withdrawal(&mut test);
    // SOL rail: `[sol_interface, recipient, system_program]` (3 settlement
    // accounts). The zone verifies the (1, 1) withdrawal proof on-chain, then
    // forwards the settlement to the SPP CPI, where the placeholder `spp_program`
    // is rejected -- proving the withdrawal zone-proof path completed and reached
    // settlement. `transact_withdrawal_rejects_tampered_zone_proof` is the
    // discriminating counterpart (fails earlier, in proof verification).
    let withdrawal = TransactWithdrawal::Sol {
        sol_interface: Keypair::new().pubkey(),
        recipient: Keypair::new().pubkey(),
    };
    let ix = transact_withdrawal_ix(&test, &setup, setup.data.clone(), withdrawal);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn transact_withdrawal_spl_reaches_spp_cpi() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let setup = build_withdrawal(&mut test);
    // SPL rail: `[cpi_authority, vault, recipient, user_token_account,
    // token_program]` (5 settlement accounts). The zone proof is identical to the
    // SOL rail (only the settlement tail differs), so the same withdrawal proof is
    // reused; the rail is selected from the settlement account count and the CPI is
    // rejected at the placeholder `spp_program`.
    let withdrawal = TransactWithdrawal::Spl {
        cpi_authority: Keypair::new().pubkey(),
        vault: Keypair::new().pubkey(),
        recipient: Keypair::new().pubkey(),
        user_token_account: Keypair::new().pubkey(),
        token_program: Keypair::new().pubkey(),
    };
    let ix = transact_withdrawal_ix(&test, &setup, setup.data.clone(), withdrawal);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn transact_withdrawal_rejects_tampered_zone_proof() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let setup = build_withdrawal(&mut test);

    // Flip a byte of a public input the program binds the proof to: the program
    // recomputes a DIFFERENT public-input hash, so the proof fails the pairing
    // check with ZoneProofVerificationFailed -- earlier than the SPP CPI attempt.
    let mut ix_data = setup.data.clone();
    ix_data.private_tx_hash[0] ^= 1;
    let withdrawal = TransactWithdrawal::Sol {
        sol_interface: Keypair::new().pubkey(),
        recipient: Keypair::new().pubkey(),
    };
    let ix = transact_withdrawal_ix(&test, &setup, ix_data, withdrawal);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("tampered zone proof must be rejected on-chain");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ZoneProofVerificationFailed as u32,
    );
}

#[test]
fn transact_rejects_tampered_zone_proof() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let setup = build_transfer(&mut test);

    // Flip a byte of a public input the program binds the proof to: the program
    // recomputes a DIFFERENT public-input hash, so the still-decompressable proof
    // fails the pairing check with ZoneProofVerificationFailed.
    let mut ix_data = setup.data.clone();
    ix_data.private_tx_hash[0] ^= 1;
    let ix = transact_ix(&test, &setup, ix_data);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("tampered zone proof must be rejected on-chain");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ZoneProofVerificationFailed as u32,
    );
}
