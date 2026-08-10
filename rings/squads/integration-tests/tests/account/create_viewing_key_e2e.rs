//! End-to-end test for `create_viewing_key_account` (tag 5). Builds a real
//! key-encryption Groth16 proof with the squads SDK, sends the instruction
//! through LiteSVM, and asserts the program verified the proof on-chain and
//! initialized the `ViewingKeyAccount` PDA with the proof-derived key
//! material.
//!
//! The SDK computes the proof's public-input hash from the same shared viewing
//! key, commitment, ephemeral, recovery and auditor keys, ciphertexts, and
//! nullifier that go into `CreateViewingKeyAccountIxData`, and the program
//! recomputes that hash from the instruction data plus the `zone_config`
//! auditor key. The zone config's auditor key therefore equals the trailing
//! auditor recipient key in the proof, and the recovery keys and ciphertext
//! ordering match the proof inputs.
//!
//! Skips when the prebuilt program `.so` is missing or `spawn_prover` fails.
//! The first proof request lazy-loads the proving key.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, prover_url, SquadsZoneTest};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{builders::CreateViewingKeyAccount, CreateViewingKeyAccountIxData},
    state::{viewing_key_account::ViewingKeyAccount, zone_config::ZoneConfig},
    types::Address,
    VIEWING_KEY_ACCOUNT_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::{
    key_encryption::KeyEncryptionProofInputs,
    key_encryption_fold::KeyEncryptionFoldProofInputs,
    viewing_key_account::{
        prove_create_viewing_key_account, prove_create_viewing_key_account_folded,
    },
};

/// A random BN254-range scalar (top byte cleared so it is below the field
/// modulus). The nullifier secret is a BN254 field element by design. The
/// viewing and ephemeral secrets are full-range P-256 scalars.
fn random_bn254_scalar() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0; // < 2^248 < BN254 modulus.
    b
}

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

/// `None` when the `.so` is missing or the prover server is unreachable, a
/// clean skip in both cases.
/// A prover the tests cannot reach is a failure. A run that quietly skips
/// every proof-backed case reports green while proving nothing.
fn boot_with_prover() -> SquadsZoneTest {
    spawn_prover().expect("the prover server must be reachable, see ZOLANA_PROVER_URL");
    SquadsZoneTest::new().expect("boot")
}

fn create_zone_config(test: &mut SquadsZoneTest, auditor: &P256Pubkey) -> Pubkey {
    let zone_config = zone_config_pda(&test.program_id);
    let config = ZoneConfig::new(
        Address::new_from_array([7u8; 32]),
        Address::new_from_array(test.payer.pubkey().to_bytes()),
        3_600,
        vec![*auditor.as_bytes()],
        vec![],
    );
    test.set_program_account(
        &zone_config,
        config.serialize().expect("serialize zone config"),
    )
    .expect("seed zone config");
    zone_config
}

/// Enrollment authorization is checked before proof verification. An arbitrary
/// payer cannot squat another public proof identity's canonical PDA, even with
/// structurally valid instruction data.
#[test]
fn create_viewing_key_account_rejects_non_co_signer_enrollment() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let zone_config = create_zone_config(&mut test, &auditor);
    let impostor = Keypair::new();
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let owner_identity = Pubkey::new_unique();
    let vka = vka_pda(&test.program_id, &owner_identity);

    let ix = CreateViewingKeyAccount {
        enrollment_authority: impostor.pubkey(),
        owner_identity,
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        data: CreateViewingKeyAccountIxData {
            key_encryption_proof: [0u8; 192],
            encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
            owner_kind: OWNER_KIND_KEYPAIR,
            shared_viewing_key: [0u8; 33],
            shared_viewing_key_commitment: [0u8; 32],
            nullifier_pubkey: [0u8; 32],
            key_ciphertext_ephemeral: [0u8; 33],
            encrypted_nullifier_secret: [0u8; 31],
            recovery_keys: vec![],
            key_ciphertexts: vec![[0u8; 32]],
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("non-co-signer enrollment must fail before proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::CoSignerMismatch as u32);
}

/// The configured co-signer may initialize an auditor-only account, but cannot
/// grant an arbitrary recovery key access without control of the exact stored
/// owner identity. This check intentionally runs before proof verification.
#[test]
fn create_viewing_key_account_rejects_co_signer_only_recovery_enrollment() {
    let mut test = SquadsZoneTest::new().expect("boot");
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recovery = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let zone_config = create_zone_config(&mut test, &auditor);
    let owner_identity = Pubkey::new_unique();
    let vka = vka_pda(&test.program_id, &owner_identity);

    let mut ix = CreateViewingKeyAccount {
        enrollment_authority: test.payer.pubkey(),
        owner_identity,
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        data: CreateViewingKeyAccountIxData {
            key_encryption_proof: [0u8; 192],
            encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
            owner_kind: OWNER_KIND_KEYPAIR,
            shared_viewing_key: [0u8; 33],
            shared_viewing_key_commitment: [0u8; 32],
            nullifier_pubkey: [0u8; 32],
            key_ciphertext_ephemeral: [0u8; 33],
            encrypted_nullifier_secret: [0u8; 31],
            recovery_keys: vec![*recovery.as_bytes()],
            key_ciphertexts: vec![[0u8; 32]; 2],
        },
    }
    .instruction();
    // Simulate a hand-crafted instruction that omits the builder's required
    // signer bit for a non-empty recovery-key list.
    ix.accounts[1].is_signer = false;

    let err = test
        .send(&[ix], &[])
        .expect_err("co-signer-only recovery enrollment must fail closed");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::MissingOwnerSignature as u32
    );
}

/// One recovery key plus the zone's auditor (numKeys = 2). The program must
/// verify the real proof on-chain and initialize the PDA.
#[test]
fn create_viewing_key_account_verifies_real_proof_on_chain() {
    let mut test = boot_with_prover();

    // The auditor key MUST match the zone config. It is the trailing recipient
    // among the proof recipients. The exact owner identity also signs the
    // recovery-key enrollment.
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recovery = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());

    let zone_config = create_zone_config(&mut test, &auditor);

    let proof_inputs = KeyEncryptionProofInputs {
        viewing_secret_key: SecretKey::random(&mut OsRng),
        ephemeral_secret_key: SecretKey::random(&mut OsRng),
        nullifier_secret: random_bn254_scalar(),
        // Recovery first, then auditor. The program reads recovery keys from
        // instruction data and the auditor from zone_config, in that order.
        recipient_keys: vec![recovery, auditor],
        old_state_hash: [0u8; 32],
    };

    let (ix_data, proof_result) =
        prove_create_viewing_key_account(proof_inputs, 1, &prover_url(SERVER_ADDRESS))
            .expect("real key-encryption proof generation must succeed");

    assert_eq!(ix_data.encryption_scheme, ENCRYPTION_SCHEME_P256_AES);
    assert_eq!(ix_data.recovery_keys, vec![*recovery.as_bytes()]);
    assert_eq!(ix_data.key_ciphertexts.len(), 2);
    assert_eq!(
        ix_data.shared_viewing_key,
        *proof_result.shared_viewing_pubkey.as_bytes()
    );

    // This compatibility path uses a raw, signable owner identity. SDK-derived
    // proof identities cannot use it and fail closed at the client boundary.
    let owner = Keypair::new();
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let vka = vka_pda(&test.program_id, &owner.pubkey());

    let ix = CreateViewingKeyAccount {
        enrollment_authority: test.payer.pubkey(),
        owner_identity: owner.pubkey(),
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        data: ix_data.clone(),
    }
    .instruction();

    // BSB22 pairing verification is CU-heavy, so raise the limit above the
    // 200k default.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    test.send(&[budget, ix], &[&owner])
        .expect("create_viewing_key_account must verify the proof on-chain and succeed");

    let account_data = test.account_data(&vka).expect("viewing key account exists");
    let account = ViewingKeyAccount::deserialize(&account_data).expect("deserialize vka");

    let expected = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner.pubkey().to_bytes()),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: ix_data.shared_viewing_key,
        shared_viewing_key_commitment: ix_data.shared_viewing_key_commitment,
        key_nonce: 0,
        nullifier_pubkey: ix_data.nullifier_pubkey,
        key_ciphertext_ephemeral: ix_data.key_ciphertext_ephemeral,
        encrypted_nullifier_secret: ix_data.encrypted_nullifier_secret,
        recovery_keys: vec![*recovery.as_bytes()],
        recovery_key_ciphertexts: vec![ix_data.key_ciphertexts[0]],
        auditor_keys: vec![*auditor.as_bytes()],
        auditor_key_ciphertexts: vec![ix_data.key_ciphertexts[1]],
    };
    assert_eq!(account, expected);
}

/// Tamper one byte of a public input (the shared-viewing-key commitment). The
/// program must reject it on-chain with `KeyEncryptionProofVerificationFailed`
/// (8041), which shows the Groth16 verifier runs.
#[test]
fn create_viewing_key_account_rejects_tampered_proof() {
    let mut test = boot_with_prover();

    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recovery = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let zone_config = create_zone_config(&mut test, &auditor);

    let proof_inputs = KeyEncryptionProofInputs {
        viewing_secret_key: SecretKey::random(&mut OsRng),
        ephemeral_secret_key: SecretKey::random(&mut OsRng),
        nullifier_secret: random_bn254_scalar(),
        recipient_keys: vec![recovery, auditor],
        old_state_hash: [0u8; 32],
    };
    let (mut ix_data, _result) =
        prove_create_viewing_key_account(proof_inputs, 1, &prover_url(SERVER_ADDRESS))
            .expect("real key-encryption proof generation must succeed");

    // Flipping a byte of the shared-viewing-key commitment makes the program
    // recompute a different public-input hash, so the still well-formed,
    // decompressable Groth16 proof fails the pairing check. Tampering the proof
    // bytes directly would instead fail point decompression first
    // (`InvalidProofEncoding`).
    ix_data.shared_viewing_key_commitment[0] ^= 1;

    let owner = Keypair::new();
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let vka = vka_pda(&test.program_id, &owner.pubkey());

    let ix = CreateViewingKeyAccount {
        enrollment_authority: test.payer.pubkey(),
        owner_identity: owner.pubkey(),
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        data: ix_data,
    }
    .instruction();

    // Raise the CU limit so the rejection is a genuine verification failure, not a
    // budget artifact.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&owner])
        .expect_err("tampered proof must be rejected on-chain");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::KeyEncryptionProofVerificationFailed as u32,
    );
    assert_eq!(custom_code(&err), 8041);
}

/// Five recovery keys plus the zone's auditor, six keys total, proved as two
/// folded legs of three. A fold's public input equals the chain a single
/// circuit over the whole recipient set would expose, so the program composes
/// it the same way and only selects a different verifying key.
#[test]
fn create_viewing_key_account_verifies_a_folded_proof_on_chain() {
    let mut test = boot_with_prover();

    let recovery: Vec<P256Pubkey> = (0..5)
        .map(|_| P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key()))
        .collect();
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let zone_config = create_zone_config(&mut test, &auditor);

    let mut recipient_keys = recovery.clone();
    recipient_keys.push(auditor);

    let proof_inputs = KeyEncryptionFoldProofInputs {
        viewing_secret_key: SecretKey::random(&mut OsRng),
        ephemeral_secret_key: SecretKey::random(&mut OsRng),
        nullifier_secret: random_bn254_scalar(),
        recipient_keys,
        old_state_hash: [0u8; 32],
    };

    let (ix_data, _result) = prove_create_viewing_key_account_folded(
        proof_inputs,
        recovery.len(),
        &prover_url(SERVER_ADDRESS),
    )
    .expect("folded key-encryption proof generation must succeed");

    assert_eq!(ix_data.key_ciphertexts.len(), 6);

    let owner = Keypair::new();
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let vka = vka_pda(&test.program_id, &owner.pubkey());

    let ix = CreateViewingKeyAccount {
        enrollment_authority: test.payer.pubkey(),
        owner_identity: owner.pubkey(),
        viewing_key_account: vka,
        zone_config,
        system_program: Pubkey::default(),
        data: ix_data.clone(),
    }
    .instruction();

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    test.send(&[budget, ix], &[&owner])
        .expect("the folded proof must verify on-chain and create the account");

    let account_data = test.account_data(&vka).expect("viewing key account exists");
    let account = ViewingKeyAccount::deserialize(&account_data).expect("deserialize vka");
    let expected_recovery: Vec<[u8; 33]> = recovery.iter().map(|k| *k.as_bytes()).collect();
    assert_eq!(account.recovery_keys, expected_recovery);
    assert_eq!(account.auditor_keys, vec![*auditor.as_bytes()]);
    assert_eq!(account.recovery_key_ciphertexts.len(), recovery.len());
    assert_eq!(account.auditor_key_ciphertexts.len(), 1);
}
