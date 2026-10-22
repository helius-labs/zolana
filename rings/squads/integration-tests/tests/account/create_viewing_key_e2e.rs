//! End-to-end on-chain test for `create_viewing_key_account` (tag 5): build a
//! REAL key-encryption Groth16 proof with the squads SDK (prover feature), send
//! the `create_viewing_key_account` instruction through LiteSVM, and assert the
//! program VERIFIED THE PROOF ON-CHAIN and initialized the `ViewingKeyAccount`
//! PDA with exactly the witness-derived key material.
//!
//! This closes the loop SDK -> prover -> on-chain program: the proof's
//! public-input hash is computed by the SDK from the same shared viewing
//! key/commitment/ephemeral/recovery+auditor keys/ciphertexts/nullifier that are
//! placed into `CreateViewingKeyAccountIxData`, and the program recomputes that
//! hash from the instruction data plus the `ring_config` auditor key. The ring
//! config's auditor key therefore equals the witness's trailing auditor recipient
//! key, and the recovery key(s)/ciphertext ordering match the witness.
//!
//! GATING: the test requires the prebuilt program `.so` (skips if missing, like
//! the other harness tests) . Proofs come from `squads-prover`; the
//! first proof of a circuit loads its proving key.
//!
//! Build the program first:
//!   cd rings/squads/program && cargo build-sbf --features bpf-entrypoint
//! Run with:
//!   cargo test --manifest-path rings/squads/Cargo.toml -p squads-ring-tests --test create_viewing_key_e2e -- --nocapture

use rand::{rngs::OsRng, RngCore};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_keypair::X25519Keypair;
use zolana_keypair::X25519Pubkey;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_X25519_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsRingError,
    instruction::{
        builders::{CreateRingConfig, CreateViewingKeyAccount},
        CreateRingConfigIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    types::Address,
    RING_CONFIG_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED,
};
use zolana_squads_sdk::prover::{
    key_encryption::KeyEncryptionWitness, viewing_key_account::prove_create_viewing_key_account,
};

/// A random BN254-range scalar (top byte cleared so it is < the field modulus).
/// Used for the nullifier secret, which is a BN254 field element by design; the
/// viewing and ephemeral secrets are full-range X25519 secret bytes.
fn random_bn254_scalar() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0; // < 2^248 < BN254 modulus.
    b
}

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

/// Boot LiteSVM with the program, returns `None` (a clean skip) if the `.so` is
/// missing.
fn boot_program() -> Option<SquadsRingTest> {
    let test = SquadsRingTest::new().expect("boot")?;
    Some(test)
}

/// Create the ring config whose single auditor key is `auditor`, signed by a
/// funded creator.
fn create_ring_config(test: &mut SquadsRingTest, auditor: &X25519Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let ring_config = ring_config_pda(&test.program_id);

    let ix = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: Pubkey::new_from_array([7u8; 32]),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![*auditor.as_bytes()],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_ring_config");
    ring_config
}

/// numKeys = 2 (one recovery key + the ring's one auditor): build a real proof
/// and the matching instruction data, send `create_viewing_key_account`, and
/// assert the program verified the proof on-chain and initialized the PDA.
#[test]
fn create_viewing_key_account_verifies_real_proof_on_chain() {
    let Some(mut test) = boot_program() else {
        return;
    };

    // The auditor key MUST match the ring config; it is the trailing recipient in
    // the witness. The owner registers one recovery key, so the owner must sign.
    let auditor = X25519Keypair::new().pubkey();
    let recovery = X25519Keypair::new().pubkey();

    let ring_config = create_ring_config(&mut test, &auditor);

    let witness = KeyEncryptionWitness {
        viewing_secret_key: X25519Keypair::new(),
        ephemeral_secret_key: X25519Keypair::new(),
        nullifier_secret: random_bn254_scalar(),
        // Recovery first, then auditor: the program reads recovery keys from
        // instruction data and the auditor from ring_config, in that order.
        recipient_keys: vec![recovery, auditor],
        old_state_hash: [0u8; 32],
    };

    // recovery_count = 1: the first recipient is the recovery key; the trailing
    // one is the auditor (sourced from ring_config on-chain).
    let (ix_data, proof_result) = prove_create_viewing_key_account(witness, 1)
        .expect("real key-encryption proof generation must succeed");

    // Sanity-check the SDK assembled consistent instruction data.
    assert_eq!(ix_data.encryption_scheme, ENCRYPTION_SCHEME_X25519_AES);
    assert_eq!(ix_data.recovery_keys, vec![*recovery.as_bytes()]);
    assert_eq!(ix_data.key_ciphertexts.len(), 2); // recovery + auditor
    assert_eq!(
        ix_data.shared_viewing_key,
        *proof_result.shared_viewing_pubkey.as_bytes()
    );

    // The owner signs to register its recovery key.
    let owner = Keypair::new();
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let vka = vka_pda(&test.program_id, &owner.pubkey());

    let ix = CreateViewingKeyAccount {
        fee_payer: test.payer.pubkey(),
        owner: owner.pubkey(),
        owner_signs: true,
        viewing_key_account: vka,
        ring_config,
        system_program: Pubkey::default(),
        data: ix_data.clone(),
    }
    .instruction();

    // On-chain Groth16 verification happens HERE. BSB22 pairing verification is
    // CU-heavy, so raise the limit above the 200k default.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    test.send(&[budget, ix], &[&owner])
        .expect("create_viewing_key_account must verify the proof on-chain and succeed");

    // The PDA now exists, owned by the program, with the witness-derived fields.
    let account_data = test.account_data(&vka).expect("viewing key account exists");
    let account = ViewingKeyAccount::deserialize(&account_data).expect("deserialize vka");

    let expected = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner.pubkey().to_bytes()),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_X25519_AES,
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

/// Negative control: tamper one byte of a public input (the shared-viewing-key
/// commitment) and assert the program rejects it on-chain with
/// `KeyEncryptionProofVerificationFailed` (8041). This proves the program
/// genuinely runs the Groth16 verifier rather than blindly accepting.
#[test]
fn create_viewing_key_account_rejects_tampered_proof() {
    let Some(mut test) = boot_program() else {
        return;
    };

    let auditor = X25519Keypair::new().pubkey();
    let recovery = X25519Keypair::new().pubkey();
    let ring_config = create_ring_config(&mut test, &auditor);

    let witness = KeyEncryptionWitness {
        viewing_secret_key: X25519Keypair::new(),
        ephemeral_secret_key: X25519Keypair::new(),
        nullifier_secret: random_bn254_scalar(),
        recipient_keys: vec![recovery, auditor],
        old_state_hash: [0u8; 32],
    };
    let (mut ix_data, _result) = prove_create_viewing_key_account(witness, 1)
        .expect("real key-encryption proof generation must succeed");

    // Tamper a public input the program binds the proof to: flipping a byte of the
    // shared-viewing-key commitment makes the program recompute a DIFFERENT
    // public-input hash, so the (still well-formed, decompressable) Groth16 proof
    // fails the pairing check. Tampering the proof bytes directly would instead
    // fail point decompression first (`InvalidProofEncoding`, 8039); corrupting a
    // public input exercises the verifier proper and yields the pairing-failure
    // code 8041.
    ix_data.shared_viewing_key_commitment[0] ^= 1;

    let owner = Keypair::new();
    test.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("fund owner");
    let vka = vka_pda(&test.program_id, &owner.pubkey());

    let ix = CreateViewingKeyAccount {
        fee_payer: test.payer.pubkey(),
        owner: owner.pubkey(),
        owner_signs: true,
        viewing_key_account: vka,
        ring_config,
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
        SquadsRingError::KeyEncryptionProofVerificationFailed as u32,
    );
    assert_eq!(custom_code(&err), 8041);
}
