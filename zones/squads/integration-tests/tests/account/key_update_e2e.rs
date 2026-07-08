//! End-to-end on-chain test for the key-update rotation lifecycle:
//! `update_viewing_key_account` (tag 6) -> `fill_key_update` (tag 7) ->
//! `execute_key_update` (tag 14), settled with a REAL key-encryption (rotation)
//! Groth16 proof built by the squads SDK.
//!
//! This closes the loop SDK -> prover -> on-chain program for `execute_key_update`:
//! the SDK proves the new shared viewing key is encrypted to the resulting recovery
//! keys (R') and the zone auditor (A), and the program verifies that proof, applies
//! the proposal's operations, copies the `K = R' + A` ciphertexts from the filled
//! proposal buffer, and rotates the `ViewingKeyAccount`.
//!
//! The rotation proof uses `old_state_hash = 0`, matching the value the program
//! currently passes (the prior-state-hash binding is a separate, pending change).
//!
//! GATING: requires the prebuilt program `.so` (skips if missing) AND a reachable
//! prover server (skips if `spawn_prover` fails). The first proof request
//! lazy-loads a large proving key and can take minutes.
//!
//! Build the program first:
//!   cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
//! Run with:
//!   cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests --test key_update_e2e -- --nocapture

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, prover_url, SquadsZoneTest};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, KEY_OP_ADD, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE,
    },
    error::SquadsZoneError,
    instruction::{
        builders::{CreateZoneConfig, ExecuteKeyUpdate, FillKeyUpdate, UpdateViewingKeyAccount},
        CreateZoneConfigIxData, ExecuteKeyUpdateIxData, FillKeyUpdateIxData,
        UpdateViewingKeyAccountIxData,
    },
    state::{key_update_proposal::KeyOperation, viewing_key_account::ViewingKeyAccount},
    types::Address,
    KEY_UPDATE_PROPOSAL_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::{prove_execute_key_update, KeyEncryptionWitness};

/// A random BN254-range scalar (top byte cleared so it is < the field modulus).
/// Used for the nullifier secret, which is a BN254 field element by design; the
/// viewing and ephemeral secrets are full-range P-256 scalars.
fn random_bn254_scalar() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

fn random_p256() -> (SecretKey, P256Pubkey) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = P256Pubkey::from_p256(&sk.public_key());
    (sk, pk)
}

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
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

/// Boot LiteSVM with the program; returns `None` if the `.so` is missing or the
/// prover server is unreachable (clean skip in both cases).
fn boot_with_prover() -> Option<SquadsZoneTest> {
    let test = SquadsZoneTest::new().expect("boot")?;
    if spawn_prover().is_err() {
        eprintln!("skipping key_update_e2e: prover server not reachable");
        return None;
    }
    Some(test)
}

/// Create the zone config with the given co-signer and single auditor key.
fn create_zone_config(
    test: &mut SquadsZoneTest,
    co_signer: &Pubkey,
    auditor: &P256Pubkey,
) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let zone_config = zone_config_pda(&test.program_id);
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

/// Seed the target viewing key account (pre-rotation) with the given real P-256
/// recovery + auditor keys. Ciphertexts/commitment/nullifier are arbitrary
/// fixtures -- the rotation proof binds the NEW material, not these.
fn seed_target_vka(
    test: &mut SquadsZoneTest,
    owner: &Pubkey,
    recovery_keys: &[P256Pubkey],
    auditor: &P256Pubkey,
) -> Pubkey {
    let pda = vka_pda(&test.program_id, owner);
    let recovery_bytes: Vec<[u8; 33]> = recovery_keys.iter().map(|k| *k.as_bytes()).collect();
    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner.to_bytes()),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: [0u8; 33],
        shared_viewing_key_commitment: [0u8; 32],
        key_nonce: 0,
        nullifier_pubkey: [0u8; 32],
        key_ciphertext_ephemeral: [0u8; 33],
        encrypted_nullifier_secret: [0u8; 31],
        recovery_key_ciphertexts: vec![[0u8; 32]; recovery_bytes.len()],
        recovery_keys: recovery_bytes,
        auditor_keys: vec![*auditor.as_bytes()],
        auditor_key_ciphertexts: vec![[0u8; 32]],
    };
    let bytes = account.serialize().expect("serialize target vka");
    test.set_program_account(&pda, bytes)
        .expect("seed target vka");
    // `execute_key_update` has no payer to fund a rent top-up, so a rotation that
    // grows the account (adds a recovery key) requires the account to already hold
    // rent for the larger size. Over-fund the seeded account to cover growth.
    test.airdrop(&pda, 100_000_000)
        .expect("over-fund target vka");
    pda
}

/// Everything a happy-path or tamper test needs to send `execute_key_update`.
struct Prepared {
    target: Pubkey,
    zone_config: Pubkey,
    proposal: Pubkey,
    executor: Keypair,
    co_signer: Keypair,
    /// rent_payer / rent_recipient.
    proposer: Pubkey,
    ix_data: ExecuteKeyUpdateIxData,
    expected: ViewingKeyAccount,
}

/// Run the lifecycle up to (but not including) `execute_key_update`: create the
/// zone config + target VKA, create the proposal (tag 6) with `operations`, prove
/// the rotation to `resulting_recovery ++ [auditor]`, and fill the buffer (tag 7).
/// Returns the prepared `execute_key_update` inputs and the expected rotated
/// account.
fn prepare_rotation(
    test: &mut SquadsZoneTest,
    operations: Vec<KeyOperation>,
    initial_recovery: &[P256Pubkey],
    resulting_recovery: &[P256Pubkey],
    auditor: &P256Pubkey,
) -> Prepared {
    let proposer = Keypair::new();
    test.airdrop(&proposer.pubkey(), 1_000_000_000)
        .expect("fund proposer");
    let executor = Keypair::new();
    test.airdrop(&executor.pubkey(), 1_000_000_000)
        .expect("fund executor");
    let co_signer = Keypair::new();
    let owner = Keypair::new();

    let zone_config = create_zone_config(test, &co_signer.pubkey(), auditor);
    let target = seed_target_vka(test, &owner.pubkey(), initial_recovery, auditor);

    let domain = 1u16;
    let proposal = proposal_pda(&test.program_id, &target, domain);

    // Tag 6: create the key-update proposal. The recovery-ops path needs only the
    // proposer's signature (the program does not bind the proposer identity here).
    let create = UpdateViewingKeyAccount {
        proposer: proposer.pubkey(),
        target,
        key_update_proposal: proposal,
        system_program: Pubkey::default(),
        zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            executor: executor.pubkey(),
            operations,
            expiry: i64::MAX,
        },
    }
    .instruction();
    test.send(&[create], &[&proposer])
        .expect("update_viewing_key_account (create proposal)");

    // Build the rotation proof. recipient_keys = resulting recovery keys (R') then
    // the auditor; old_state_hash = 0 (matches the on-chain hardcode).
    let (viewing_sk, _viewing_pk) = random_p256();
    let mut recipient_keys: Vec<P256Pubkey> = resulting_recovery.to_vec();
    recipient_keys.push(*auditor);
    let witness = KeyEncryptionWitness {
        viewing_secret_key: viewing_sk,
        ephemeral_secret_key: SecretKey::random(&mut OsRng),
        nullifier_secret: random_bn254_scalar(),
        recipient_keys,
        old_state_hash: [0u8; 32],
    };
    let (ix_data, buffer, _result) = prove_execute_key_update(witness, &prover_url(SERVER_ADDRESS))
        .expect("rotation proof must succeed");

    // Tag 7: fill the proposal buffer with the K = R' + A ciphertexts in recovery-
    // then-auditor order.
    let fill = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: buffer.clone(),
        },
    }
    .instruction();
    test.send(&[fill], &[&executor]).expect("fill_key_update");

    // Expected rotated account: recovery keys = R', ciphertexts split at R', auditor
    // from zone config, new key material from the instruction data, key_nonce += 1.
    let recovery_count = resulting_recovery.len();
    let recovery_ciphertexts = buffer
        .get(..recovery_count)
        .expect("recovery slice")
        .to_vec();
    let auditor_ciphertexts = buffer
        .get(recovery_count..)
        .expect("auditor slice")
        .to_vec();
    let recovery_key_bytes: Vec<[u8; 33]> =
        resulting_recovery.iter().map(|k| *k.as_bytes()).collect();
    let expected = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(owner.pubkey().to_bytes()),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: ix_data.new_shared_viewing_key,
        shared_viewing_key_commitment: ix_data.new_shared_viewing_key_commitment,
        key_nonce: 1,
        nullifier_pubkey: ix_data.new_nullifier_pubkey,
        key_ciphertext_ephemeral: ix_data.new_key_ciphertext_ephemeral,
        encrypted_nullifier_secret: ix_data.new_encrypted_nullifier_secret,
        recovery_keys: recovery_key_bytes,
        recovery_key_ciphertexts: recovery_ciphertexts,
        auditor_keys: vec![*auditor.as_bytes()],
        auditor_key_ciphertexts: auditor_ciphertexts,
    };

    Prepared {
        target,
        zone_config,
        proposal,
        executor,
        co_signer,
        proposer: proposer.pubkey(),
        ix_data,
        expected,
    }
}

/// Build the `execute_key_update` instruction from prepared inputs (rent_recipient
/// is the proposer, who paid the proposal rent).
fn execute_ix(p: &Prepared, data: ExecuteKeyUpdateIxData) -> solana_instruction::Instruction {
    ExecuteKeyUpdate {
        executor: p.executor.pubkey(),
        co_signer: p.co_signer.pubkey(),
        viewing_key_account: p.target,
        zone_config: p.zone_config,
        key_update_proposal: p.proposal,
        rent_recipient: p.proposer,
        system_program: Pubkey::default(),
        data,
    }
    .instruction()
}

/// Settle the rotation and assert the rotated account + proposal close + refund.
fn settle_and_assert(test: &mut SquadsZoneTest, p: &Prepared) {
    let proposal_lamports = test.lamports(&p.proposal).expect("proposal funded");
    let proposer_before = test.lamports(&p.proposer).unwrap_or(0);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(p, p.ix_data);
    test.send(&[budget, ix], &[&p.executor, &p.co_signer])
        .expect("execute_key_update must verify the rotation proof on-chain and succeed");

    // Rotated account matches expected exactly.
    let account_data = test.account_data(&p.target).expect("target vka exists");
    let account = ViewingKeyAccount::deserialize(&account_data).expect("deserialize rotated vka");
    assert_eq!(account, p.expected);

    // Proposal closed and its rent refunded to the proposer (rent_payer).
    assert_eq!(
        test.account_data(&p.proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
    let proposer_after = test.lamports(&p.proposer).unwrap_or(0);
    assert_eq!(proposer_after, proposer_before + proposal_lamports);
}

#[test]
fn execute_key_update_rotation_with_add_op_verifies_on_chain() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    // Target starts with one recovery key; the proposal ADDs a second. R' = 2, A = 1.
    let (_r0_sk, r0) = random_p256();
    let (_r1_sk, r1) = random_p256();
    let (_aud_sk, auditor) = random_p256();

    let operations = vec![KeyOperation {
        op: KEY_OP_ADD,
        index: 0,
        key: *r1.as_bytes(),
    }];
    let prepared = prepare_rotation(&mut test, operations, &[r0], &[r0, r1], &auditor);
    settle_and_assert(&mut test, &prepared);
}

#[test]
fn execute_key_update_pure_rotation_no_ops_verifies_on_chain() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    // No operations: the recovery set is unchanged (R' = R = 1), only the shared key
    // material rotates. A = 1.
    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, auditor) = random_p256();

    let prepared = prepare_rotation(&mut test, vec![], &[r0], &[r0], &auditor);
    settle_and_assert(&mut test, &prepared);
}

#[test]
fn execute_key_update_rejects_tampered_proof() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, auditor) = random_p256();
    let prepared = prepare_rotation(&mut test, vec![], &[r0], &[r0], &auditor);

    // Flip a byte of a public input the program binds the proof to: the program
    // recomputes a different public-input hash, so the (still decompressable) proof
    // fails the pairing check.
    let mut ix_data = prepared.ix_data;
    ix_data.new_shared_viewing_key_commitment[0] ^= 1;

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(&prepared, ix_data);
    let err = test
        .send(&[budget, ix], &[&prepared.executor, &prepared.co_signer])
        .expect_err("tampered rotation proof must be rejected on-chain");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::KeyEncryptionProofVerificationFailed as u32,
    );
}
