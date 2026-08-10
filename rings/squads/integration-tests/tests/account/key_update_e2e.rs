//! On-chain tests for the key-update rotation lifecycle,
//! `update_viewing_key_account` (tag 6) -> `fill_key_update` (tag 7) ->
//! `execute_key_update` (tag 14), settled with a real key-encryption
//! Groth16 proof built by the squads SDK.
//!
//! The SDK proves the new shared viewing key is encrypted to the recovery
//! keys (R) and the zone auditor (A). The program verifies that proof,
//! copies the `K = R + A` ciphertexts from the filled proposal buffer, and
//! rotates the `ViewingKeyAccount` without changing its recovery set.
//!
//! Tests skip when the prebuilt `.so` is missing or the prover server is
//! unreachable.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, prover_url, SquadsZoneTest};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_hasher::Hasher;
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::{
        builders::{ExecuteKeyUpdate, FillKeyUpdate, UpdateViewingKeyAccount},
        ExecuteKeyUpdateIxData, FillKeyUpdateIxData, UpdateViewingKeyAccountIxData,
    },
    state::{
        key_update_proposal::KeyOperation, viewing_key_account::ViewingKeyAccount,
        zone_config::ZoneConfig,
    },
    types::Address,
    KEY_UPDATE_PROPOSAL_PDA_SEED, VIEWING_KEY_ACCOUNT_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::{prove_execute_key_update, KeyEncryptionProofInputs};

/// A random BN254-range scalar (top byte cleared so it is < the field
/// modulus). The nullifier secret is a BN254 field element by design. The
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

/// Must match the key-encryption circuit's nullifier-pubkey derivation.
fn nullifier_pubkey(secret: &[u8; 32]) -> [u8; 32] {
    zolana_hasher::Poseidon::hashv(&[secret.as_slice()]).expect("poseidon")
}

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn vka_pda(program_id: &Pubkey, owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()], program_id).0
}

fn proposal_pda(program_id: &Pubkey, target: &Pubkey, domain: u16, key_nonce: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            KEY_UPDATE_PROPOSAL_PDA_SEED,
            target.as_ref(),
            &domain.to_le_bytes(),
            &key_nonce.to_le_bytes(),
        ],
        program_id,
    )
    .0
}

/// A prover the tests cannot reach is a failure. A run that quietly skips
/// every proof-backed case reports green while proving nothing.
fn boot_with_prover() -> SquadsZoneTest {
    spawn_prover().expect("the prover server must be reachable, see ZOLANA_PROVER_URL");
    SquadsZoneTest::new().expect("boot")
}

fn create_zone_config(
    test: &mut SquadsZoneTest,
    co_signer: &Pubkey,
    auditor: &P256Pubkey,
) -> Pubkey {
    let zone_config = zone_config_pda(&test.program_id);
    let config = ZoneConfig::new(
        Address::new_from_array([7u8; 32]),
        Address::new_from_array(co_signer.to_bytes()),
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

fn seed_target_vka(
    test: &mut SquadsZoneTest,
    owner: &Pubkey,
    recovery_keys: &[P256Pubkey],
    auditor: &P256Pubkey,
    nullifier_pubkey: [u8; 32],
) -> (Pubkey, ViewingKeyAccount) {
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
        nullifier_pubkey,
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
    (pda, account)
}

struct Prepared {
    target: Pubkey,
    zone_config: Pubkey,
    proposal: Pubkey,
    executor: Keypair,
    co_signer: Keypair,
    rent_payer: Pubkey,
    ix_data: ExecuteKeyUpdateIxData,
    buffer: Vec<[u8; 32]>,
    pre_rotation: ViewingKeyAccount,
    expected: ViewingKeyAccount,
}

/// Run the lifecycle up to but not including `execute_key_update`.
///
/// `auditor` is the target account's own auditor. `zone_auditor` is the one the
/// zone config publishes. They differ only when a test checks that a rotation
/// leaves the account's auditor set alone.
fn prepare_rotation(
    test: &mut SquadsZoneTest,
    operations: Vec<KeyOperation>,
    initial_recovery: &[P256Pubkey],
    resulting_recovery: &[P256Pubkey],
    auditor: &P256Pubkey,
    zone_auditor: &P256Pubkey,
) -> Prepared {
    let executor = Keypair::new();
    test.airdrop(&executor.pubkey(), 1_000_000_000)
        .expect("fund executor");
    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co-signer");
    let owner = Keypair::new();

    // The rotation re-encrypts this secret to the new shared viewing key, so
    // the stored nullifier public key must survive it unchanged.
    let nullifier_secret = random_bn254_scalar();
    let zone_config = create_zone_config(test, &co_signer.pubkey(), zone_auditor);
    let (target, target_account) = seed_target_vka(
        test,
        &owner.pubkey(),
        initial_recovery,
        auditor,
        nullifier_pubkey(&nullifier_secret),
    );

    let domain = 1u16;
    let proposal = proposal_pda(&test.program_id, &target, domain, target_account.key_nonce);

    // A keypair owner is not a Solana signer, so the zone co-signer opens the
    // proposal and receives the rent refund.
    let create = UpdateViewingKeyAccount {
        proposer: co_signer.pubkey(),
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
    test.send(&[create], &[&co_signer])
        .expect("update_viewing_key_account (create proposal)");

    // recipient_keys order is the resulting recovery keys, then the auditor.
    // The SDK helper binds the proof to `target_account`.
    let (viewing_sk, _viewing_pk) = random_p256();
    let mut recipient_keys: Vec<P256Pubkey> = resulting_recovery.to_vec();
    recipient_keys.push(*auditor);
    let proof_inputs = KeyEncryptionProofInputs {
        viewing_secret_key: viewing_sk,
        ephemeral_secret_key: SecretKey::random(&mut OsRng),
        nullifier_secret,
        recipient_keys,
        old_state_hash: [0u8; 32],
    };
    let (ix_data, buffer, _result) =
        prove_execute_key_update(proof_inputs, &target_account, &prover_url(SERVER_ADDRESS))
            .expect("rotation proof must succeed");

    let fill = FillKeyUpdate {
        executor: executor.pubkey(),
        key_update_proposal: proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: buffer.clone(),
        },
    }
    .instruction();
    test.send(&[fill], &[&executor]).expect("fill_key_update");

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
        nullifier_pubkey: target_account.nullifier_pubkey,
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
        rent_payer: co_signer.pubkey(),
        executor,
        co_signer,
        ix_data,
        buffer,
        pre_rotation: target_account,
        expected,
    }
}

fn execute_ix(p: &Prepared, data: ExecuteKeyUpdateIxData) -> solana_instruction::Instruction {
    ExecuteKeyUpdate {
        executor: p.executor.pubkey(),
        co_signer: p.co_signer.pubkey(),
        viewing_key_account: p.target,
        zone_config: p.zone_config,
        key_update_proposal: p.proposal,
        rent_recipient: p.rent_payer,
        system_program: Pubkey::default(),
        data,
    }
    .instruction()
}

fn settle_and_assert(test: &mut SquadsZoneTest, p: &Prepared) {
    let proposal_lamports = test.lamports(&p.proposal).expect("proposal funded");
    let rent_payer_before = test.lamports(&p.rent_payer).unwrap_or(0);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(p, p.ix_data);
    test.send(&[budget, ix], &[&p.executor, &p.co_signer])
        .expect("execute_key_update must verify the rotation proof on-chain and succeed");

    let account_data = test.account_data(&p.target).expect("target vka exists");
    let account = ViewingKeyAccount::deserialize(&account_data).expect("deserialize rotated vka");
    assert_eq!(account, p.expected);
    // `deposit` binds a UTXO's owner to `Poseidon(owner, nullifier_pubkey)` and
    // the spend proof binds the value the account holds now. Both components
    // survive the rotation, so every pre-rotation UTXO stays spendable.
    assert_eq!(account.owner, p.pre_rotation.owner);
    assert_eq!(
        account.nullifier_pubkey, p.pre_rotation.nullifier_pubkey,
        "a rotation must not orphan pre-rotation UTXOs"
    );

    assert_eq!(
        test.account_data(&p.proposal).map(|d| d.len()).unwrap_or(0),
        0
    );
    let rent_payer_after = test.lamports(&p.rent_payer).unwrap_or(0);
    assert_eq!(rent_payer_after, rent_payer_before + proposal_lamports);
}

#[test]
fn execute_key_update_pure_rotation_no_ops_verifies_on_chain() {
    let mut test = boot_with_prover();

    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, auditor) = random_p256();

    let prepared = prepare_rotation(&mut test, vec![], &[r0], &[r0], &auditor, &auditor);
    settle_and_assert(&mut test, &prepared);
}

#[test]
fn execute_key_update_rejects_tampered_proof() {
    let mut test = boot_with_prover();

    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, auditor) = random_p256();
    let prepared = prepare_rotation(&mut test, vec![], &[r0], &[r0], &auditor, &auditor);

    // Flip a byte of a bound public input. The program recomputes a different
    // public-input hash, so the still-decompressable proof fails the pairing
    // check.
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

/// Creation gates an auditor change behind the co-signer, so a rotation that
/// declares no operation must leave the account's auditor set alone even when
/// the zone config publishes a different auditor.
#[test]
fn execute_key_update_no_op_keeps_the_account_auditor() {
    let mut test = boot_with_prover();

    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, account_auditor) = random_p256();
    let (_zone_aud_sk, zone_auditor) = random_p256();

    let prepared = prepare_rotation(
        &mut test,
        vec![],
        &[r0],
        &[r0],
        &account_auditor,
        &zone_auditor,
    );
    assert_eq!(
        prepared.expected.auditor_keys,
        vec![*account_auditor.as_bytes()]
    );
    settle_and_assert(&mut test, &prepared);
}

/// A fresh nullifier public key would orphan every pre-rotation UTXO, so the
/// rotation must refuse it instead of applying it.
#[test]
fn execute_key_update_rejects_a_changed_nullifier_pubkey() {
    let mut test = boot_with_prover();

    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, auditor) = random_p256();
    let prepared = prepare_rotation(&mut test, vec![], &[r0], &[r0], &auditor, &auditor);

    let mut ix_data = prepared.ix_data;
    ix_data.new_nullifier_pubkey = nullifier_pubkey(&random_bn254_scalar());

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(&prepared, ix_data);
    let err = test
        .send(&[budget, ix], &[&prepared.executor, &prepared.co_signer])
        .expect_err("a rotation must keep the account's nullifier public key");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::NullifierPubkeyRotationUnsupported as u32,
    );
}

#[test]
fn execute_key_update_rejects_replay_after_nonce_advance() {
    let mut test = boot_with_prover();

    let (_r0_sk, r0) = random_p256();
    let (_aud_sk, auditor) = random_p256();
    let prepared = prepare_rotation(&mut test, vec![], &[r0], &[r0], &auditor, &auditor);
    settle_and_assert(&mut test, &prepared);

    // The settled rotation advanced the nonce, so a new proposal is opened at
    // nonce 1.
    let domain = 2u16;
    let replay_proposal = proposal_pda(&test.program_id, &prepared.target, domain, 1);
    let create = UpdateViewingKeyAccount {
        proposer: prepared.co_signer.pubkey(),
        target: prepared.target,
        key_update_proposal: replay_proposal,
        system_program: Pubkey::default(),
        zone_config: prepared.zone_config,
        data: UpdateViewingKeyAccountIxData {
            domain,
            executor: prepared.executor.pubkey(),
            operations: vec![],
            expiry: i64::MAX,
        },
    }
    .instruction();
    test.send(&[create], &[&prepared.co_signer])
        .expect("create replay proposal");

    let fill = FillKeyUpdate {
        executor: prepared.executor.pubkey(),
        key_update_proposal: replay_proposal,
        data: FillKeyUpdateIxData {
            ciphertexts: prepared.buffer.clone(),
        },
    }
    .instruction();
    test.send(&[fill], &[&prepared.executor])
        .expect("fill replay proposal");

    let replay = ExecuteKeyUpdate {
        executor: prepared.executor.pubkey(),
        co_signer: prepared.co_signer.pubkey(),
        viewing_key_account: prepared.target,
        zone_config: prepared.zone_config,
        key_update_proposal: replay_proposal,
        rent_recipient: prepared.rent_payer,
        system_program: Pubkey::default(),
        data: prepared.ix_data,
    }
    .instruction();
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(
            &[budget, replay],
            &[&prepared.executor, &prepared.co_signer],
        )
        .expect_err("proof bound to the prior nonce must not authorize another rotation");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::KeyEncryptionProofVerificationFailed as u32,
    );
}
