//! On-chain tests for `fold_transact` (tag 17). Two folded `(2,2)` legs
//! spend three UTXOs of one account, and the program verifies the fold proof
//! on-chain against the live viewing key accounts.
//!
//! As in `transact_e2e`, `spp_program` is a placeholder the SPP-address
//! check rejects, so the run stops at the first settlement CPI. A genuine
//! settlement needs a real SPP program plus an initialized tree, which the
//! composed localnet suite owns. `fold_transact_rejects_a_tampered_leg`
//! fails earlier, in fold verification, and never reaches the CPI.
//!
//! Tests skip when the prebuilt `.so` is missing or the prover server is
//! unreachable.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, prover_url, SquadsRingTest};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT,
        VIEWING_KEY_STATE_ACTIVE,
    },
    error::SquadsRingError,
    instruction::{
        builders::FoldTransact,
        instruction_data::{EncryptedUtxos, InputContext},
        FoldTransactIxData, FoldTransactLeg,
    },
    state::{ring_config::SquadsRingConfig, viewing_key_account::ViewingKeyAccount},
    types::Address,
    RING_AUTH_PDA_SEED, RING_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::{
    ring::{derive_change_blinding, RingProofInputs, RingRecipient, RingUtxo},
    ring_fold::prove_ring_fold,
};

fn random_field() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

fn nullifier_pubkey(secret: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[secret.as_slice()]).expect("poseidon")
}

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

fn ring_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], program_id).0
}

/// A prover the tests cannot reach is a failure. A run that quietly skips
/// every proof-backed case reports green while proving nothing.
fn boot_with_prover() -> SquadsRingTest {
    spawn_prover().expect("the prover server must be reachable, see ZOLANA_PROVER_URL");
    SquadsRingTest::new().expect("boot")
}

fn create_ring_config(test: &mut SquadsRingTest, co_signer: &Pubkey) -> Pubkey {
    let ring_config = ring_config_pda(&test.program_id);
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let config = SquadsRingConfig::new(
        Address::new_from_array([7u8; 32]),
        Address::new_from_array(co_signer.to_bytes()),
        3_600,
        vec![*auditor.as_bytes()],
        vec![],
    );
    test.set_program_account(
        &ring_config,
        config.serialize().expect("serialize ring config"),
    )
    .expect("seed ring config");
    ring_config
}

fn install_vka(
    test: &mut SquadsRingTest,
    owner_key_hash: [u8; 32],
    owner_kind: u8,
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
        owner_kind,
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

fn utxo(amount: u64, owner_key_hash: [u8; 32], nullifier_pk: [u8; 32], is_dummy: bool) -> RingUtxo {
    RingUtxo {
        owner_key_hash,
        nullifier_pubkey: nullifier_pk,
        asset: [0u8; 32],
        amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy,
    }
}

struct FoldSetup {
    ring_config: Pubkey,
    sender_vka: Pubkey,
    recipient_vka: Pubkey,
    co_signer: Keypair,
    data: FoldTransactIxData,
}

fn build_fold(test: &mut SquadsRingTest) -> FoldSetup {
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_viewing_bytes = *recipient_viewing.as_bytes();
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();
    let recipient = RingRecipient {
        owner_key_hash: recipient_owner,
        nullifier_pubkey: recipient_nullifier_pk,
        viewing_pubkey: recipient_viewing,
    };

    // Three real UTXOs across two legs. The second leg pads its free slot with a
    // dummy, which is what the `(2,2)` shape forces for an odd count.
    let leg_amounts = [(700u64, Some(300u64), 400u64), (500, None, 200)];
    let legs: Vec<RingProofInputs> = leg_amounts
        .iter()
        .map(|(first, second, transferred)| {
            let inputs = vec![
                utxo(*first, sender_owner, sender_nullifier_pk, false),
                utxo(
                    second.unwrap_or(0),
                    sender_owner,
                    sender_nullifier_pk,
                    second.is_none(),
                ),
            ];
            let change_blinding =
                derive_change_blinding(&sender_viewing, &sender_nullifier_secret, &inputs[0])
                    .expect("derive change blinding");
            let change = RingUtxo {
                owner_key_hash: sender_owner,
                nullifier_pubkey: sender_nullifier_pk,
                asset: [0u8; 32],
                amount: first + second.unwrap_or(0) - transferred,
                blinding: change_blinding,
                program_data_hash: [0u8; 32],
                ring_data_hash: [0u8; 32],
                ring_program_id: [0u8; 32],
                is_dummy: false,
            };
            let recipient_output = RingUtxo {
                owner_key_hash: recipient_owner,
                nullifier_pubkey: recipient_nullifier_pk,
                asset: [0u8; 32],
                amount: *transferred,
                blinding: random_field(),
                program_data_hash: [0u8; 32],
                ring_data_hash: [0u8; 32],
                ring_program_id: [0u8; 32],
                is_dummy: false,
            };
            RingProofInputs {
                viewing_secret_key: sender_viewing.clone(),
                nullifier_secret: sender_nullifier_secret,
                inputs,
                outputs: vec![change, recipient_output],
                external_data_hash: random_field(),
                recipient: Some(recipient.clone()),
                proposal: None,
                public_amount: [0u8; 32],
            }
        })
        .collect();

    let folded =
        prove_ring_fold(legs, &prover_url(SERVER_ADDRESS)).expect("fold proof must be produced");

    let co_signer = Keypair::new();
    let ring_config = create_ring_config(test, &co_signer.pubkey());
    let sender_vka = install_vka(
        test,
        sender_owner,
        OWNER_KIND_KEYPAIR,
        sender_viewing_pk,
        folded.legs[0].commitment,
        sender_nullifier_pk,
    );
    let recipient_vka = install_vka(
        test,
        recipient_owner,
        OWNER_KIND_KEYPAIR,
        recipient_viewing_bytes,
        // The recipient's commitment is not read on the recipient side.
        [0u8; 32],
        recipient_nullifier_pk,
    );

    let ix_legs: Vec<FoldTransactLeg> = folded
        .legs
        .iter()
        .map(|leg| FoldTransactLeg {
            // Forwarded to the SPP CPI, which this test never reaches.
            spp_proof: [0u8; 192],
            private_tx_hash: leg.private_tx_hash,
            salt: [0u8; 16],
            output_view_tags: vec![[0u8; 32], [0u8; 32]],
            output_utxo_hashes: vec![[0u8; 32]; 2],
            input_contexts: vec![
                InputContext {
                    nullifier: [0u8; 32],
                    tree_index: 0,
                    utxo_root_index: 0,
                    nullifier_root_index: 0,
                };
                2
            ],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: leg.tx_viewing_pk.expect("transfer leg has a viewing pk"),
                sender_ciphertext: leg
                    .sender_ciphertext
                    .as_slice()
                    .try_into()
                    .expect("40-byte sender ciphertext"),
                recipient_ciphertexts: vec![leg
                    .recipient_ciphertext
                    .as_slice()
                    .try_into()
                    .expect("71-byte recipient ciphertext")],
            },
        })
        .collect();

    FoldSetup {
        ring_config,
        sender_vka,
        recipient_vka,
        co_signer,
        data: FoldTransactIxData {
            ring_fold_proof: folded.proof,
            expiry: i64::MAX,
            legs: ix_legs,
        },
    }
}

fn invalid_fold_data() -> FoldTransactIxData {
    let leg = FoldTransactLeg {
        spp_proof: [0u8; 192],
        private_tx_hash: [0u8; 32],
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32], [0u8; 32]],
        // The leg keeps the proved `(2, 2)` shape, so the flow reaches proof
        // decoding rather than stopping at the shape check.
        output_utxo_hashes: vec![[0u8; 32], [0u8; 32]],
        input_contexts: vec![
            InputContext {
                nullifier: [0u8; 32],
                tree_index: 0,
                utxo_root_index: 0,
                nullifier_root_index: 0,
            };
            2
        ],
        encrypted_utxos: EncryptedUtxos {
            tx_viewing_pk: [0u8; 33],
            sender_ciphertext: [0u8; 40],
            recipient_ciphertexts: vec![[0u8; 71]],
        },
    };
    FoldTransactIxData {
        ring_fold_proof: [0xff; 192],
        expiry: i64::MAX,
        legs: vec![leg.clone(), leg],
    }
}

fn fold_transact_ix(
    test: &SquadsRingTest,
    setup: &FoldSetup,
    data: FoldTransactIxData,
) -> Instruction {
    FoldTransact {
        payer: test.payer.pubkey(),
        co_signer: setup.co_signer.pubkey(),
        ring_config: setup.ring_config,
        sender_viewing_key_account: setup.sender_vka,
        recipient_viewing_key_account: setup.recipient_vka,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data,
    }
    .instruction()
}

#[test]
fn fold_transact_verifies_a_three_utxo_spend_then_attempts_spp_cpi() {
    let mut test = boot_with_prover();

    let setup = build_fold(&mut test);
    assert_eq!(setup.data.legs.len(), 2);
    let ix = fold_transact_ix(&test, &setup, setup.data.clone());

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("the placeholder spp_program must be rejected after fold verification");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn fold_transact_requires_smart_account_vault_before_proof_verification() {
    let mut test = SquadsRingTest::new().expect("boot");

    let relayer = test.payer.pubkey();
    let ring_config = create_ring_config(&mut test, &relayer);
    let vault = Keypair::new();
    let vault_owner = zolana_hasher::primitives::hash_bytes(&vault.pubkey().to_bytes())
        .expect("hash vault identity");
    let sender_vka = install_vka(
        &mut test,
        vault_owner,
        OWNER_KIND_SMART_ACCOUNT,
        [0u8; 33],
        [0u8; 32],
        [0u8; 32],
    );
    let recipient_vka = install_vka(
        &mut test,
        random_field(),
        OWNER_KIND_KEYPAIR,
        [0u8; 33],
        [0u8; 32],
        [0u8; 32],
    );
    let ring_auth = ring_auth_pda(&test.program_id);
    let spp_program = test.program_id;

    let build_ix = |payer| {
        FoldTransact {
            payer,
            co_signer: relayer,
            ring_config,
            sender_viewing_key_account: sender_vka,
            recipient_viewing_key_account: recipient_vka,
            ring_auth,
            spp_program,
            tree_accounts: vec![Keypair::new().pubkey()],
            data: invalid_fold_data(),
        }
        .instruction()
    };

    let err = test
        .send(&[build_ix(relayer)], &[])
        .expect_err("a co-signer cannot substitute for the smart-account vault");
    assert_eq!(custom_code(&err), SquadsRingError::OwnerMismatch as u32);

    let err = test
        .send(&[build_ix(vault.pubkey())], &[&vault])
        .expect_err("an authorized request with an invalid proof must reach proof decoding");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::InvalidProofEncoding as u32,
    );
}

/// A leg the fold did not prove must not settle. Swapping one leg's
/// `private_tx_hash` changes the chain the program recomputes, so the fold fails
/// the pairing check before any CPI is attempted.
#[test]
fn fold_transact_rejects_a_tampered_leg() {
    let mut test = boot_with_prover();

    let setup = build_fold(&mut test);
    let mut data = setup.data.clone();
    data.legs[1].private_tx_hash[0] ^= 1;
    let ix = fold_transact_ix(&test, &setup, data);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("a leg the fold did not prove must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::RingProofVerificationFailed as u32,
    );
}

/// Leg order is part of the statement, because the fold chains the legs left to
/// right. A permuted instruction must not verify.
#[test]
fn fold_transact_rejects_reordered_legs() {
    let mut test = boot_with_prover();

    let setup = build_fold(&mut test);
    let mut data = setup.data.clone();
    data.legs.reverse();
    let ix = fold_transact_ix(&test, &setup, data);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&setup.co_signer])
        .expect_err("reordered legs must be rejected");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::RingProofVerificationFailed as u32,
    );
}
