//! End-to-end `transact` tests with real zone Groth16 proofs verified
//! on-chain in LiteSVM.
//!
//! `spp_program` is the zone program's own id, a deliberate placeholder.
//! `spp_transact` validates the exact SPP program id before any CPI, so the
//! placeholder is rejected with `InvalidSppProgram`. Reaching that error
//! proves zone-proof verification completed and the flow attempted
//! settlement without a real SPP. A tampered proof fails earlier, in
//! zone-proof verification, and never reaches the CPI attempt.
//!
//! Tests skip when the prebuilt program `.so` is missing or the prover
//! server is unreachable. The first proof request lazy-loads the proving
//! key.

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
    constants::{
        ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT,
        VIEWING_KEY_STATE_ACTIVE,
    },
    error::SquadsZoneError,
    instruction::{
        builders::{Transact, TransactWithdrawal},
        instruction_data::{EncryptedUtxos, InputContext},
        TransactIxData,
    },
    state::{viewing_key_account::ViewingKeyAccount, zone_config::ZoneConfig},
    types::Address,
    RING_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::zone::{
    derive_change_blinding, ZoneProofInputs, ZoneRecipient, ZoneUtxo,
};

/// Top byte cleared so the value is below the BN254 modulus and is a valid
/// P-256 scalar.
fn random_field() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

/// Must match the Go circuit's nullifier-pubkey derivation.
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

fn ring_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], program_id).0
}

/// A prover the tests cannot reach is a failure. A run that quietly skips
/// every proof-backed case reports green while proving nothing.
fn boot_with_prover() -> SquadsZoneTest {
    spawn_prover().expect("the prover server must be reachable, see ZOLANA_PROVER_URL");
    SquadsZoneTest::new().expect("boot")
}

/// The program enforces exactly one auditor key.
fn create_zone_config(test: &mut SquadsZoneTest, co_signer: &Pubkey) -> Pubkey {
    let zone_config = zone_config_pda(&test.program_id);
    let auditor = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
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

/// The fixture carries the public identity the zone proof binds, the
/// owner-key-hash, the shared-key commitment, and the nullifier pubkey.
/// Fields `transact` never reads stay zero.
fn install_vka(
    test: &mut SquadsZoneTest,
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

/// Only the first input's fields feed the change-blinding KDF chain. Every
/// input's hash binds into `private_tx_hash`.
fn input_utxo(amount: u64, owner_key_hash: [u8; 32], nullifier_pubkey: [u8; 32]) -> ZoneUtxo {
    ZoneUtxo {
        owner_key_hash,
        nullifier_pubkey,
        asset: [0u8; 32],
        amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    }
}

/// Who owns the spent UTXOs. A smart-account sender carries no owner signature
/// in the SPP proof, so the vault itself must sign `transact`. The kind also
/// selects the SPP settlement rail.
enum Sender {
    Keypair,
    SmartAccount(Box<Keypair>),
}

impl Sender {
    fn smart_account(vault: Keypair) -> Self {
        Sender::SmartAccount(Box::new(vault))
    }

    fn owner_kind(&self) -> u8 {
        match self {
            Sender::Keypair => OWNER_KIND_KEYPAIR,
            Sender::SmartAccount(_) => OWNER_KIND_SMART_ACCOUNT,
        }
    }

    /// The identity the viewing key account stores and the proof binds. A vault
    /// must use the canonical `hash_bytes(address)` encoding the program
    /// recomputes from the signing payer.
    fn owner_key_hash(&self) -> [u8; 32] {
        match self {
            Sender::Keypair => random_field(),
            Sender::SmartAccount(vault) => {
                zolana_hasher::primitives::hash_bytes(&vault.pubkey().to_bytes())
                    .expect("hash vault identity")
            }
        }
    }
}

/// A smart-account sender must present the vault as `payer`.
fn transact_payer(test: &SquadsZoneTest, sender: &Sender) -> Pubkey {
    match sender {
        Sender::Keypair => test.payer.pubkey(),
        Sender::SmartAccount(vault) => vault.pubkey(),
    }
}

fn transact_signers<'a>(sender: &'a Sender, co_signer: &'a Keypair) -> Vec<&'a Keypair> {
    match sender {
        Sender::Keypair => vec![co_signer],
        Sender::SmartAccount(vault) => vec![co_signer, vault],
    }
}

/// Fixtures and instruction data for a `(2, 2)` transfer with a real zone proof.
struct TransferSetup {
    zone_config: Pubkey,
    sender_vka: Pubkey,
    recipient_vka: Pubkey,
    co_signer: Keypair,
    sender: Sender,
    data: TransactIxData,
}

fn build_transfer(test: &mut SquadsZoneTest) -> TransferSetup {
    build_transfer_inputs(test, Sender::Keypair, &[700, 300])
}

fn build_smart_account_transfer(test: &mut SquadsZoneTest) -> TransferSetup {
    build_transfer_inputs(test, Sender::smart_account(Keypair::new()), &[700, 300])
}

/// The shape the client builds from a single spendable UTXO: one real input
/// padded with a dummy so the shape stays `(2, 2)`.
fn build_transfer_single_input(test: &mut SquadsZoneTest) -> TransferSetup {
    build_transfer_inputs(test, Sender::Keypair, &[700])
}

/// `input_amounts` holds the real inputs. One real input is padded with a dummy.
fn build_transfer_inputs(
    test: &mut SquadsZoneTest,
    sender: Sender,
    input_amounts: &[u64],
) -> TransferSetup {
    // The owner-key-hash is stored verbatim as the viewing key account `owner`
    // the proof reads back.
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = sender.owner_key_hash();

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_viewing_bytes = *recipient_viewing.as_bytes();
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();

    let mut inputs: Vec<ZoneUtxo> = input_amounts
        .iter()
        .map(|amount| input_utxo(*amount, sender_owner, sender_nullifier_pk))
        .collect();
    // The prover rejects a dummy first input, so the real input stays at index 0.
    if inputs.len() == 1 {
        let mut dummy = input_utxo(0, sender_owner, sender_nullifier_pk);
        dummy.is_dummy = true;
        inputs.push(dummy);
    }
    let transferred = 400u64;
    let change_amount: u64 = input_amounts.iter().sum::<u64>() - transferred;
    let first_input = inputs.first().expect("at least one input");
    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, first_input)
            .expect("derive change blinding");
    let change_output = ZoneUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: [0u8; 32],
        amount: change_amount,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };
    let recipient_output = ZoneUtxo {
        owner_key_hash: recipient_owner,
        nullifier_pubkey: recipient_nullifier_pk,
        asset: [0u8; 32],
        amount: transferred,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    let proof_inputs = ZoneProofInputs {
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
    let proof_result = proof_inputs
        .prove(&prover_url(SERVER_ADDRESS))
        .expect("proof generation must succeed");

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

    let co_signer = Keypair::new();
    test.airdrop(&co_signer.pubkey(), 1_000_000_000)
        .expect("fund co_signer");
    let zone_config = create_zone_config(test, &co_signer.pubkey());
    let sender_vka = install_vka(
        test,
        sender_owner,
        sender.owner_kind(),
        sender_viewing_pk,
        proof_result.commitment,
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

    let ix_data = TransactIxData {
        zone_proof: proof_result.proof,
        // Never read on this path. The placeholder `spp_program` is rejected before
        // the SPP CPI (see the module doc).
        spp_proof: [0u8; 192],
        public_amount: None,
        spl_interface_bump: 0,
        private_tx_hash: proof_result.private_tx_hash,
        expiry: i64::MAX,
        // Not read on the zone-verification path (forwarded to the SPP CPI).
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
        encrypted_utxos,
    };

    TransferSetup {
        zone_config,
        sender_vka,
        recipient_vka,
        co_signer,
        sender,
        data: ix_data,
    }
}

/// `tree_accounts` needs one arbitrary never-loaded account so the zone's
/// account parsing succeeds and the flow reaches the SPP-address check.
fn transact_ix(
    test: &SquadsZoneTest,
    setup: &TransferSetup,
    ix_data: TransactIxData,
) -> Instruction {
    Transact {
        payer: transact_payer(test, &setup.sender),
        co_signer: setup.co_signer.pubkey(),
        zone_config: setup.zone_config,
        sender_viewing_key_account: setup.sender_vka,
        recipient_viewing_key_account: Some(setup.recipient_vka),
        withdrawal: None,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: ix_data,
    }
    .instruction()
}

#[test]
fn transact_transfer_verifies_real_zone_proof_then_attempts_spp_cpi() {
    let mut test = boot_with_prover();

    let setup = build_transfer(&mut test);
    let ix = transact_ix(&test, &setup, setup.data.clone());

    // The pairing-heavy on-chain verify exceeds the default CU limit.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(
            &[budget, ix],
            &transact_signers(&setup.sender, &setup.co_signer),
        )
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

/// The vault signature authorizes the spend and the program routes the
/// settlement to SPP's `ring_authority_transact` rail.
#[test]
fn smart_account_transact_transfer_verifies_real_zone_proof_then_attempts_spp_cpi() {
    let mut test = boot_with_prover();

    let setup = build_smart_account_transfer(&mut test);
    let ix = transact_ix(&test, &setup, setup.data.clone());

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(
            &[budget, ix],
            &transact_signers(&setup.sender, &setup.co_signer),
        )
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

/// A sender with one spendable UTXO pads the `(2, 2)` shape with a dummy input.
#[test]
fn transact_transfer_with_one_real_input_and_a_dummy_verifies() {
    let mut test = boot_with_prover();

    let setup = build_transfer_single_input(&mut test);
    let ix = transact_ix(&test, &setup, setup.data.clone());

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(
            &[budget, ix],
            &transact_signers(&setup.sender, &setup.co_signer),
        )
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn co_signer_only_smart_account_transact_is_rejected() {
    let mut test = SquadsZoneTest::new().expect("boot");

    // The relayer is both payer and configured co-signer while the vault never
    // signs or appears in the instruction. Rejection happens before proof
    // verification, so this regression needs no prover and no valid proof.
    let relayer = test.payer.pubkey();
    let zone_config = create_zone_config(&mut test, &relayer);
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

    let ix = Transact {
        payer: relayer,
        co_signer: relayer,
        zone_config,
        sender_viewing_key_account: sender_vka,
        recipient_viewing_key_account: None,
        withdrawal: None,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: TransactIxData {
            zone_proof: [0u8; 192],
            spp_proof: [0u8; 192],
            public_amount: Some(1),
            spl_interface_bump: 0,
            private_tx_hash: [0u8; 32],
            expiry: i64::MAX,
            salt: [0u8; 16],
            output_view_tags: vec![[0u8; 32]],
            output_utxo_hashes: vec![],
            input_contexts: vec![],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [0u8; 33],
                sender_ciphertext: [0u8; 40],
                recipient_ciphertexts: vec![],
            },
        },
    }
    .instruction();

    let err = test
        .send(&[ix], &[])
        .expect_err("the co-signer cannot substitute for the smart-account vault");
    assert_eq!(custom_code(&err), SquadsZoneError::OwnerMismatch as u32);
}

/// Fixtures and instruction data for a `(1, 1)` withdrawal with a real zone proof.
struct WithdrawalSetup {
    zone_config: Pubkey,
    sender_vka: Pubkey,
    co_signer: Keypair,
    sender: Sender,
    data: TransactIxData,
}

fn build_withdrawal(test: &mut SquadsZoneTest) -> WithdrawalSetup {
    build_withdrawal_for(test, Sender::Keypair)
}

fn build_smart_account_withdrawal(test: &mut SquadsZoneTest) -> WithdrawalSetup {
    build_withdrawal_for(test, Sender::smart_account(Keypair::new()))
}

/// Build a `(1, 1)` withdrawal proof for a sync `transact`. Sync `transact`
/// binds no proposal, so the on-chain recomputation uses `proposal_hash = 0`
/// and the proof inputs set `proposal: None`, with the withdrawn value
/// carried in the independent `public_amount` chain element.
fn build_withdrawal_for(test: &mut SquadsZoneTest, sender: Sender) -> WithdrawalSetup {
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = sender.owner_key_hash();

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
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    let public_amount = fe_u64(withdrawn);
    let proof_inputs = ZoneProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output],
        external_data_hash: random_field(),
        recipient: None,
        proposal: None,
        public_amount,
    };
    let proof_result = proof_inputs
        .prove(&prover_url(SERVER_ADDRESS))
        .expect("proof generation must succeed");

    // A withdrawal carries only the sender ciphertext. With no recipient the
    // ephemeral tx_viewing_pk is unused and stays zero.
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
        OWNER_KIND_KEYPAIR,
        sender_viewing_pk,
        proof_result.commitment,
        sender_nullifier_pk,
    );

    let ix_data = TransactIxData {
        zone_proof: proof_result.proof,
        spp_proof: [0u8; 192],
        // `Some` selects the (1, 1) withdrawal shape on-chain.
        public_amount: Some(withdrawn),
        spl_interface_bump: 0,
        private_tx_hash: proof_result.private_tx_hash,
        expiry: i64::MAX,
        salt: [0u8; 16],
        // The withdrawal SPP-data builder requires exactly one view tag (sender
        // only). The value is forwarded to the CPI, never bound by the proof.
        output_view_tags: vec![[0u8; 32]],
        output_utxo_hashes: vec![[0u8; 32]],
        input_contexts: vec![InputContext {
            nullifier: [0u8; 32],
            tree_index: 0,
            utxo_root_index: 0,
            nullifier_root_index: 0,
        }],
        encrypted_utxos,
    };

    WithdrawalSetup {
        zone_config,
        sender_vka,
        co_signer,
        sender,
        data: ix_data,
    }
}

/// The zone never loads the settlement tail or the tree account. It only
/// forwards them to the SPP CPI, so junk pubkeys suffice.
fn transact_withdrawal_ix(
    test: &SquadsZoneTest,
    setup: &WithdrawalSetup,
    ix_data: TransactIxData,
    withdrawal: TransactWithdrawal,
) -> Instruction {
    Transact {
        payer: transact_payer(test, &setup.sender),
        co_signer: setup.co_signer.pubkey(),
        zone_config: setup.zone_config,
        sender_viewing_key_account: setup.sender_vka,
        recipient_viewing_key_account: None,
        withdrawal: Some(withdrawal),
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: ix_data,
    }
    .instruction()
}

#[test]
fn transact_withdrawal_reaches_spp_cpi() {
    let mut test = boot_with_prover();

    let setup = build_withdrawal(&mut test);
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

/// The vault signature authorizes the spend and the program routes the
/// settlement to SPP's `ring_authority_transact` rail.
#[test]
fn smart_account_transact_withdrawal_reaches_spp_cpi() {
    let mut test = boot_with_prover();

    let setup = build_smart_account_withdrawal(&mut test);
    let withdrawal = TransactWithdrawal::Sol {
        sol_interface: Keypair::new().pubkey(),
        recipient: Keypair::new().pubkey(),
    };
    let ix = transact_withdrawal_ix(&test, &setup, setup.data.clone(), withdrawal);

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(
            &[budget, ix],
            &transact_signers(&setup.sender, &setup.co_signer),
        )
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn transact_withdrawal_spl_reaches_spp_cpi() {
    let mut test = boot_with_prover();

    let setup = build_withdrawal(&mut test);
    // The zone proof does not bind the settlement rail, so the SOL-rail proof
    // is reused. The program selects the SPL rail from the settlement account
    // count.
    let withdrawal = TransactWithdrawal::Spl {
        cpi_authority: Keypair::new().pubkey(),
        mint: Keypair::new().pubkey(),
        spl_interface: Keypair::new().pubkey(),
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
    let mut test = boot_with_prover();

    let setup = build_withdrawal(&mut test);

    // The program binds `private_tx_hash` into the recomputed public-input
    // hash, so a flipped byte fails the pairing check before the SPP CPI
    // attempt.
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
    let mut test = boot_with_prover();

    let setup = build_transfer(&mut test);

    // The program binds `private_tx_hash` into the recomputed public-input
    // hash, so a flipped byte fails the pairing check.
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
