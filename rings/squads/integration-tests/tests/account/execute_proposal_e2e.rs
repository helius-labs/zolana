//! On-chain tests for `execute_proposal` (tag 13) with a real ring Groth16
//! proof bound to a proposal (`proposal_hash != 0`).
//!
//! `spp_program` is the ring program's own id, a placeholder the SPP-address
//! check rejects with `InvalidSppProgram` before any CPI. That rejection
//! shows ring-proof verification completed and the flow reached settlement.
//! A genuine settlement needs a real SPP program plus an initialized tree
//! and ring-config bootstrap, which the composed localnet suite owns.
//! `execute_proposal_rejects_tampered_ring_proof` fails earlier, in
//! ring-proof verification itself.
//!
//! Both the transfer and withdrawal shapes are covered. The processor
//! consumes the recipient viewing key account slot only for a transfer, so
//! the builder's withdrawal layout omits that slot and appends the SPP
//! settlement account tail.
//!
//! The proposal account is seeded directly. The proposal loader checks only
//! program ownership and discriminator, so no create_proposal owner
//! signature is needed.
//!
//! Tests skip when the prebuilt `.so` is missing or the prover server is
//! unreachable.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, prover_url, SquadsRingTest};
use zolana_client::prover::{spawn_prover, SERVER_ADDRESS};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsRingError,
    instruction::{
        builders::{ExecuteProposal, TransactWithdrawal},
        instruction_data::{EncryptedUtxos, InputContext},
        ExecuteProposalIxData,
    },
    state::{
        proposal::Proposal, ring_config::SquadsRingConfig, viewing_key_account::ViewingKeyAccount,
    },
    types::Address,
    RING_AUTH_PDA_SEED, RING_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::proposal::{
    proposal_asset_commitment, proposal_destination_commitment, proposal_hash, ProposalOperation,
};
use zolana_squads_sdk::prover::{
    derive_change_blinding, RingProofInputs, RingProposal, RingRecipient, RingUtxo,
};

/// A random BN254-range field element (top byte cleared so it is < the field
/// modulus and a valid P-256 scalar).
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

/// The UTXO owner hash the proposal binds for a transfer recipient.
fn owner_hash(owner_key_hash: &[u8; 32], nullifier_pubkey: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[owner_key_hash.as_slice(), nullifier_pubkey.as_slice()]).expect("poseidon")
}

fn fe_u64(x: u64) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[24..32].copy_from_slice(&x.to_be_bytes());
    fe
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

/// The ring proof binds the owner key hash, commitment, and nullifier
/// pubkey stored here.
fn install_vka(
    test: &mut SquadsRingTest,
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

fn input_utxo(amount: u64, owner_key_hash: [u8; 32], nullifier_pubkey: [u8; 32]) -> RingUtxo {
    RingUtxo {
        owner_key_hash,
        nullifier_pubkey,
        asset: proposal_asset_commitment(&Address::default()).expect("SOL asset commitment"),
        amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    }
}

struct Prepared {
    co_signer: Keypair,
    ring_config: Pubkey,
    proposal: Pubkey,
    sender_vka: Pubkey,
    /// Present for a transfer, absent for a withdrawal.
    recipient_vka: Option<Pubkey>,
    /// rent_payer == rent_recipient.
    rent_recipient: Pubkey,
    withdrawal_destination: Option<Pubkey>,
    data: ExecuteProposalIxData,
}

fn prepare_transfer_proposal(test: &mut SquadsRingTest) -> Prepared {
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let recipient_viewing = P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key());
    let recipient_viewing_bytes = *recipient_viewing.as_bytes();
    let recipient_nullifier_pk = random_field();
    let recipient_owner = random_field();

    let recipient_amount = 400u64;
    let asset_field = proposal_asset_commitment(&Address::default()).expect("SOL asset commitment");
    let inputs = vec![
        input_utxo(700, sender_owner, sender_nullifier_pk),
        input_utxo(300, sender_owner, sender_nullifier_pk),
    ];
    let first_input = inputs.first().expect("at least one input");
    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, first_input)
            .expect("derive change blinding");
    let change_output = RingUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: asset_field,
        amount: 600,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };
    let recipient_output = RingUtxo {
        owner_key_hash: recipient_owner,
        nullifier_pubkey: recipient_nullifier_pk,
        asset: asset_field,
        amount: recipient_amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    // For a transfer the proposal commits the recipient output's amount and
    // owner hash.
    let proposal_blinding = random_field();
    let proposal = RingProposal {
        amount: fe_u64(recipient_amount),
        recipient: owner_hash(&recipient_owner, &recipient_nullifier_pk),
        asset: asset_field,
        destination: recipient_owner,
        blinding: proposal_blinding,
        public_amount: [0u8; 32],
    };
    let proposal_private_core = proposal_hash(
        ProposalOperation::Transfer,
        recipient_amount,
        &proposal.recipient,
        proposal_blinding[1..].try_into().expect("31-byte blinding"),
        0,
    )
    .expect("proposal private core");

    let proof_inputs = RingProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output, recipient_output],
        external_data_hash: random_field(),
        recipient: Some(RingRecipient {
            owner_key_hash: recipient_owner,
            nullifier_pubkey: recipient_nullifier_pk,
            viewing_pubkey: recipient_viewing,
        }),
        proposal: Some(proposal),
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
    let ring_config = create_ring_config(test, &co_signer.pubkey());
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
        [0u8; 32],
        recipient_nullifier_pk,
    );

    // `execute_proposal` checks the proposal `owner` against the sender VKA
    // owner. `proposal_hash` binds the proof. `rent_payer` receives the rent
    // when the proposal closes.
    let rent_payer = Keypair::new().pubkey();
    let proposal_addr = Keypair::new().pubkey();
    let record = Proposal::new(
        Address::new_from_array(sender_owner),
        Address::new_from_array(recipient_owner),
        Address::default(),
        proposal_private_core,
        [0u8; 88],
        i64::MAX,
        Address::new_from_array(rent_payer.to_bytes()),
    );
    test.set_program_account(
        &proposal_addr,
        record.serialize().expect("serialize proposal"),
    )
    .expect("seed proposal");
    test.lamports(&proposal_addr).expect("proposal funded");

    // `execute_proposal` selects the ring verifying key from the lengths of these
    // vectors (unlike `transact`, which hardcodes the shape), so a (2, 2) transfer
    // needs two output hashes and two input contexts. Their values are not bound by
    // the ring proof (only forwarded to the stubbed SPP CPI), so dummies suffice.
    let dummy_input = InputContext {
        nullifier: [0u8; 32],
        tree_index: 0,
        utxo_root_index: 0,
        nullifier_root_index: 0,
    };
    let ix_data = ExecuteProposalIxData {
        ring_proof: proof_result.proof,
        spp_proof: [0u8; 192],
        public_amount: None,
        spl_interface_bump: 0,
        private_tx_hash: proof_result.private_tx_hash,
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32]; 2],
        output_utxo_hashes: vec![[0u8; 32]; 2],
        input_contexts: vec![dummy_input; 2],
        encrypted_utxos,
    };

    Prepared {
        co_signer,
        ring_config,
        proposal: proposal_addr,
        sender_vka,
        recipient_vka: Some(recipient_vka),
        rent_recipient: rent_payer,
        withdrawal_destination: None,
        data: ix_data,
    }
}

fn prepare_withdrawal_proposal(test: &mut SquadsRingTest) -> Prepared {
    let sender_viewing = SecretKey::random(&mut OsRng);
    let sender_viewing_pk = *P256Pubkey::from_p256(&sender_viewing.public_key()).as_bytes();
    let sender_nullifier_secret = random_field();
    let sender_nullifier_pk = nullifier_pubkey(&sender_nullifier_secret);
    let sender_owner = random_field();

    let withdrawn = 700u64;
    let asset_field = proposal_asset_commitment(&Address::default()).expect("SOL asset commitment");
    let inputs = vec![input_utxo(1000, sender_owner, sender_nullifier_pk)];
    let first_input = inputs.first().expect("at least one input");
    let change_blinding =
        derive_change_blinding(&sender_viewing, &sender_nullifier_secret, first_input)
            .expect("derive change blinding");
    let change_output = RingUtxo {
        owner_key_hash: sender_owner,
        nullifier_pubkey: sender_nullifier_pk,
        asset: asset_field,
        amount: 300,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
        is_dummy: false,
    };

    // A withdrawal has no recipient UTXO, so the committed amount and
    // recipient are 0 and public_amount is the withdrawn value.
    let public_amount = fe_u64(withdrawn);
    let withdrawal_destination = Keypair::new().pubkey();
    let destination_field = proposal_destination_commitment(
        ProposalOperation::Withdrawal,
        &Address::new_from_array(withdrawal_destination.to_bytes()),
    )
    .expect("withdrawal destination field");
    let proposal_blinding = random_field();
    let proposal = RingProposal {
        amount: [0u8; 32],
        recipient: [0u8; 32],
        asset: asset_field,
        destination: destination_field,
        blinding: proposal_blinding,
        public_amount,
    };
    let proposal_private_core = proposal_hash(
        ProposalOperation::Withdrawal,
        0,
        &[0u8; 32],
        proposal_blinding[1..].try_into().expect("31-byte blinding"),
        withdrawn,
    )
    .expect("proposal private core");

    let proof_inputs = RingProofInputs {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output],
        external_data_hash: random_field(),
        recipient: None,
        proposal: Some(proposal),
        public_amount,
    };
    let proof_result = proof_inputs
        .prove(&prover_url(SERVER_ADDRESS))
        .expect("proof generation must succeed");

    // A withdrawal carries only the sender ciphertext. The ephemeral
    // tx_viewing_pk has no recipient to serve, so it stays zero.
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
    let ring_config = create_ring_config(test, &co_signer.pubkey());
    let sender_vka = install_vka(
        test,
        sender_owner,
        sender_viewing_pk,
        proof_result.commitment,
        sender_nullifier_pk,
    );

    let rent_payer = Keypair::new().pubkey();
    let proposal_addr = Keypair::new().pubkey();
    let record = Proposal::new(
        Address::new_from_array(sender_owner),
        Address::new_from_array(withdrawal_destination.to_bytes()),
        Address::default(),
        proposal_private_core,
        [0u8; 88],
        i64::MAX,
        Address::new_from_array(rent_payer.to_bytes()),
    );
    test.set_program_account(
        &proposal_addr,
        record.serialize().expect("serialize proposal"),
    )
    .expect("seed proposal");
    test.lamports(&proposal_addr).expect("proposal funded");

    let dummy_input = InputContext {
        nullifier: [0u8; 32],
        tree_index: 0,
        utxo_root_index: 0,
        nullifier_root_index: 0,
    };
    let ix_data = ExecuteProposalIxData {
        ring_proof: proof_result.proof,
        spp_proof: [0u8; 192],
        public_amount: Some(withdrawn),
        spl_interface_bump: 0,
        private_tx_hash: proof_result.private_tx_hash,
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32]; 1],
        output_utxo_hashes: vec![[0u8; 32]; 1],
        input_contexts: vec![dummy_input; 1],
        encrypted_utxos,
    };

    Prepared {
        co_signer,
        ring_config,
        proposal: proposal_addr,
        sender_vka,
        recipient_vka: None,
        rent_recipient: rent_payer,
        withdrawal_destination: Some(withdrawal_destination),
        data: ix_data,
    }
}

/// `tree_accounts` needs one arbitrary, never-loaded account so the ring's
/// account parsing succeeds. Withdrawal settlement accounts are junk pubkeys
/// the ring only forwards to the CPI the placeholder `spp_program` rejects.
fn execute_ix(
    test: &SquadsRingTest,
    p: &Prepared,
    ix_data: ExecuteProposalIxData,
    withdrawal: Option<TransactWithdrawal>,
) -> solana_instruction::Instruction {
    ExecuteProposal {
        payer: test.payer.pubkey(),
        co_signer: p.co_signer.pubkey(),
        ring_config: p.ring_config,
        proposal: p.proposal,
        sender_viewing_key_account: p.sender_vka,
        recipient_viewing_key_account: p.recipient_vka,
        withdrawal,
        rent_recipient: p.rent_recipient,
        ring_auth: ring_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: ix_data,
    }
    .instruction()
}

#[test]
fn execute_proposal_transfer_verifies_real_ring_proof_then_attempts_spp_cpi() {
    let mut test = boot_with_prover();
    let prepared = prepare_transfer_proposal(&mut test);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(&test, &prepared, prepared.data.clone(), None);

    let err = test
        .send(&[budget, ix], &[&prepared.co_signer])
        .expect_err("the placeholder spp_program must be rejected after ring-proof verification");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn execute_proposal_withdrawal_verifies_real_ring_proof_then_attempts_spp_cpi() {
    let mut test = boot_with_prover();
    let prepared = prepare_withdrawal_proposal(&mut test);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let withdrawal = TransactWithdrawal::Sol {
        sol_interface: Keypair::new().pubkey(),
        recipient: prepared
            .withdrawal_destination
            .expect("prepared withdrawal destination"),
    };
    let ix = execute_ix(&test, &prepared, prepared.data.clone(), Some(withdrawal));
    let err = test
        .send(&[budget, ix], &[&prepared.co_signer])
        .expect_err("the placeholder spp_program must be rejected after ring-proof verification");
    assert_eq!(custom_code(&err), SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn execute_proposal_rejects_tampered_ring_proof() {
    let mut test = boot_with_prover();

    let prepared = prepare_transfer_proposal(&mut test);

    // Flip a byte of a bound public input. The program recomputes a different
    // public-input hash, so the proof fails the pairing check.
    let mut ix_data = prepared.data.clone();
    ix_data.private_tx_hash[0] ^= 1;

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(&test, &prepared, ix_data, None);
    let err = test
        .send(&[budget, ix], &[&prepared.co_signer])
        .expect_err("tampered ring proof must be rejected on-chain");
    assert_eq!(
        custom_code(&err),
        SquadsRingError::RingProofVerificationFailed as u32,
    );
}
