//! End-to-end on-chain test for `execute_proposal` (tag 13): build a REAL zone
//! Groth16 proof bound to a proposal (`proposal_hash != 0`), seed the `Proposal`,
//! viewing key accounts, and zone config, send `execute_proposal`, and assert the
//! program VERIFIED THE ZONE PROOF ON-CHAIN, then proceeded to settlement.
//!
//! The SPP CPI is real, but these tests pass the zone program's own id as
//! `spp_program` -- a deliberate placeholder, not the real SPP -- since a genuine
//! settlement needs a real SPP program plus an initialized tree and zone-config
//! bootstrap (this crate's composed localnet suite owns that). The SPP CPI
//! validates the exact SPP program id BEFORE attempting any CPI, so this
//! placeholder is rejected with `InvalidSppProgram` -- proving the zone-proof
//! verification path completed and the flow proceeded to attempt settlement,
//! without needing a real SPP. `execute_proposal_rejects_tampered_zone_proof` is
//! the discriminating counterpart: a tampered proof fails earlier, in zone-proof
//! verification itself. The proposal account is seeded directly (the proposal
//! loader checks only program ownership + discriminator), so no create_proposal
//! owner signature is needed -- the focus is tag 13.
//!
//! Both the TRANSFER and WITHDRAWAL shapes are covered. The processor parses
//! accounts with `AccountIterator`, consuming the recipient viewing key account
//! slot only for a transfer (mirroring SPP), so the builder's withdrawal layout
//! (which omits that slot and appends the SPP settlement account tail) lines up.
//!
//! GATING: requires the prebuilt program `.so` (skips if missing) AND a reachable
//! prover server (skips if `spawn_prover` fails). The first proof request
//! lazy-loads a large proving key and can take minutes.
//!
//! Build the program first:
//!   cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
//! Run with:
//!   cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests --test execute_proposal_e2e -- --nocapture

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_compute_budget_interface::ComputeBudgetInstruction;
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
        builders::{CreateZoneConfig, ExecuteProposal, TransactWithdrawal},
        instruction_data::{EncryptedUtxos, InputContext},
        CreateZoneConfigIxData, ExecuteProposalIxData,
    },
    state::{proposal::Proposal, viewing_key_account::ViewingKeyAccount},
    types::Address,
    ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::{
    derive_change_blinding, ZoneProposal, ZoneRecipient, ZoneUtxo, ZoneWitness,
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

/// `nullifier_pubkey = Poseidon([nullifier_secret])` (view_key.go:54).
fn nullifier_pubkey(secret: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[secret.as_slice()]).expect("poseidon")
}

/// `owner_hash = Poseidon(owner_key_hash, nullifier_pubkey)` (the UTXO owner hash
/// the proposal binds for a transfer recipient).
fn owner_hash(owner_key_hash: &[u8; 32], nullifier_pubkey: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[owner_key_hash.as_slice(), nullifier_pubkey.as_slice()]).expect("poseidon")
}

/// A `u64` as a 32-byte big-endian field element.
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
        eprintln!("skipping execute_proposal_e2e: prover server not reachable");
        return None;
    }
    Some(test)
}

/// Create the zone config with the given co-signer and a dummy single auditor key.
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

/// Install a viewing key account fixture carrying the public identity the zone
/// proof binds (owner-key-hash field element, commitment, nullifier pubkey).
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

/// Prepared `execute_proposal` inputs for a transfer-proposal settlement.
struct Prepared {
    co_signer: Keypair,
    zone_config: Pubkey,
    proposal: Pubkey,
    sender_vka: Pubkey,
    /// Present for a transfer, absent for a withdrawal.
    recipient_vka: Option<Pubkey>,
    /// rent_payer == rent_recipient.
    rent_recipient: Pubkey,
    data: ExecuteProposalIxData,
}

/// Build a real transfer zone proof bound to a proposal, install all fixtures
/// (zone config, sender/recipient VKAs, the seeded `Proposal`), and assemble the
/// `execute_proposal` instruction data.
fn prepare_transfer_proposal(test: &mut SquadsZoneTest) -> Prepared {
    // Sender identity (owner-key-hash is a field element, stored as the VKA owner).
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
    let recipient_amount = 400u64;
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
        amount: recipient_amount,
        blinding: random_field(),
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: [0u8; 32],
        is_dummy: false,
    };

    // Proposal binding (proposal.go:36-39): for a transfer the committed amount and
    // recipient must equal the recipient output's amount and owner hash.
    let proposal = ZoneProposal {
        amount: fe_u64(recipient_amount),
        recipient: owner_hash(&recipient_owner, &recipient_nullifier_pk),
        blinding: random_field(),
        public_amount: [0u8; 32],
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
        proposal: Some(proposal),
        public_amount: [0u8; 32],
    };
    let proof_result = witness
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

    // Fixtures.
    let co_signer = Keypair::new();
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
        [0u8; 32],
        recipient_nullifier_pk,
    );

    // Seed the Proposal account: `owner` is the sender VKA's owner field (what
    // execute_proposal checks), `proposal_hash` is the bound proof hash, and
    // `rent_payer` receives the rent when the proposal closes.
    let rent_payer = Keypair::new().pubkey();
    let proposal_addr = Keypair::new().pubkey();
    let record = Proposal::new(
        Address::new_from_array(sender_owner),
        Address::default(),
        Address::default(),
        proof_result.proposal_hash,
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

    // `execute_proposal` selects the zone verifying key from the lengths of these
    // vectors (unlike `transact`, which hardcodes the shape), so a (2, 2) transfer
    // needs two output hashes and two input contexts. Their values are not bound by
    // the zone proof (only forwarded to the stubbed SPP CPI), so dummies suffice.
    let dummy_input = InputContext {
        nullifier: [0u8; 32],
        tree_index: 0,
        utxo_root_index: 0,
        nullifier_root_index: 0,
    };
    let ix_data = ExecuteProposalIxData {
        zone_proof: proof_result.proof,
        spp_proof: [0u8; 192],
        public_amount: None,
        private_tx_hash: proof_result.private_tx_hash,
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32]; 2],
        output_utxo_hashes: vec![[0u8; 32]; 2],
        input_contexts: vec![dummy_input; 2],
        encrypted_utxos,
    };

    Prepared {
        co_signer,
        zone_config,
        proposal: proposal_addr,
        sender_vka,
        recipient_vka: Some(recipient_vka),
        rent_recipient: rent_payer,
        data: ix_data,
    }
}

/// Build a real withdrawal zone proof bound to a proposal (no recipient), seed the
/// fixtures + `Proposal`, and assemble the `execute_proposal` instruction data.
/// Exercises the withdrawal account layout (recipient slot omitted).
fn prepare_withdrawal_proposal(test: &mut SquadsZoneTest) -> Prepared {
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

    // Withdrawal proposal binding (proposal.go:41-43): no recipient UTXO, so the
    // committed amount and recipient are 0; public_amount is the withdrawn value.
    let public_amount = fe_u64(withdrawn);
    let proposal = ZoneProposal {
        amount: [0u8; 32],
        recipient: [0u8; 32],
        blinding: random_field(),
        public_amount,
    };

    let witness = ZoneWitness {
        viewing_secret_key: sender_viewing,
        nullifier_secret: sender_nullifier_secret,
        inputs,
        outputs: vec![change_output],
        external_data_hash: random_field(),
        recipient: None,
        proposal: Some(proposal),
        public_amount,
    };
    let proof_result = witness
        .prove(&prover_url(SERVER_ADDRESS))
        .expect("proof generation must succeed");

    // Withdrawal carries only the sender ciphertext; the ephemeral tx_viewing_pk is
    // unused (no recipient) so it is left zero.
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
    let zone_config = create_zone_config(test, &co_signer.pubkey());
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
        Address::default(),
        Address::default(),
        proof_result.proposal_hash,
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

    // (1, 1) withdrawal shape: one output hash, one input context.
    let dummy_input = InputContext {
        nullifier: [0u8; 32],
        tree_index: 0,
        utxo_root_index: 0,
        nullifier_root_index: 0,
    };
    let ix_data = ExecuteProposalIxData {
        zone_proof: proof_result.proof,
        spp_proof: [0u8; 192],
        public_amount: Some(withdrawn),
        private_tx_hash: proof_result.private_tx_hash,
        salt: [0u8; 16],
        output_view_tags: vec![[0u8; 32]; 1],
        output_utxo_hashes: vec![[0u8; 32]; 1],
        input_contexts: vec![dummy_input; 1],
        encrypted_utxos,
    };

    Prepared {
        co_signer,
        zone_config,
        proposal: proposal_addr,
        sender_vka,
        recipient_vka: None,
        rent_recipient: rent_payer,
        data: ix_data,
    }
}

/// `spp_program` is the zone program's own id -- a deliberate placeholder the
/// real SPP-address check in `spp_transact` rejects (mirrors `transact_e2e`);
/// `tree_accounts` needs one (arbitrary, never-loaded) account so the zone's
/// own account parsing succeeds for the transfer leg. For a withdrawal, pass the
/// settlement account tail via `withdrawal` (junk pubkeys -- the zone never loads
/// them, only forwards them to the SPP CPI the placeholder `spp_program` rejects).
fn execute_ix(
    test: &SquadsZoneTest,
    p: &Prepared,
    ix_data: ExecuteProposalIxData,
    withdrawal: Option<TransactWithdrawal>,
) -> solana_instruction::Instruction {
    ExecuteProposal {
        payer: test.payer.pubkey(),
        co_signer: p.co_signer.pubkey(),
        zone_config: p.zone_config,
        proposal: p.proposal,
        sender_viewing_key_account: p.sender_vka,
        recipient_viewing_key_account: p.recipient_vka,
        withdrawal,
        rent_recipient: p.rent_recipient,
        zone_auth: zone_auth_pda(&test.program_id),
        spp_program: test.program_id,
        tree_accounts: vec![Keypair::new().pubkey()],
        data: ix_data,
    }
    .instruction()
}

#[test]
fn execute_proposal_transfer_verifies_real_zone_proof_then_attempts_spp_cpi() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };
    let prepared = prepare_transfer_proposal(&mut test);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(&test, &prepared, prepared.data.clone(), None);

    // The zone proof verifies, so the flow proceeds to attempt the SPP CPI,
    // where the placeholder `spp_program` is rejected. The transaction fails
    // atomically, so the proposal is never closed (asserting that would be
    // asserting the failed transaction had no effect, which is redundant with
    // LiteSVM's own atomicity guarantee).
    let err = test
        .send(&[budget, ix], &[&prepared.co_signer])
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn execute_proposal_withdrawal_verifies_real_zone_proof_then_attempts_spp_cpi() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };
    // Withdrawal layout: the builder omits the recipient slot (the processor
    // consumes it only for a transfer) and appends the SPP settlement account tail
    // via `withdrawal`. The zone verifies the (1, 1) withdrawal proof bound to the
    // proposal on-chain, then forwards the settlement to the SPP CPI, where the
    // placeholder `spp_program` is rejected -- proving the withdrawal zone-proof
    // path completed and reached settlement.
    let prepared = prepare_withdrawal_proposal(&mut test);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    // SOL rail: `[sol_interface, recipient, system_program]` (junk pubkeys -- never
    // loaded, only forwarded to the CPI the placeholder program rejects).
    let withdrawal = TransactWithdrawal::Sol {
        sol_interface: Keypair::new().pubkey(),
        recipient: Keypair::new().pubkey(),
    };
    let ix = execute_ix(&test, &prepared, prepared.data.clone(), Some(withdrawal));
    let err = test
        .send(&[budget, ix], &[&prepared.co_signer])
        .expect_err("the placeholder spp_program must be rejected after zone-proof verification");
    assert_eq!(custom_code(&err), SquadsZoneError::InvalidSppProgram as u32);
}

#[test]
fn execute_proposal_rejects_tampered_zone_proof() {
    let Some(mut test) = boot_with_prover() else {
        return;
    };

    let prepared = prepare_transfer_proposal(&mut test);

    // Flip a byte of a public input the program binds the proof to: the program
    // recomputes a different public-input hash, so the proof fails the pairing check.
    let mut ix_data = prepared.data.clone();
    ix_data.private_tx_hash[0] ^= 1;

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let ix = execute_ix(&test, &prepared, ix_data, None);
    let err = test
        .send(&[budget, ix], &[&prepared.co_signer])
        .expect_err("tampered zone proof must be rejected on-chain");
    assert_eq!(
        custom_code(&err),
        SquadsZoneError::ZoneProofVerificationFailed as u32,
    );
}
