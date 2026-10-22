//! End-to-end on-chain test for `execute_proposal` (tag 13): build a REAL ring
//! Groth16 proof bound to a proposal (`proposal_hash != 0`), seed the `Proposal`,
//! viewing key accounts, and ring config, send `execute_proposal`, and assert the
//! program VERIFIED THE RING PROOF ON-CHAIN, then proceeded to settlement.
//!
//! The forwarded SPP account list is the real `ring_transact` layout built by
//! `zolana_program::instruction::RingTransact`, except that the SPP program
//! account is replaced by the ring program's own id -- a deliberate placeholder,
//! since a genuine settlement needs a real SPP program plus an initialized tree
//! and ring-config bootstrap. `forward_to_spp` requires the SPP program account
//! in the forwarded list BEFORE attempting the CPI, so the placeholder is
//! rejected with `InvalidSppProgram` -- proving the ring-proof verification path
//! completed and the flow proceeded to settlement.
//! `execute_proposal_rejects_tampered_ring_proof` is the discriminating
//! counterpart: a tampered proof fails earlier, in ring-proof verification. The
//! proposal account is seeded directly (the proposal loader checks only program
//! ownership + discriminator), so no create_proposal owner signature is needed.
//!
//! Both the TRANSFER and WITHDRAWAL shapes are covered: the processor consumes
//! the recipient viewing key account slot only for a transfer.
//!
//! GATING: requires the prebuilt program `.so` (skips if missing) . Proofs come from
//! `squads-prover`; the first proof of a circuit loads its proving key.
//!
//! Build the program first:
//!   cd rings/squads/program && cargo build-sbf --features bpf-entrypoint
//! Run with:
//!   cargo test --manifest-path rings/squads/Cargo.toml -p squads-ring-tests --test execute_proposal_e2e -- --nocapture

use std::sync::OnceLock;

use rand::{rngs::OsRng, RngCore};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, SquadsRingTest};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::verifying_keys::{AnonymousRingEddsaProofData, Bsb22Commitment};
use zolana_interface::{
    instruction::{
        CircuitId, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData as SppTransactIxData,
        TransactOutput, TransactProof, TreeContext,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::X25519Keypair;
use zolana_program::instruction::{
    RingTransact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_X25519_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsRingError,
    instruction::{
        builders::{CreateRingConfig, ExecuteProposal},
        CreateRingConfigIxData, ExecuteProposalIxData,
    },
    state::{proposal::Proposal, viewing_key_account::ViewingKeyAccount},
    types::Address,
    RING_CONFIG_PDA_SEED,
};
use zolana_squads_sdk::prover::{
    derive_spend_secrets,
    ring::{RingProofResult, UTXO_DOMAIN},
    RingProposal, RingRecipient, RingUtxo, RingWitness,
};

/// The proposal expiry; the forwarded SPP payload must carry the same value.
const PROPOSAL_EXPIRY: i64 = i64::MAX;

const WITHDRAWN: u64 = 700;

/// A random field element below both the BN254 modulus and the field range.
fn random_field() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b[0] = 0;
    b
}

/// `nullifier_pubkey = Poseidon([nullifier_secret])` (view_key.go:54).
fn nullifier_pubkey(secret: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[secret.as_slice()]).expect("poseidon")
}

/// A `u64` as a 32-byte big-endian field element.
fn fe_u64(x: u64) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe.get_mut(24..)
        .expect("low 8 bytes")
        .copy_from_slice(&x.to_be_bytes());
    fe
}

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

/// Boot LiteSVM with the program; returns `None` (a clean skip) if the `.so` is
/// missing.
fn boot_program() -> Option<SquadsRingTest> {
    let test = SquadsRingTest::new().expect("boot")?;
    Some(test)
}

/// Create the ring config with the given co-signer and a dummy single auditor key.
fn create_ring_config(test: &mut SquadsRingTest, co_signer: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let ring_config = ring_config_pda(&test.program_id);
    let auditor = X25519Keypair::new().pubkey();
    let ix = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: Pubkey::new_from_array([7u8; 32]),
            co_signer: *co_signer,
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![*auditor.as_bytes()],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_ring_config");
    ring_config
}

/// Install a viewing key account fixture carrying the public identity the ring
/// proof binds (owner-key-hash field element, commitment, nullifier pubkey).
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
        encryption_scheme: ENCRYPTION_SCHEME_X25519_AES,
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

fn ring_utxo(
    owner_key_hash: [u8; 32],
    nullifier_pubkey: [u8; 32],
    amount: u64,
    blinding: [u8; 32],
) -> RingUtxo {
    RingUtxo {
        domain: UTXO_DOMAIN,
        tree_id: 1,
        owner_key_hash,
        nullifier_pubkey,
        asset: [0u8; 32],
        amount,
        blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: [0u8; 32],
    }
}

/// The sender's secrets and public identity.
struct Sender {
    viewing: X25519Keypair,
    viewing_pk: [u8; 33],
    nullifier_secret: [u8; 32],
    nullifier_pubkey: [u8; 32],
    owner: [u8; 32],
}

fn sender() -> Sender {
    let viewing = X25519Keypair::new();
    let viewing_pk = *viewing.pubkey().as_bytes();
    let nullifier_secret = random_field();
    Sender {
        viewing,
        viewing_pk,
        nullifier_pubkey: nullifier_pubkey(&nullifier_secret),
        nullifier_secret,
        owner: random_field(),
    }
}

/// Real inputs owned by the sender plus the change (and, for a transfer, the
/// recipient) outputs carrying the blindings the circuit derives from the first
/// nullifier, bound to `proposal`.
fn spend_witness(
    sender: &Sender,
    input_amounts: &[u64],
    change_amount: u64,
    recipient: Option<(&RingRecipient, u64)>,
    public_amount: u64,
    proposal: RingProposal,
) -> RingWitness {
    let inputs: Vec<RingUtxo> = input_amounts
        .iter()
        .map(|amount| {
            ring_utxo(
                sender.owner,
                sender.nullifier_pubkey,
                *amount,
                random_field(),
            )
        })
        .collect();
    let first = inputs.first().expect("at least one input");
    let first_nullifier = Poseidon::hashv(&[
        first.hash().expect("input hash").as_slice(),
        first.blinding.as_slice(),
        sender.nullifier_secret.as_slice(),
    ])
    .expect("first nullifier");
    let secrets = derive_spend_secrets(&sender.viewing, &first_nullifier).expect("spend secrets");

    let mut outputs = vec![ring_utxo(
        sender.owner,
        sender.nullifier_pubkey,
        change_amount,
        secrets.change_blinding,
    )];
    if let Some((recipient, amount)) = recipient {
        outputs.push(ring_utxo(
            recipient.owner_key_hash,
            recipient.nullifier_pubkey,
            amount,
            secrets.recipient_blinding,
        ));
    }
    RingWitness {
        viewing_secret_key: sender.viewing.clone(),
        nullifier_secret: sender.nullifier_secret,
        inputs,
        outputs,
        external_data_hash: random_field(),
        recipient: recipient.map(|(recipient, _)| recipient.clone()),
        proposal: Some(proposal),
        public_amount: fe_u64(public_amount),
    }
}

fn copy_witness(witness: &RingWitness) -> RingWitness {
    RingWitness {
        viewing_secret_key: witness.viewing_secret_key.clone(),
        nullifier_secret: witness.nullifier_secret,
        inputs: witness.inputs.clone(),
        outputs: witness.outputs.clone(),
        external_data_hash: witness.external_data_hash,
        recipient: witness.recipient.clone(),
        proposal: witness.proposal.clone(),
        public_amount: witness.public_amount,
    }
}

/// Prove a copy of `witness`, so the fixture keeps the original.
fn prove_copy(witness: &RingWitness) -> RingProofResult {
    copy_witness(witness)
        .prove()
        .expect("proof generation must succeed")
}

/// A proven proposal-bound spend plus the public identities its fixtures must
/// carry. Proofs are generated once per shape and shared by every test here.
struct ProvenSpend {
    sender_owner: [u8; 32],
    sender_viewing_pk: [u8; 33],
    sender_nullifier_pubkey: [u8; 32],
    recipient: Option<RingRecipient>,
    n_inputs: u8,
    output_hashes: Vec<[u8; 32]>,
    proof: RingProofResult,
    witness: RingWitness,
}

fn prove_spend(sender: &Sender, witness: RingWitness) -> ProvenSpend {
    let output_hashes = witness
        .outputs
        .iter()
        .map(|output| output.hash().expect("output hash"))
        .collect();
    ProvenSpend {
        sender_owner: sender.owner,
        sender_viewing_pk: sender.viewing_pk,
        sender_nullifier_pubkey: sender.nullifier_pubkey,
        recipient: witness.recipient.clone(),
        n_inputs: u8::try_from(witness.inputs.len()).expect("input count"),
        output_hashes,
        proof: prove_copy(&witness),
        witness,
    }
}

/// A `(2, 2)` transfer proposal: inputs 700 + 300, change 600, recipient 400.
/// For a transfer the proposal commits the recipient output's amount and owner
/// hash (proposal.go).
fn proven_transfer() -> &'static ProvenSpend {
    static TRANSFER: OnceLock<ProvenSpend> = OnceLock::new();
    TRANSFER.get_or_init(|| {
        let sender = sender();
        let recipient = RingRecipient {
            owner_key_hash: random_field(),
            nullifier_pubkey: random_field(),
            viewing_pubkey: X25519Keypair::new().pubkey(),
        };
        let recipient_amount = 400;
        let proposal = RingProposal {
            amount: fe_u64(recipient_amount),
            recipient: Poseidon::hashv(&[
                recipient.owner_key_hash.as_slice(),
                recipient.nullifier_pubkey.as_slice(),
            ])
            .expect("recipient owner hash"),
            blinding: random_field(),
            public_amount: [0u8; 32],
        };
        let witness = spend_witness(
            &sender,
            &[700, 300],
            600,
            Some((&recipient, recipient_amount)),
            0,
            proposal,
        );
        prove_spend(&sender, witness)
    })
}

/// A `(1, 1)` withdrawal proposal: input 1000, change 300, public amount
/// `WITHDRAWN`. With no recipient UTXO the proposal commits amount and recipient
/// 0 and the withdrawn value as its public amount.
fn proven_withdrawal() -> &'static ProvenSpend {
    static WITHDRAWAL: OnceLock<ProvenSpend> = OnceLock::new();
    WITHDRAWAL.get_or_init(|| {
        let sender = sender();
        let proposal = RingProposal {
            amount: [0u8; 32],
            recipient: [0u8; 32],
            blinding: random_field(),
            public_amount: fe_u64(WITHDRAWN),
        };
        let witness = spend_witness(
            &sender,
            &[1000],
            1000 - WITHDRAWN,
            None,
            WITHDRAWN,
            proposal,
        );
        prove_spend(&sender, witness)
    })
}

/// The forwarded SPP payload the ring proof binds: `private_tx_hash`,
/// `tx_viewing_pk`, the change/recipient ciphertexts in `outputs[..].data`, and
/// the withdrawal leg's amount. The SPP proof itself is never checked here (the
/// SPP CPI is not reached), so it is zeroed.
fn spp_payload(spend: &ProvenSpend, withdrawal: Option<InterfaceTransfer>) -> SppTransactIxData {
    let ciphertexts = std::iter::once(spend.proof.ciphertexts.sender.clone())
        .chain(spend.proof.ciphertexts.recipient.clone());
    let outputs: Vec<TransactOutput> = spend
        .output_hashes
        .iter()
        .zip(ciphertexts)
        .map(|(utxo_hash, ciphertext)| TransactOutput {
            utxo_hash: *utxo_hash,
            owner_tag: OwnerTag::Inline([0u8; 32]),
            data: Some(ciphertext),
        })
        .collect();
    let n_outputs = u8::try_from(outputs.len()).expect("output count");
    SppTransactIxData {
        expiry_unix_ts: u64::try_from(PROPOSAL_EXPIRY).expect("non-negative expiry"),
        tx_viewing_pk: spend.proof.secrets.tx_viewing_pk,
        salt: [0u8; 16],
        interface_transfers: withdrawal.into_iter().collect(),
        data_hash: None,
        ring_data_hash: None,
        outputs,
        messages: vec![],
        private_tx_hash: spend.proof.private_tx_hash,
        circuit: CircuitId::AnonymousRingEddsa(
            spend.n_inputs,
            n_outputs.max(2),
            3,
            AnonymousRingEddsaProofData {
                bsb22_commitment: Bsb22Commitment {
                    commitment: [0; 32],
                    commitment_pok: [0; 32],
                },
                default_owner_tag: None,
            },
        ),
        proof: TransactProof::zeroed(),
        inputs: (0..spend.n_inputs)
            .map(|index| InputUtxo {
                nullifier_hash: [index.wrapping_add(1); 32],
                tree_index: 0,
            })
            .collect(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    }
}

/// The SPP `ring_transact` account list the ring forwards, with the SPP program
/// account replaced by the ring program's own id (see the module doc comment).
fn placeholder_spp_accounts(
    test: &SquadsRingTest,
    spp: &SppTransactIxData,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
) -> Vec<AccountMeta> {
    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    RingTransact {
        payer: test.payer.pubkey(),
        input_trees: vec![Keypair::new().pubkey()],
        output_tree: Keypair::new().pubkey(),
        ring_program_id: test.program_id,
        owner_signers: vec![],
        interface_transfer_accounts,
        data: spp.clone(),
    }
    .instruction()
    .accounts
    .into_iter()
    .map(|meta| {
        if meta.pubkey == spp_program {
            AccountMeta::new_readonly(test.program_id, false)
        } else {
            meta
        }
    })
    .collect()
}

/// Prepared `execute_proposal` fixtures and instruction data.
struct Prepared {
    co_signer: Keypair,
    ring_config: Pubkey,
    proposal: Pubkey,
    sender_vka: Pubkey,
    /// Present for a transfer, absent for a withdrawal.
    recipient_vka: Option<Pubkey>,
    /// rent_payer == rent_recipient.
    rent_recipient: Pubkey,
    spp_accounts: Vec<AccountMeta>,
    data: ExecuteProposalIxData,
}

/// Install the ring config, the viewing key accounts and the seeded `Proposal`
/// for `spend`, and assemble the `execute_proposal` instruction data.
fn prepare(
    test: &mut SquadsRingTest,
    spend: &ProvenSpend,
    withdrawal: Option<(InterfaceTransfer, TransactInterfaceTransferAccounts)>,
) -> Prepared {
    let co_signer = Keypair::new();
    let ring_config = create_ring_config(test, &co_signer.pubkey());
    let sender_vka = install_vka(
        test,
        spend.sender_owner,
        spend.sender_viewing_pk,
        spend.proof.commitment,
        spend.sender_nullifier_pubkey,
    );
    let recipient_vka = spend.recipient.as_ref().map(|recipient| {
        install_vka(
            test,
            recipient.owner_key_hash,
            *recipient.viewing_pubkey.as_bytes(),
            [0u8; 32],
            recipient.nullifier_pubkey,
        )
    });

    // `owner` is the sender VKA's owner field (what execute_proposal checks),
    // `proposal_hash` is the hash the proof binds, and `rent_payer` receives the
    // rent when the proposal closes.
    let rent_payer = Keypair::new().pubkey();
    let proposal = Keypair::new().pubkey();
    let record = Proposal::new(
        Address::new_from_array(spend.sender_owner),
        Address::default(),
        Address::default(),
        spend.proof.proposal_hash,
        [0u8; 88],
        PROPOSAL_EXPIRY,
        rent_payer,
    );
    test.set_program_account(&proposal, record.serialize().expect("serialize proposal"))
        .expect("seed proposal");

    let (leg, leg_accounts) = withdrawal.unzip();
    let spp = spp_payload(spend, leg);
    let spp_accounts = placeholder_spp_accounts(test, &spp, leg_accounts.into_iter().collect());
    let mut bound_witness = copy_witness(&spend.witness);
    bound_witness.external_data_hash = squads_ring_tests::spp_external_data_hash(
        zolana_interface::instruction::tag::RING_TRANSACT,
        &spp,
        &spp_accounts,
    );
    // Settlement addresses are part of the proof's public input. Cache only a
    // proof for these exact external bytes, so tampering still fails on-chain.
    static BOUND_PROOFS: OnceLock<
        std::sync::Mutex<std::collections::HashMap<[u8; 32], [u8; 192]>>,
    > = OnceLock::new();
    let proof_cache = BOUND_PROOFS.get_or_init(Default::default);
    let mut proof_cache = proof_cache.lock().expect("proof cache lock");
    let ring_proof = *proof_cache
        .entry(bound_witness.external_data_hash)
        .or_insert_with(|| prove_copy(&bound_witness).proof);

    Prepared {
        co_signer,
        ring_config,
        proposal,
        sender_vka,
        recipient_vka,
        rent_recipient: rent_payer,
        spp_accounts,
        data: ExecuteProposalIxData { ring_proof, spp },
    }
}

fn prepare_transfer_proposal(test: &mut SquadsRingTest) -> Prepared {
    prepare(test, proven_transfer(), None)
}

fn prepare_withdrawal_proposal(test: &mut SquadsRingTest) -> Prepared {
    let withdrawal = (
        InterfaceTransfer::SolWithdrawal { amount: WITHDRAWN },
        TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
            recipient: Keypair::new().pubkey(),
        }),
    );
    prepare(test, proven_withdrawal(), Some(withdrawal))
}

fn execute_ix(test: &SquadsRingTest, p: &Prepared, data: ExecuteProposalIxData) -> Instruction {
    ExecuteProposal {
        payer: test.payer.pubkey(),
        co_signer: p.co_signer.pubkey(),
        ring_config: p.ring_config,
        proposal: p.proposal,
        sender_viewing_key_account: p.sender_vka,
        recipient_viewing_key_account: p.recipient_vka,
        rent_recipient: p.rent_recipient,
        spp_accounts: p.spp_accounts.clone(),
        data,
    }
    .instruction()
}

/// Send `execute_proposal` with a CU limit above the 200k default for the
/// pairing-heavy on-chain Groth16 verification and return the custom error.
fn send_execute_expect_err(
    test: &mut SquadsRingTest,
    p: &Prepared,
    data: ExecuteProposalIxData,
) -> u32 {
    let ix = execute_ix(test, p, data);
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let err = test
        .send(&[budget, ix], &[&p.co_signer])
        .expect_err("execute_proposal must not settle without a real SPP program");
    custom_code(&err)
}

#[test]
fn execute_proposal_transfer_verifies_real_ring_proof_then_attempts_spp_cpi() {
    let Some(mut test) = boot_program() else {
        return;
    };
    let prepared = prepare_transfer_proposal(&mut test);
    let code = send_execute_expect_err(&mut test, &prepared, prepared.data.clone());
    assert_eq!(code, SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn execute_proposal_withdrawal_verifies_real_ring_proof_then_attempts_spp_cpi() {
    let Some(mut test) = boot_program() else {
        return;
    };
    let prepared = prepare_withdrawal_proposal(&mut test);
    let code = send_execute_expect_err(&mut test, &prepared, prepared.data.clone());
    assert_eq!(code, SquadsRingError::InvalidSppProgram as u32);
}

#[test]
fn execute_proposal_rejects_tampered_ring_proof() {
    let Some(mut test) = boot_program() else {
        return;
    };
    let prepared = prepare_transfer_proposal(&mut test);

    let mut data = prepared.data.clone();
    if let Some(byte) = data.spp.private_tx_hash.first_mut() {
        *byte ^= 1;
    }
    let code = send_execute_expect_err(&mut test, &prepared, data);
    assert_eq!(code, SquadsRingError::RingProofVerificationFailed as u32);
}

#[test]
fn execute_proposal_rejects_proof_bound_to_another_proposal() {
    let Some(mut test) = boot_program() else {
        return;
    };
    let mut prepared = prepare_transfer_proposal(&mut test);

    let other_proposal = Keypair::new().pubkey();
    let record = Proposal::new(
        Address::new_from_array(proven_transfer().sender_owner),
        Address::default(),
        Address::default(),
        random_field(),
        [0u8; 88],
        PROPOSAL_EXPIRY,
        prepared.rent_recipient,
    );
    test.set_program_account(
        &other_proposal,
        record.serialize().expect("serialize proposal"),
    )
    .expect("seed proposal");
    prepared.proposal = other_proposal;

    let code = send_execute_expect_err(&mut test, &prepared, prepared.data.clone());
    assert_eq!(code, SquadsRingError::RingProofVerificationFailed as u32);
}

#[test]
fn execute_proposal_rejects_expiry_mismatch() {
    let Some(mut test) = boot_program() else {
        return;
    };
    let prepared = prepare_transfer_proposal(&mut test);

    let mut data = prepared.data.clone();
    data.spp.expiry_unix_ts -= 1;
    let code = send_execute_expect_err(&mut test, &prepared, data);
    assert_eq!(code, SquadsRingError::InvalidInstructionData as u32);
}
