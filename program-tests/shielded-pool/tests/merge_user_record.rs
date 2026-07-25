//! `merge_transact` reads owner identity, the viewing key, and the `merging_enabled`
//! opt-in from a `user_record` account. This pins the property those three reads
//! depend on: the record must be the canonical registry record of the owner whose
//! UTXOs are merged, not merely some registry-owned account carrying that owner's
//! signing key.
//!
//! Both tests submit a merge with a zeroed proof. That is enough to tell the
//! account check apart from the proof check: a record SPP accepts runs on to proof
//! verification (`InvalidTransactProofEncoding` / `TransactProofVerificationFailed`),
//! a record SPP rejects fails earlier with `InvalidUserRecord`. Skips when the
//! program `.so` files are missing.

#[path = "common/setup.rs"]
mod common;

use std::path::PathBuf;

use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::instruction::{
    instruction_data::{
        merge_transact::{
            MergeTransactIxData, MERGE_ENCRYPTED_UTXO_LEN, MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
            MERGE_INPUT_COUNT,
        },
        transact::P256Proof,
    },
    MergeTransact,
};
use zolana_interface::merge_utils::owner_pk_field_compressed;
use zolana_keypair::hash::hash_field;
use zolana_program_test::ZolanaProgramTest;
use zolana_user_registry_interface::{
    instruction::{self as registry, set_merging_enabled, RegisterData},
    user_record_pda, user_registry_program_id,
};

/// `ShieldedPoolError::InvalidUserRecord`.
const INVALID_USER_RECORD: u32 = 7018;
/// `ShieldedPoolError::InvalidTransactProofEncoding`.
const INVALID_PROOF_ENCODING: u32 = 7007;
/// `ShieldedPoolError::TransactProofVerificationFailed`.
const PROOF_VERIFICATION_FAILED: u32 = 7008;
/// `ShieldedPoolError::MergeDisabled`.
const MERGE_DISABLED: u32 = 7017;

/// The owner whose UTXOs the merge consolidates. `owner_p256` is public key
/// material: the compressed prefix is the only thing SPP validates about it.
const OWNER_P256: [u8; 33] = p256_pubkey(0x11);
const OWNER_VIEWING: [u8; 33] = p256_pubkey(0x22);
const IMPOSTOR_VIEWING: [u8; 33] = p256_pubkey(0x33);

const fn p256_pubkey(tag: u8) -> [u8; 33] {
    let mut pubkey = [0u8; 33];
    pubkey[0] = 0x02;
    pubkey[1] = tag;
    pubkey
}

fn user_registry_path() -> PathBuf {
    if let Ok(path) = std::env::var("USER_REGISTRY_PROGRAM_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("zolana_user_registry.so")
}

/// Boot the pool test environment with the user-registry program loaded, or `None`
/// when either `.so` is missing.
fn program_test_with_registry() -> Option<ZolanaProgramTest> {
    let mut rpc = common::program_test()?;
    let path = user_registry_path();
    if !path.exists() {
        eprintln!(
            "skipping merge user_record test: {} missing - run `just build-programs`",
            path.display()
        );
        return None;
    }
    let bytes = std::fs::read(&path).expect("read user-registry program");
    rpc.svm
        .add_program(user_registry_program_id(), &bytes)
        .expect("add user-registry program");
    Some(rpc)
}

fn send(
    rpc: &mut ZolanaProgramTest,
    ixs: &[Instruction],
    signers: &[&Keypair],
) -> Result<(), String> {
    let payer = rpc.payer.insecure_clone();
    let mut all_signers: Vec<&Keypair> = vec![&payer];
    all_signers.extend_from_slice(signers);
    rpc.svm.expire_blockhash();
    let blockhash = rpc.svm.latest_blockhash();
    let message = Message::new(ixs, Some(&payer.pubkey()));
    let transaction = Transaction::new(&all_signers, message, blockhash);
    rpc.svm
        .send_transaction(transaction)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

/// Register `owner` with the given keys, opting the record into merging when
/// `enable_merging`. Returns the record address, or the registry's rejection.
fn register(
    rpc: &mut ZolanaProgramTest,
    owner: &Keypair,
    owner_p256: Option<[u8; 33]>,
    viewing_pubkey: [u8; 33],
    enable_merging: bool,
) -> Result<Pubkey, String> {
    rpc.airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("airdrop owner");
    let record = user_record_pda(&owner.pubkey()).0;
    let data = RegisterData {
        owner_p256,
        nullifier_pubkey: fe(1),
        viewing_pubkey,
    };
    send(
        rpc,
        &[registry::register(record, owner.pubkey(), data)],
        &[&owner.insecure_clone()],
    )?;
    if enable_merging {
        send(
            rpc,
            &[set_merging_enabled(record, owner.pubkey(), true)],
            &[&owner.insecure_clone()],
        )?;
    }
    Ok(record)
}

/// Register `owner` with the given keys and opt the record into merging.
fn register_opted_in(
    rpc: &mut ZolanaProgramTest,
    owner: &Keypair,
    owner_p256: [u8; 33],
    viewing_pubkey: [u8; 33],
) -> Result<Pubkey, String> {
    register(rpc, owner, Some(owner_p256), viewing_pubkey, true)
}

/// A field element holding `value` in its low 8 bytes (big-endian).
fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// A well-formed `merge_transact` body with a zeroed proof. `eddsa_owner` picks
/// the rail SPP derives the owner identity on.
fn merge_data(eddsa_owner: bool) -> MergeTransactIxData {
    let mut encrypted_utxo = vec![0u8; MERGE_ENCRYPTED_UTXO_LEN];
    encrypted_utxo[0] = MERGE_ENCRYPTED_UTXO_TYPE_PREFIX;
    MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: P256Proof {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
            commitment: [0u8; 32],
            commitment_pok: [0u8; 32],
        },
        output_utxo_hash: fe(900),
        nullifiers: (0..MERGE_INPUT_COUNT as u64).map(|i| fe(500 + i)).collect(),
        utxo_tree_root_index: vec![0; MERGE_INPUT_COUNT],
        nullifier_tree_root_index: vec![0; MERGE_INPUT_COUNT],
        private_tx_hash: fe(901),
        encrypted_utxo,
        eddsa_owner,
    }
}

fn send_merge_on_rail(
    rpc: &mut ZolanaProgramTest,
    tree: Pubkey,
    user_record: Pubkey,
    eddsa_owner: bool,
) -> Result<(), String> {
    let payer = rpc.payer.pubkey();
    let ix = MergeTransact {
        tree,
        payer,
        user_record,
        data: merge_data(eddsa_owner),
    }
    .instruction();
    // The tree writes and the proof decoding run past the 200k default.
    let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    send(rpc, &[compute_budget, ix], &[])
}

fn send_merge(
    rpc: &mut ZolanaProgramTest,
    tree: Pubkey,
    user_record: Pubkey,
) -> Result<(), String> {
    send_merge_on_rail(rpc, tree, user_record, false)
}

#[track_caller]
fn assert_custom(err: &str, code: u32, context: &str) {
    let needle = format!("Custom({code})");
    assert!(
        err.contains(&needle),
        "{context}: expected {needle}, got: {err}"
    );
}

fn setup() -> Option<(ZolanaProgramTest, Pubkey)> {
    let mut rpc = program_test_with_registry()?;
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    Some((rpc, tree.pubkey()))
}

/// The canonical record of the merged owner is accepted, so a rejection of any
/// other record is attributable to the account check rather than to the proof.
fn assert_canonical_record_reaches_the_proof(
    rpc: &mut ZolanaProgramTest,
    tree: Pubkey,
    record: Pubkey,
) {
    let err = send_merge(rpc, tree, record).expect_err("a zeroed proof must not verify");
    assert!(
        err.contains(&format!("Custom({INVALID_PROOF_ENCODING})"))
            || err.contains(&format!("Custom({PROOF_VERIFICATION_FAILED})")),
        "the owner's own record must be accepted and the merge reach proof verification, got: {err}"
    );
}

/// A second registrant may claim any `owner_p256` it likes, so a record that is
/// canonical for one Solana owner can carry a different owner's signing key. That
/// record is not the merged owner's record and must not authorize the merge.
#[test]
fn merge_transact_rejects_a_record_registered_under_another_owner() {
    let Some((mut rpc, tree)) = setup() else {
        return;
    };

    let owner = Keypair::new();
    let owner_record = register_opted_in(&mut rpc, &owner, OWNER_P256, OWNER_VIEWING)
        .expect("register the merged owner");
    assert_canonical_record_reaches_the_proof(&mut rpc, tree, owner_record);

    // Claiming another owner's `owner_p256` is the step a registry proof of
    // possession would refuse; the property holds either way.
    let impostor = Keypair::new();
    let Ok(impostor_record) = register_opted_in(&mut rpc, &impostor, OWNER_P256, IMPOSTOR_VIEWING)
    else {
        return;
    };

    let err = send_merge(&mut rpc, tree, impostor_record).expect_err(
        "merge_transact must reject a record registered under an owner other than the merged owner",
    );
    assert_custom(
        &err,
        INVALID_USER_RECORD,
        "a record whose owner_p256 was claimed by a different registrant",
    );
}

/// A registry-owned account at an address that is not the record PDA of its stored
/// `owner`. The registry program only ever creates canonical PDAs, so this state is
/// planted rather than reachable on-chain; the test pins the derivation check that
/// would reject it.
#[test]
fn merge_transact_rejects_a_non_canonical_record_address() {
    let Some((mut rpc, tree)) = setup() else {
        return;
    };

    let owner = Keypair::new();
    let owner_record = register_opted_in(&mut rpc, &owner, OWNER_P256, OWNER_VIEWING)
        .expect("register the merged owner");
    assert_canonical_record_reaches_the_proof(&mut rpc, tree, owner_record);

    let canonical = rpc.svm.get_account(&owner_record).expect("record account");
    let copy = Pubkey::new_unique();
    rpc.svm
        .set_account(
            copy,
            Account {
                lamports: canonical.lamports,
                data: canonical.data,
                owner: user_registry_program_id(),
                executable: false,
                rent_epoch: canonical.rent_epoch,
            },
        )
        .expect("plant the record copy");

    let err = send_merge(&mut rpc, tree, copy)
        .expect_err("merge_transact must reject a record at a non-canonical address");
    assert_custom(
        &err,
        INVALID_USER_RECORD,
        "a registry-owned record copy at a non-canonical address",
    );
}

/// A Solana owner is reachable through the P256 branch, because the owner
/// encoding drops the parity bit: `owner_pk_field_compressed(0x02 || address)` is
/// the same field element as the Solana owner's `hash_field(address)`. An
/// impostor record carrying those 33 bytes therefore speaks for a Solana owner
/// who never enabled merging.
#[test]
fn merge_transact_rejects_an_opt_in_borrowed_from_another_record() {
    let Some((mut rpc, tree)) = setup() else {
        return;
    };

    let owner = Keypair::new();
    let address = owner.pubkey().to_bytes();
    let mut claimed_p256 = [0u8; 33];
    claimed_p256[0] = 0x02;
    claimed_p256[1..].copy_from_slice(&address);
    assert_eq!(
        owner_pk_field_compressed(&claimed_p256).expect("owner pk_field of the claimed key"),
        hash_field(&address).expect("owner pk_field of the Solana address"),
        "the two rails must agree for this substitution to be possible"
    );

    // A Solana owner: no `owner_p256`, and merging left off.
    let owner_record =
        register(&mut rpc, &owner, None, OWNER_VIEWING, false).expect("register the merged owner");
    let err = send_merge_on_rail(&mut rpc, tree, owner_record, true)
        .expect_err("the owner never enabled merging");
    assert_custom(
        &err,
        MERGE_DISABLED,
        "the merged owner's own record, merging not enabled",
    );

    let impostor = Keypair::new();
    let Ok(impostor_record) =
        register_opted_in(&mut rpc, &impostor, claimed_p256, IMPOSTOR_VIEWING)
    else {
        return;
    };

    let err = send_merge(&mut rpc, tree, impostor_record)
        .expect_err("merge_transact must not take the opt-in from someone else's record");
    assert_custom(
        &err,
        INVALID_USER_RECORD,
        "an impostor record claiming the merged owner's Solana address as a P256 key",
    );
}
