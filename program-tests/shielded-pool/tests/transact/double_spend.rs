//! Double-spend probes for the `transact` nullifier path.
//!
//! `process_transact_core` writes the tree (`apply_tree`) before it verifies the
//! proof, so every control in `apply_tree` -- the nullifier queue's bloom-filter
//! non-inclusion check and the root-history lookups -- is reachable with a zeroed
//! proof. That ordering is what makes these probes precise: the returned error
//! code says which control fired. `NullifierTreeUpdateFailed` (7002) means the
//! queue rejected the nullifier; `TransactProofVerificationFailed` (7008) means
//! the queue accepted it and only the (deliberately invalid) proof stopped the
//! transaction.
//!
//! Requires `just build-programs`; each test skips when the `.so` is missing.

#[path = "../common/setup.rs"]
mod common;
#[path = "../common/transact_core.rs"]
mod transact_common;

use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::TransferOutput;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::instruction::{
    instruction_data::transact::{
        InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof,
    },
    Transact,
};
use zolana_keypair::hash::hash_field;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::instructions::transact::PrivateTxHash;
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, external_data_hash,
    inline_outputs, new_transact_ix_data, output_owner_pk_hashes, prove_and_verify_transfer,
    public_input_hash, set_output_owner_tags, start_prover, TransferProverInputsArgs,
};

/// `ShieldedPoolError::NullifierTreeUpdateFailed` -- the nullifier queue refused
/// the value (bloom-filter non-inclusion, i.e. already spent).
const NULLIFIER_TREE_UPDATE_FAILED: u32 = 7002;
/// `ShieldedPoolError::TransactProofVerificationFailed` -- the queue accepted
/// every nullifier and the transaction only failed on the invalid proof.
const TRANSACT_PROOF_VERIFICATION_FAILED: u32 = 7008;
/// `ShieldedPoolError::StaleNullifierRoot` -- the nullifier root index pointed at
/// a zeroed root-history slot.
const STALE_NULLIFIER_ROOT: u32 = 7015;

/// A field element holding `value` in its low 8 bytes (big-endian).
fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

struct Env {
    rpc: ZolanaProgramTest,
    tree: Pubkey,
}

impl Env {
    /// Returns `None` when the program `.so` is missing so callers can skip.
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        let authority = solana_keypair::Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(common::tree_account_size(), &authority)
            .expect("create tree");
        let tree = tree.pubkey();
        Some(Self { rpc, tree })
    }

    /// Send a `transact` whose inputs are exactly `inputs`, with a zeroed proof.
    /// Returns the program's custom error code.
    fn send(&mut self, inputs: Vec<InputUtxo>) -> u32 {
        let payer = self.rpc.payer.pubkey();
        let ix = Transact {
            payer,
            tree: self.tree,
            withdrawal: None,
            data: TransactIxData {
                proof: TransactProof::zeroed_eddsa(),
                expiry_unix_ts: u64::MAX,
                relayer_fee: 0,
                private_tx_hash: [0u8; 32],
                p256_signing_pk_x: None,
                inputs,
                public_sol_amount: None,
                public_spl_amount: None,
                data_hash: None,
                zone_data_hash: None,
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                outputs: vec![
                    TransactOutput {
                        utxo_hash: fe(101),
                        owner_tag: OwnerTag::Inline([1u8; 32]),
                        data: None,
                    },
                    TransactOutput {
                        utxo_hash: fe(102),
                        owner_tag: OwnerTag::Inline([2u8; 32]),
                        data: None,
                    },
                ],
                messages: Vec::new(),
            },
        }
        .instruction();

        let err = self
            .rpc
            .create_and_send_default_payer_transaction(&[ix], &[])
            .expect_err("zeroed proof must never land");
        custom_code(&err)
    }
}

/// Extract the `Custom(n)` code from a program-test error.
#[track_caller]
fn custom_code(err: &zolana_program_test::ProgramTestError) -> u32 {
    let msg = format!("{err}");
    let start = msg
        .find("Custom(")
        .unwrap_or_else(|| panic!("no Custom(..) in error: {msg}"))
        + "Custom(".len();
    let rest = &msg[start..];
    let end = rest
        .find(')')
        .unwrap_or_else(|| panic!("unterminated Custom( in error: {msg}"));
    rest[..end]
        .parse()
        .unwrap_or_else(|_| panic!("non-numeric Custom code in error: {msg}"))
}

fn input(nullifier_hash: [u8; 32], nullifier_tree_root_index: u16) -> InputUtxo {
    InputUtxo {
        nullifier_hash,
        nullifier_tree_root_index,
        utxo_tree_root_index: 0,
        tree_index: 0,
        eddsa_signer_index: 0,
    }
}

/// The same nullifier in two input slots of one proof must be rejected by the
/// program, independently of the circuit's own distinctness constraint. The first
/// slot's insert sets the bloom-filter bits; the second finds them all set and
/// fails. Reaching `NullifierTreeUpdateFailed` rather than the proof error proves
/// the queue -- not the verifier -- is what stops it.
#[test]
fn duplicate_nullifier_in_two_slots_is_rejected_by_the_queue() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    let n = fe(0x5EED);
    assert_eq!(
        env.send(vec![input(n, 0), input(n, 0)]),
        NULLIFIER_TREE_UPDATE_FAILED,
        "the nullifier queue must reject a repeated nullifier within one instruction"
    );
}

/// Control for the test above: two *distinct* nullifiers pass the queue, so the
/// transaction gets as far as proof verification. Without this the assertion
/// above could pass for the wrong reason (e.g. every zeroed-proof transact
/// failing at 7002 for some unrelated cause).
#[test]
fn distinct_nullifiers_pass_the_queue_and_fail_only_on_the_proof() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    assert_eq!(
        env.send(vec![input(fe(0xA1), 0), input(fe(0xA2), 0)]),
        TRANSACT_PROOF_VERIFICATION_FAILED,
        "distinct nullifiers must clear the queue and stop at the proof"
    );
}

/// A nullifier root index pointing at a root-history slot that was never written
/// (still zero) must be rejected. This is the on-chain half of the root-history
/// bound: when the forester zeroes a batch's bloom filter it also zeroes every
/// root that predates the batch, and this lookup is what makes those slots
/// unusable afterwards.
#[test]
fn zeroed_nullifier_root_slot_is_rejected() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    // Slot 0 holds the init root; a fresh tree leaves 1..capacity zeroed.
    assert_eq!(
        env.send(vec![input(fe(0xB1), 5)]),
        STALE_NULLIFIER_ROOT,
        "a zeroed root-history slot must not resolve to a usable root"
    );
}

/// The (utxo, nullifier) tree roots at history index 0, as `apply_tree` reads
/// them. `transact` never advances the nullifier root history -- only the
/// forester's `batch_update_nullifier_tree` does -- so these values are stable
/// across the two sends below, which is what makes the replay a genuine
/// double-spend attempt rather than a stale-proof rejection.
fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(0).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

/// A (2,3) eddsa-rail `transact` with a real Groth16 proof over two circuit-dummy
/// inputs carrying `nullifiers`. Mirrors `transact.rs::build_valid_transact_ix`.
fn build_valid_transact_ix(env: &Env, nullifiers: [[u8; 32]; 2]) -> TransactIxData {
    let payer = env.rpc.payer.pubkey();
    let payer_bytes = payer.to_bytes();
    let roots = tree_roots(&env.rpc, &env.tree);
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];

    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let view_tags = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut ix_data = new_transact_ix_data(
        nullifiers.iter().map(|n| input(*n, 0)).collect(),
        None,
        inline_outputs(&output_hashes, &view_tags),
        None,
    );

    let owner_pk_hashes =
        output_owner_pk_hashes(&ix_data.outputs, None).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);

    let external_data_hash = external_data_hash(&ix_data, &zero).expect("external data hash");
    let private_tx = PrivateTxHash::new(&[zero, zero], &[zero, zero, zero], &external_data_hash)
        .hash()
        .expect("private tx hash");

    let owner_hash = hash_field(&payer_bytes).expect("owner hash");
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = public_input_hash(
        &nullifiers,
        &output_hashes,
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &zero,
        &payer_pubkey_hash,
        &[owner_hash, owner_hash],
        &owner_pk_hashes,
        &zero,
    );

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            dummy_input(&nullifiers[0], roots, &owner_hash),
            dummy_input(&nullifiers[1], roots, &owner_hash),
        ],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_sol_amount: zero,
        payer_pubkey_hash,
        public_input_hash,
    });
    ix_data.proof = prove_and_verify_transfer(&prover_inputs, public_input_hash, "double spend")
        .expect("prove transact");
    ix_data.private_tx_hash = private_tx;
    ix_data
}

/// The central invariant, exercised end to end: land a `transact` that publishes
/// two nullifiers, then resubmit the byte-identical instruction. The proof is
/// still valid the second time (the roots it commits to have not moved), so the
/// nullifier queue is the only thing that can stop it -- and it does.
#[test]
fn replaying_a_landed_spend_is_rejected() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    start_prover().expect("start prover");

    let ix_data = build_valid_transact_ix(&env, [fe(0xD1), fe(0xD2)]);
    let payer = env.rpc.payer.pubkey();
    let build = |data: TransactIxData| {
        Transact {
            payer,
            tree: env.tree,
            withdrawal: None,
            data,
        }
        .instruction()
    };

    let first = env
        .rpc
        .create_and_send_default_payer_transaction(&[build(ix_data.clone())], &[]);
    assert!(first.is_ok(), "the first spend must land: {first:?}");

    // The `transact` instruction is byte-identical on the replay; a compute-budget
    // instruction only changes the enclosing transaction so litesvm does not
    // reject it as an already-processed signature.
    let replay = env
        .rpc
        .create_and_send_default_payer_transaction(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                build(ix_data),
            ],
            &[],
        )
        .expect_err("a replayed spend must be rejected");
    assert_eq!(
        custom_code(&replay),
        NULLIFIER_TREE_UPDATE_FAILED,
        "the replay must be stopped by the nullifier queue, not by anything else"
    );
}

/// The same spend twice inside one Solana transaction. Instructions execute
/// sequentially against the same account data, so the second instruction sees the
/// bloom-filter bits the first set; the whole transaction then reverts.
#[test]
fn spending_twice_in_one_transaction_is_rejected() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    start_prover().expect("start prover");

    let ix_data = build_valid_transact_ix(&env, [fe(0xE1), fe(0xE2)]);
    let payer = env.rpc.payer.pubkey();
    let build = |data: TransactIxData| {
        Transact {
            payer,
            tree: env.tree,
            withdrawal: None,
            data,
        }
        .instruction()
    };

    let err = env
        .rpc
        .create_and_send_default_payer_transaction(&[build(ix_data.clone()), build(ix_data)], &[])
        .expect_err("two identical spends in one transaction must be rejected");
    assert_eq!(
        custom_code(&err),
        NULLIFIER_TREE_UPDATE_FAILED,
        "the second instruction must be stopped by the nullifier queue"
    );
}

/// Probe: the nullifier value `0` is already a leaf of the nullifier tree (the
/// indexed tree is initialised with element `0`, next_value `p-1`). A padding
/// dummy input slot leaves its public nullifier column unconstrained in the
/// circuit, so a prover may put `0` there. This test records whether the program
/// accepts `0` into the nullifier queue.
///
/// Reaching the proof error means the queue accepted it, which would leave the
/// pending batch holding a value the forester cannot append to an indexed tree
/// that already contains it.
#[test]
fn zero_nullifier_is_accepted_into_the_queue() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    assert_eq!(
        env.send(vec![input([0u8; 32], 0)]),
        TRANSACT_PROOF_VERIFICATION_FAILED,
        "records that the queue does not reject the already-present value 0"
    );
}

/// The same probe with a *valid* proof: a padding dummy input slot carrying the
/// nullifier `0` lands on chain. The circuit does not pin a padding slot's
/// nullifier column, so a prover is free to choose it, and `apply_tree` inserts
/// every column unconditionally. `0` is already a leaf of the indexed nullifier
/// tree, so the pending batch now holds a value the forester cannot append.
///
/// This is a liveness finding, not a double spend: it cannot un-nullify a real
/// note. See `zero_is_already_a_nullifier_tree_leaf` for the other half.
#[test]
fn zero_nullifier_lands_on_chain_with_a_valid_proof() {
    let Some(mut env) = Env::boot() else {
        return;
    };
    start_prover().expect("start prover");

    let ix_data = build_valid_transact_ix(&env, [[0u8; 32], fe(1)]);
    let payer = env.rpc.payer.pubkey();
    let ix = Transact {
        payer,
        tree: env.tree,
        withdrawal: None,
        data: ix_data,
    }
    .instruction();

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(
        result.is_ok(),
        "a padding dummy carrying nullifier 0 is accepted: {result:?}"
    );
}

/// The other half of the finding above: `0` is a leaf of the nullifier tree from
/// genesis (the indexed array is initialised with element `0`), and an indexed
/// tree cannot take it a second time. A batch containing `0` therefore has no
/// satisfiable append proof.
#[test]
fn zero_is_already_a_nullifier_tree_leaf() {
    use num_bigint::BigUint;
    use zolana_merkle_tree::indexed::IndexedMerkleTree;

    // Same construction as the on-chain nullifier tree: an indexed tree seeded
    // with element 0 and next_value p-1.
    let modulus: BigUint = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();
    let mut tree = IndexedMerkleTree::<zolana_hasher::Poseidon, usize>::new_with_next_value(
        40,
        0,
        modulus - 1u32,
    )
    .unwrap();

    assert_eq!(
        tree.indexed_array.get(0).map(|e| e.value.clone()),
        Some(BigUint::from(0u32)),
        "element 0 must be present from genesis"
    );
    assert!(
        tree.append(&BigUint::from(0u32)).is_err(),
        "appending the already-present value 0 must be unsatisfiable"
    );
}
