//! C-02 regression: the program rejects a reserved input nullifier (0 or p-1)
//! before it can reach the nullifier queue. The reject runs ahead of proof
//! verification, so a dummy proof is enough -- no prover needed. The circuit-side
//! pin that also blocks arbitrary (non-sentinel) victim nullifiers is covered by
//! `spp_transaction/inputs_test.go::TestDummyInputRejectsMimickedNullifier`.
//!
//! Requires `cargo build-sbf -p shielded-pool-program`; skips when `.so` missing.

#[path = "../common/setup.rs"]
mod common;
// The shared helper module carries prover-backed helpers this binary does not use.
#[allow(dead_code)]
#[path = "../common/transact_core.rs"]
mod transact_common;

use num_bigint::BigUint;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::instruction::{instruction_data::transact::TransactIxData, Transact};
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::instructions::transact::spp_proof_inputs::BN254_MODULUS_DEC;
use zolana_tree::TreeAccount;

use crate::transact_common::{eddsa_input_utxo, fe, inline_outputs, new_transact_ix_data};

/// Error code for `ShieldedPoolError::ReservedNullifier`.
const RESERVED_NULLIFIER: u32 = 7026;

fn send_raw(
    rpc: &mut ZolanaProgramTest,
    ix: solana_instruction::Instruction,
    payer: &Keypair,
) -> Result<(), String> {
    let blockhash = rpc.svm.latest_blockhash();
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, blockhash);
    rpc.svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn queue_next_index(rpc: &ZolanaProgramTest, tree: &Pubkey) -> u64 {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    account.nullifer_tree().queue_batches.next_index
}

/// BN254 `p-1`, big-endian: the nullifier tree's upper sentinel.
fn p_minus_one() -> [u8; 32] {
    let p1 = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32;
    let be = p1.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// A dummy-only (2,3) transact whose first input carries `nullifier`. The proof
/// stays zeroed; the reserved-nullifier guard runs before verification, so the
/// witness never has to be valid.
fn dummy_transact(nullifier: [u8; 32]) -> TransactIxData {
    let output_hashes = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let view_tags = [[4u8; 32], [5u8; 32], [6u8; 32]];
    new_transact_ix_data(
        vec![eddsa_input_utxo(nullifier, 0), eddsa_input_utxo(fe(2), 0)],
        None,
        inline_outputs(&output_hashes, &view_tags),
        None,
    )
}

#[test]
fn reserved_padding_nullifier_is_rejected() {
    let Some(mut rpc) = common::program_test() else {
        return;
    };
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree")
        .pubkey();
    let attacker = rpc.payer.insecure_clone();

    for (label, nullifier) in [("zero", [0u8; 32]), ("p-1", p_minus_one())] {
        let queued_before = queue_next_index(&rpc, &tree);
        let ix = Transact {
            payer: attacker.pubkey(),
            tree,
            withdrawal: None,
            data: dummy_transact(nullifier),
        }
        .instruction();

        let err = send_raw(&mut rpc, ix, &attacker)
            .expect_err(&format!("{label} nullifier must be rejected"));
        assert!(
            err.contains(&format!("Custom({RESERVED_NULLIFIER})")),
            "{label}: expected ReservedNullifier ({RESERVED_NULLIFIER}), got: {err}"
        );
        assert_eq!(
            queue_next_index(&rpc, &tree),
            queued_before,
            "{label}: rejected before queue insertion, so next_index is unchanged"
        );
    }
}
