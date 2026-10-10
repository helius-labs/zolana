//! Batch settlement through the test batch program: the authority creates a
//! batch account, fills it over several write transactions, and one settlement
//! transaction pays every recorded output through a single SPP `transact` CPI
//! with one real proof. Closing the batch returns its rent to a dedicated
//! recipient.

use shielded_pool_tests::support::{
    batch::{
        fill_batch, load_batch_program, send_v1, transact_instruction, CloseBatch, ScalingSpend,
        SettleBatch, SplitTransact,
    },
    batch_ring::{ring_transact_instruction, RingScalingSpend},
    fixtures::Pool,
    ring::RingRail,
    transact::{current_tree_roots, tree_progress},
};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::STATE_TREE_HEIGHT;
use zolana_hasher::Poseidon;
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::ZolanaProgramTest;
use zolana_tree::TreeAccount;

#[test]
fn settle_pays_every_output_written_in_chunks() {
    let Pool {
        mut rpc,
        tree,
        tree_id,
        ..
    } = Pool::initialized();
    load_batch_program(&mut rpc).expect("load batch program");
    let authority = rpc.payer.insecure_clone();

    let spend = ScalingSpend {
        n_inputs: 1,
        n_outputs: 16,
        sent_inputs: 1,
        sent_outputs: 16,
        prove: true,
    }
    .build(&rpc, tree, tree_id)
    .expect("prove spend");
    let output_hashes: Vec<[u8; 32]> = spend
        .data
        .outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect();
    let split = SplitTransact::new(&spend.data).expect("split transact data");

    let fill = fill_batch(&mut rpc, &authority, 7, &split, 5).expect("fill batch");
    assert_eq!(fill.write_transactions, 4);

    let transact = transact_instruction(authority.pubkey(), tree, spend.data);
    let settle = SettleBatch {
        authority: authority.pubkey(),
        batch: fill.batch,
        transact: &transact,
        split: &split,
    }
    .instruction()
    .expect("settle instruction");
    send_v1(&mut rpc, &authority, &[settle], None).expect("settle batch");

    let mut expected = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for hash in &output_hashes {
        expected.append(hash).expect("append output");
    }
    let (_, utxo_root, _) = current_tree_roots(&rpc, &tree);
    assert_eq!(utxo_root, expected.root());

    let rent_recipient = Keypair::new().pubkey();
    let batch_lamports = rpc
        .svm
        .get_account(&fill.batch)
        .expect("batch account")
        .lamports;
    let close = CloseBatch {
        authority: authority.pubkey(),
        batch: fill.batch,
        rent_recipient,
    }
    .instruction();
    send_v1(&mut rpc, &authority, &[close], None).expect("close batch");
    assert_eq!(
        rpc.svm.get_account(&rent_recipient).map(|a| a.lamports),
        Some(batch_lamports)
    );
    assert!(rpc
        .svm
        .get_account(&fill.batch)
        .is_none_or(|account| account.lamports == 0));
}

/// The widest confidential settlements as real v1 transactions through
/// LiteSVM: write transactions, then one settlement transaction that requests
/// the heap the wide `transact` needs. Ignored: these shapes verify against
/// locally generated keys that are not in proving-keys.lock.
#[test]
#[ignore = "needs local transfer_confidential_4_148 / 16_142 / 58_121 keys"]
fn wide_settlements_succeed_as_v1_transactions() {
    for (n_inputs, n_outputs, heap_bytes) in [
        (4, 148, 47 * 1024),
        (16, 142, 46 * 1024),
        (58, 121, 42 * 1024),
    ] {
        let Pool {
            mut rpc,
            tree,
            tree_id,
            ..
        } = Pool::initialized();
        load_batch_program(&mut rpc).expect("load batch program");
        let authority = rpc.payer.insecure_clone();
        let spend = ScalingSpend {
            n_inputs,
            n_outputs,
            sent_inputs: n_inputs,
            sent_outputs: n_outputs,
            prove: true,
        }
        .build(&rpc, tree, tree_id)
        .expect("prove wide spend");
        let split = SplitTransact::new(&spend.data).expect("split transact data");
        let fill = fill_batch(&mut rpc, &authority, 1, &split, usize::MAX).expect("fill batch");
        assert_eq!(fill.write_transactions, 3);
        let transact = transact_instruction(authority.pubkey(), tree, spend.data);
        let settle = SettleBatch {
            authority: authority.pubkey(),
            batch: fill.batch,
            transact: &transact,
            split: &split,
        }
        .instruction()
        .expect("settle instruction");
        let below = send_v1(
            &mut rpc,
            &authority,
            std::slice::from_ref(&settle),
            Some(heap_bytes - 1024),
        );
        assert!(below.is_err(), "{n_inputs}x{n_outputs} below its heap");
        let consumed = send_v1(&mut rpc, &authority, &[settle], Some(heap_bytes))
            .unwrap_or_else(|error| panic!("{n_inputs}x{n_outputs} settle: {error}"));
        println!("{n_inputs}x{n_outputs} settle consumed {consumed} CU");
    }
}

/// Moves the tree's nullifier queue cursor so its dummy-input headroom is 0:
/// every nullifier slot left is reserved for a UTXO the state tree can still
/// hold.
fn exhaust_dummy_input_headroom(rpc: &mut ZolanaProgramTest, tree: Pubkey) {
    let mut account = rpc.svm.get_account(&tree).expect("tree account");
    {
        let mut on_chain =
            TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
        let reserve = on_chain.utxo_tree().capacity();
        let nullifier = on_chain.nullifier_tree();
        let next_leaf = nullifier
            .capacity
            .checked_sub(reserve)
            .expect("nullifier capacity exceeds state capacity");
        nullifier
            .get_current_batch_mut()
            .expect("current nullifier batch")
            .start_index = next_leaf;
        nullifier.queue_next_index = next_leaf;
        assert_eq!(on_chain.dummy_input_headroom().expect("headroom"), 0);
    }
    rpc.svm.set_account(tree, account).expect("write tree");
}

fn dummy_input_headroom(rpc: &ZolanaProgramTest, tree: Pubkey) -> u64 {
    let mut account = rpc.svm.get_account(&tree).expect("tree account");
    let headroom = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())
        .expect("load tree")
        .dummy_input_headroom()
        .expect("headroom");
    headroom
}

/// Settles a ring 4x32 spend of one real input through the batch program;
/// the three other input slots are compact padding.
fn settle_one_input_on_four_slots(
    allow_dummy_inputs: bool,
    exhaust_headroom: bool,
) -> HeadroomSettlement {
    let Pool {
        mut rpc,
        tree,
        tree_id,
        ..
    } = Pool::initialized();
    load_batch_program(&mut rpc).expect("load batch program");
    let authority = rpc.payer.insecure_clone();
    let spend = RingScalingSpend {
        rail: RingRail::Eddsa,
        n_inputs: 4,
        n_outputs: 32,
        sent_inputs: 1,
        sent_outputs: 32,
        ring_data_hash: None,
        allow_dummy_inputs,
        prove: true,
    }
    .build(&mut rpc, tree, tree_id)
    .expect("prove ring 4x32 spend");
    assert_eq!(spend.data.inputs.len(), 1, "compact padding is not sent");
    let split = SplitTransact::new(&spend.data).expect("split transact data");
    let fill = fill_batch(&mut rpc, &authority, 1, &split, usize::MAX).expect("fill batch");
    let transact = ring_transact_instruction(authority.pubkey(), tree, spend.data, false);
    let settle = SettleBatch {
        authority: authority.pubkey(),
        batch: fill.batch,
        transact: &transact,
        split: &split,
    }
    .instruction()
    .expect("settle instruction");
    if exhaust_headroom {
        exhaust_dummy_input_headroom(&mut rpc, tree);
    }
    let headroom_before = dummy_input_headroom(&rpc, tree);
    let progress_before = tree_progress(&rpc, &tree);
    let result = send_v1(&mut rpc, &authority, &[settle], None);
    HeadroomSettlement {
        result,
        headroom_before,
        headroom_after: dummy_input_headroom(&rpc, tree),
        progress_before,
        progress_after: tree_progress(&rpc, &tree),
    }
}

struct HeadroomSettlement {
    result: Result<u64, anyhow::Error>,
    headroom_before: u64,
    headroom_after: u64,
    progress_before: (u64, u64),
    progress_after: (u64, u64),
}

/// A 1-input spend on a 4-input shape sends one input; its three compact
/// padding slots insert no nullifier and draw no dummy-input headroom. On a
/// fresh tree it consumes one unit of headroom (its own nullifier). At zero
/// headroom SPP publishes `allow_dummy_inputs = false`, and the spend proven
/// for that policy still settles, while one proven for `true` is refused.
#[test]
#[ignore = "needs the local transfer_ring_4_32 key"]
fn compact_padded_settlement_needs_no_dummy_input_headroom() {
    let fresh = settle_one_input_on_four_slots(true, false);
    fresh.result.expect("fresh tree settles");
    assert_eq!(
        fresh.headroom_before - fresh.headroom_after,
        1,
        "one sent input, one unit of headroom"
    );
    assert_eq!(
        fresh.progress_after,
        (fresh.progress_before.0 + 32, fresh.progress_before.1 + 1),
        "32 outputs appended and one nullifier queued"
    );

    let exhausted = settle_one_input_on_four_slots(false, true);
    exhausted
        .result
        .expect("compact-padded spend settles at zero headroom");
    assert_eq!(
        (exhausted.headroom_before, exhausted.headroom_after),
        (0, 0)
    );
    assert_eq!(exhausted.progress_after.1, exhausted.progress_before.1 + 1);

    let refused = settle_one_input_on_four_slots(true, true);
    assert!(
        refused.result.is_err(),
        "a proof for allow_dummy_inputs = true no longer matches"
    );
}
