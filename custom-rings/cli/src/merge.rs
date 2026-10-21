//! Merge the persistent sender wallet's fragmented custom-ring notes.

use std::collections::{BTreeMap, HashSet};

use anyhow::{anyhow, ensure, Result};
use custom_ring_sdk::{CoSignScope, CustomRingMerge, MergeProofInput, RingMergeOperation};
use solana_address::Address;
use solana_signer::Signer;
use zolana_interface::pda;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{select_merge_where, SpendableDecryptionResult, WalletUtxo, SOL_MINT};

use crate::{assets, line, transact, Context, MergeArgs};

pub fn run(ctx: &Context, args: MergeArgs) -> Result<()> {
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let registry = assets::resolve(ctx.rpc(), mint)?.registry;
    let cosigner = transact::cosigner(ctx, &args.cosigner, CoSignScope::TRANSFERS)?;
    println!("reading the sender's notes");
    let spendable = ctx.spendable_utxos(&sender, &registry)?;
    if !spendable.unknown_asset_ids.is_empty() {
        line("unregistered asset ids", spendable.unknown_asset_ids.len());
    }
    if !spendable.unknown_mints.is_empty() {
        line("unregistered mints", spendable.unknown_mints.len());
    }
    let selected = select(&spendable, ctx.ring.program_id(), mint, args.count as usize)?;
    let (input_count, tree_id) = (selected.len(), selected[0].tree_id);
    let tree = pda::tree(tree_id);
    let prepared = CustomRingMerge::new(ctx.ring, selected, None)?
        .with_output_tree_id(tree_id)
        .encrypt(&sender)?;
    let (output_hash, merged_amount) = (prepared.output().hash(tree_id)?, prepared.output().amount);
    let mut merge = RingMergeOperation::new(
        prepared,
        MergeProofInput {
            nullifier_key: sender.nullifier_key.clone(),
            input_tree: tree,
            output_tree: tree,
        },
    );
    if let Some(cosigner) = &cosigner {
        merge = merge.with_cosigner(cosigner.pubkey());
    }
    let payer = ctx.funded_authority()?;
    let signers: Vec<&(dyn Signer + Sync)> = cosigner.iter().map(|keypair| keypair as _).collect();
    let signature = ctx.submit(merge, payer, &signers)?;
    ctx.wait_for_indexed(signature)?;
    let merged = ctx.spendable_utxos(&sender, &registry)?;
    ensure!(
        merged.utxos().any(|entry| entry.utxo_hash == output_hash),
        "the indexer did not reconstruct merged output {output_hash:?}"
    );
    line("merge", signature);
    line("inputs", input_count);
    line("amount", merged_amount);
    line("mint", mint);
    line("tree", tree);
    println!("merge preserves value and binds its ciphertext to registered auditor recovery");
    Ok(())
}

/// The smallest clean notes of the tree holding the most of them, at most `count`.
fn select(
    spendable: &SpendableDecryptionResult,
    ring: Address,
    mint: Address,
    count: usize,
) -> Result<Vec<WalletUtxo>> {
    let keep = |entry: &WalletUtxo| mergeable(entry, ring);
    select_merge_where(spendable.utxos(), mint, count, &HashSet::new(), keep).map_err(|_| {
        let mut trees = BTreeMap::<u16, usize>::new();
        for entry in spendable.utxos() {
            if entry.utxo.asset.asset == mint && keep(entry) {
                *trees.entry(entry.tree_id).or_default() += 1;
            }
        }
        let found = trees.into_values().max().unwrap_or(0);
        anyhow!("found only {found} mergeable notes for mint {mint} in ring {ring}")
    })
}

/// A ring deposit publishes the all-zero no-data hash as `Some`, it commits like an absent one.
/// A nonzero hash is ring state this generic command must not transition.
fn mergeable(entry: &WalletUtxo, ring: Address) -> bool {
    let data = &entry.utxo.data;
    entry.utxo.ring_program_id == Some(ring)
        && entry.data_hash.is_none()
        && entry.ring_data_hash.is_none_or(|hash| hash == [0; 32])
        && data.utxo_data().is_none()
        && data.ring_data().is_none_or(|data| data.is_empty())
        && data.memo().is_none()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use solana_signature::Signature;
    use zolana_transaction::{Data, DataRecord, Mint, Utxo};

    use super::*;
    use crate::wallet::fixtures::{
        self, inbox_tag, keypair, AnonymousTransfer, Indexer, Member, Paid, RingUtxo,
    };

    const RING: Address = Address::new_from_array([9; 32]);

    fn note(owner: &ShieldedKeypair, tree_id: u16, amount: u64, leaf_index: u64) -> WalletUtxo {
        WalletUtxo {
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount,
                blinding: [amount as u8; 32],
                ring_program_id: Some(RING),
                data: Data::default(),
            },
            nullifier_pubkey: [0u8; 32],
            utxo_hash: [leaf_index as u8; 32],
            nullifier: [leaf_index as u8; 32],
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index,
            latest_tree_id: None,
            slot: leaf_index,
            tx_signature: Signature::default(),
            slot_index: 0,
        }
    }

    #[test]
    fn selection_uses_one_tree_and_the_smallest_clean_notes() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let mut spendable = SpendableDecryptionResult::default();
        spendable.utxos_with_data.extend([
            note(&owner, 1, 30, 1),
            {
                let mut deposited = note(&owner, 1, 10, 2);
                deposited.ring_data_hash = Some([0; 32]);
                deposited.utxo.data = Data::new(vec![DataRecord::RingData(Vec::new())]);
                deposited
            },
            note(&owner, 1, 20, 3),
            note(&owner, 2, 1, 4),
        ]);
        let mut dirty = note(&owner, 1, 2, 5);
        dirty.ring_data_hash = Some([1; 32]);
        spendable.utxos_with_data.push(dirty);

        let selected = select(&spendable, RING, SOL_MINT, 2).expect("candidates");
        assert!(selected.iter().all(|entry| entry.tree_id == 1));
        assert_eq!(
            selected
                .iter()
                .map(|entry| entry.utxo.amount)
                .collect::<Vec<_>>(),
            vec![10, 20]
        );
    }

    #[test]
    fn one_note_is_not_a_merge() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let spendable = SpendableDecryptionResult {
            utxos_with_data: vec![note(&owner, 0, 10, 1)],
            ..Default::default()
        };
        let refused = select(&spendable, RING, SOL_MINT, 54).expect_err("one note");
        assert!(
            refused
                .to_string()
                .starts_with("found only 1 mergeable notes"),
            "{refused}"
        );
        let empty = SpendableDecryptionResult::default();
        let refused = select(&empty, RING, SOL_MINT, 2).expect_err("no note");
        assert!(refused
            .to_string()
            .starts_with("found only 0 mergeable notes"));
    }

    #[test]
    fn the_merge_scan_finds_an_anonymous_payment_and_anonymous_change() {
        let sender = Member::new(1, "merge-scan");
        let (bob, carol) = (keypair(2), keypair(3));
        let spent = RingUtxo::new(&sender.keys, 10);
        let paid = RingUtxo::new(&sender.keys, 7);
        let change = RingUtxo::new(&sender.keys, 6);
        let to_carol = RingUtxo::new(&carol, 4);
        let from_bob = AnonymousTransfer {
            payer: &bob,
            nullifiers: vec![[21; 32]],
            outputs: vec![Paid {
                to: &sender.keys,
                output: &spent,
                tag: inbox_tag(&sender.keys, 0),
            }],
        }
        .transaction();
        let from_carol = AnonymousTransfer {
            payer: &carol,
            nullifiers: vec![[22; 32]],
            outputs: vec![Paid {
                to: &sender.keys,
                output: &paid,
                tag: inbox_tag(&sender.keys, 1),
            }],
        }
        .transaction();
        let change_tag = sender
            .keys
            .viewing_key
            .ring_change_view_tag(&spent.nullifier, 1)
            .unwrap();
        let spend = AnonymousTransfer {
            payer: &sender.keys,
            nullifiers: vec![spent.nullifier],
            outputs: vec![
                Paid {
                    to: &carol,
                    output: &to_carol,
                    tag: inbox_tag(&carol, 0),
                },
                Paid {
                    to: &sender.keys,
                    output: &change,
                    tag: change_tag,
                },
            ],
        }
        .transaction();
        let indexer = Indexer(vec![from_bob, from_carol, spend]);

        let selected = select(&sender.scan(&indexer), fixtures::RING, SOL_MINT, 2).unwrap();
        let merged: BTreeSet<_> = selected.iter().map(|entry| entry.utxo_hash).collect();
        assert_eq!(merged, BTreeSet::from([paid.hash, change.hash]));
        let state = sender.store.load().unwrap();
        assert_eq!(state.issued_addresses(), 2);
        assert_eq!(state.known_counterparties.len(), 2);
    }
}
