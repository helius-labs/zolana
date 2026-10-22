//! Merge the persistent sender wallet's fragmented custom-ring notes.

use std::collections::{BTreeMap, HashSet};

use anyhow::{anyhow, ensure, Result};
use custom_ring_interface::ANONYMOUS_MERGE_WIDTHS;
use custom_ring_sdk::{CustomRingMerge, MergeProofInput, RingMergeOperation, RingMode};
use solana_address::Address;
use solana_signer::Signer;
use zolana_interface::pda;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{select_merge_where, SpendableDecryptionResult, WalletUtxo, SOL_MINT};

use crate::{
    assets,
    fund::MIN_AUTHORITY_BALANCE,
    line,
    member::KeyEnrolment,
    transact::{CoSigner, Demand},
    wallet::WalletScan,
    Context, MergeArgs,
};

pub fn run(ctx: &Context, args: MergeArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let registry = assets::resolve(ctx.rpc(), mint)?.registry;
    let cosigner = CoSigner::read(ctx, &args.cosigner)?;
    let merge_cosigner = cosigner.sign(&config, Demand::Transfer)?;
    let scan = || {
        WalletScan {
            keys: &sender,
            registry: &registry,
            config: &config,
        }
        .fetch(ctx)
    };
    println!("reading the sender's notes");
    let spendable = scan()?;
    if !spendable.unknown_asset_ids.is_empty() {
        line("unregistered asset ids", spendable.unknown_asset_ids.len());
    }
    if !spendable.unknown_mints.is_empty() {
        line("unregistered mints", spendable.unknown_mints.len());
    }
    let count = match config.mode {
        RingMode::Anonymous => (args.count as usize).min(widest_anonymous_merge()),
        RingMode::Off | RingMode::Registry => args.count as usize,
    };
    let selected = select(&spendable, ctx.ring.program_id(), mint, count)?;
    let (input_count, tree_id) = (selected.len(), selected[0].tree_id);
    let tree = pda::tree(tree_id);
    let prepared = CustomRingMerge::new(ctx.ring, selected, None)?
        .with_output_tree_id(tree_id)
        .encrypt(&sender)?;
    let (output_hash, merged_amount) = (prepared.output().hash(tree_id)?, prepared.output().amount);
    let merge = RingMergeOperation::new(
        prepared,
        MergeProofInput {
            nullifier_key: sender.nullifier_key.clone(),
            input_tree: tree,
            output_tree: tree,
        },
    );
    let payer = ctx.member_payer(config.mode, sender.pubkey())?;
    ctx.fund(payer.pubkey(), MIN_AUTHORITY_BALANCE)?;
    // The merge proves the owner's escrowed key.
    if config.mode != RingMode::Anonymous {
        KeyEnrolment {
            funder: payer,
            members: &[&sender],
        }
        .ensure(ctx)?;
    }
    let signature = ctx.submit(merge, payer, merge_cosigner.as_slice())?;
    ctx.wait_for_indexed(signature)?;
    let merged = scan()?;
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

fn widest_anonymous_merge() -> usize {
    ANONYMOUS_MERGE_WIDTHS.into_iter().max().unwrap_or_default()
}

/// The smallest clean notes of the tree holding the most of them, at most `count`.
fn select(
    spendable: &SpendableDecryptionResult,
    ring: Address,
    mint: Address,
    count: usize,
) -> Result<Vec<WalletUtxo>> {
    let keep =
        |entry: &WalletUtxo| entry.utxo.ring_program_id == Some(ring) && carries_no_data(entry);
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

/// A deposit's all-zero ring data hash commits like none, any other is ring state left unspent.
pub(crate) fn carries_no_data(entry: &WalletUtxo) -> bool {
    let data = &entry.utxo.data;
    entry.data_hash.is_none()
        && entry.ring_data_hash.is_none_or(|hash| hash == [0; 32])
        && data.utxo_data().is_none()
        && data.ring_data().is_none_or(|data| data.is_empty())
        && data.memo().is_none()
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;
    use zolana_transaction::{Data, DataRecord, Mint, Utxo};

    use super::*;

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
}
