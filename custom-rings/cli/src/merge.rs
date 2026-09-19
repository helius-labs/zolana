//! Merge the persistent sender wallet's fragmented custom-ring notes.

use std::{collections::BTreeMap, path::Path};

use custom_ring_sdk::{
    CustomRing, CustomRingMerge, CustomRingMergeProofEnvironment, MAX_MERGE_INPUTS,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_interface::{pda, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::{KeypairError, ShieldedKeypair};
use zolana_transaction::{AssetRegistry, TransactionError, WalletUtxo, SOL_MINT};
use zolana_wallet::{sync_wallet, Wallet};

use crate::{
    file::{self, FileError},
    line,
    transact::{wait_for_indexed_transaction, WaitError},
    Context, ContextError, MergeArgs, SENDER_KEYPAIR_FILE,
};

const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

#[derive(Debug, Error)]
pub enum MergeError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    Indexer(#[from] WaitError<ClientError>),
    #[error("merge count must be from 2 through {MAX_MERGE_INPUTS}, got {0}")]
    Count(usize),
    #[error("found only {found} mergeable notes for mint {mint} in ring {ring}")]
    InsufficientNotes {
        mint: Address,
        ring: Address,
        found: usize,
    },
    #[error("mint {0} is not registered with SPP")]
    AssetNotRegistered(Address),
    #[error("mint {0} has an invalid SPP asset registry account")]
    InvalidAssetRegistry(Address),
    #[error("the indexer did not reconstruct merged output {0:?}")]
    OutputNotFound([u8; 32]),
}

pub fn run(ctx: &mut Context, args: MergeArgs) -> Result<(), MergeError> {
    if !(2..=MAX_MERGE_INPUTS).contains(&args.count) {
        return Err(MergeError::Count(args.count));
    }

    let payer = ctx.funded_authority()?;
    let sender = sender_keypair(ctx)?;
    let indexer = ctx.indexer();
    let mint = args.mint.unwrap_or(SOL_MINT);
    let registry = asset_registry(&ctx.rpc, mint)?;
    // Tree 0 to start with; `sync_wallet` backfills the registry from chain if a
    // note turns up in a tree this one does not name.
    let mut wallet = Wallet::new(sender.shielded_address()?, registry)?;

    println!("syncing the sender wallet");
    sync_wallet(&mut wallet, &sender, &indexer)?;
    let (tree, selected) = select_candidates(&wallet, ctx.ring, mint, args.count).ok_or(
        MergeError::InsufficientNotes {
            mint,
            ring: ctx.ring.program_id(),
            found: largest_candidate_group(&wallet, ctx.ring, mint),
        },
    )?;
    let input_count = selected.len();
    let output_tree_id = selected.first().expect("selected merge group").tree_id;
    let inputs = selected.into_iter().cloned().collect();
    let prepared = CustomRingMerge::new(ctx.ring, inputs, None)?
        .with_output_tree_id(output_tree_id)
        .encrypt(&sender)?;
    let proven = prepared.prove(
        sender.nullifier_key.clone(),
        tree,
        CustomRingMergeProofEnvironment {
            indexer: &indexer,
            prover: &ctx.prover(),
        },
    )?;
    let output_hash = proven.output_hash;
    let merged_amount = proven.merged_amount;
    let merge = proven.instruction(tree, tree, payer.pubkey());
    let signature = ctx.rpc.create_and_send_transaction(
        &[merge],
        payer.pubkey(),
        &[&payer],
        ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
    )?;

    wait_for_indexed_transaction(&indexer, signature)?;
    sync_wallet(&mut wallet, &sender, &indexer)?;
    if !wallet.unspent().any(|entry| entry.utxo_hash == output_hash) {
        return Err(MergeError::OutputNotFound(output_hash));
    }

    line("merge", signature);
    line("inputs", input_count);
    line("amount", merged_amount);
    line("mint", mint);
    line("tree", tree);
    println!("merge is value-preserving and has no auditor ciphertext");
    Ok(())
}

fn sender_keypair(ctx: &Context) -> Result<ShieldedKeypair, MergeError> {
    let path = ctx.project_path(Path::new(SENDER_KEYPAIR_FILE));
    let keypair = file::read_or_create_keypair(&path)?;
    Ok(ShieldedKeypair::from_keypair(&keypair)?)
}

fn asset_registry(rpc: &SolanaRpc, mint: Address) -> Result<AssetRegistry, MergeError> {
    if mint == SOL_MINT {
        return Ok(AssetRegistry::default());
    }
    let address = pda::spl_asset_registry(&mint);
    let account = rpc
        .get_account(address)?
        .ok_or(MergeError::AssetNotRegistered(mint))?;
    let expected_owner = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let record = SplAssetRegistry::from_account_bytes(&account.data)
        .map_err(|_| MergeError::InvalidAssetRegistry(mint))?;
    if account.owner != expected_owner || record.mint != mint {
        return Err(MergeError::InvalidAssetRegistry(mint));
    }
    Ok(AssetRegistry::new([(record.asset_id, record.mint)])?)
}

fn candidate_groups(
    wallet: &Wallet,
    ring: CustomRing,
    mint: Address,
) -> BTreeMap<Address, Vec<&WalletUtxo>> {
    let mut groups: BTreeMap<Address, Vec<&WalletUtxo>> = BTreeMap::new();
    for entry in wallet.unspent() {
        if entry.utxo.asset.asset != mint
            || entry.utxo.ring_program_id != Some(ring.program_id())
            || entry.data_hash.is_some()
            // Ring deposits publish the protocol's all-zero "no data" hash as
            // `Some`, although it commits identically to an absent hash. A
            // non-zero hash is real ring state and this generic command must
            // not choose how to transition it.
            || entry
                .ring_data_hash
                .is_some_and(|hash| hash != [0u8; 32])
            || entry.utxo.data.utxo_data().is_some()
            || entry
                .utxo
                .data
                .ring_data()
                .is_some_and(|data| !data.is_empty())
            || entry.utxo.data.memo().is_some()
        {
            continue;
        }
        groups
            .entry(pda::tree(entry.tree_id))
            .or_default()
            .push(entry);
    }
    for entries in groups.values_mut() {
        entries.sort_by_key(|entry| (entry.utxo.amount, entry.leaf_index));
    }
    groups
}

fn largest_candidate_group(wallet: &Wallet, ring: CustomRing, mint: Address) -> usize {
    candidate_groups(wallet, ring, mint)
        .values()
        .map(Vec::len)
        .max()
        .unwrap_or(0)
}

fn select_candidates(
    wallet: &Wallet,
    ring: CustomRing,
    mint: Address,
    limit: usize,
) -> Option<(Address, Vec<&WalletUtxo>)> {
    candidate_groups(wallet, ring, mint)
        .into_iter()
        .filter(|(_, entries)| entries.len() >= 2)
        .max_by_key(|(tree, entries)| (entries.len(), *tree))
        .map(|(tree, mut entries)| {
            entries.truncate(limit);
            (tree, entries)
        })
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;
    use zolana_interface::pda;
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, DataRecord, Mint, Utxo};

    use super::*;

    fn note(
        owner: &ShieldedKeypair,
        ring: CustomRing,
        tree_id: u16,
        amount: u64,
        leaf_index: u64,
    ) -> WalletUtxo {
        WalletUtxo {
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount,
                blinding: [amount as u8; 32],
                ring_program_id: Some(ring.program_id()),
                data: Data::default(),
            },
            nullifier_pubkey: [0u8; 32],
            utxo_hash: [leaf_index as u8; 32],
            nullifier: [leaf_index as u8; 32],
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index,
            slot: leaf_index,
            tx_signature: Signature::default(),
            slot_index: 0,
        }
    }

    #[test]
    fn selection_uses_one_tree_and_the_smallest_clean_notes() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let ring = CustomRing::new(Address::new_from_array([9; 32]));
        let tree = pda::tree(1);
        let mut wallet = Wallet::new(
            owner.shielded_address().expect("address"),
            Default::default(),
        )
        .expect("wallet");
        wallet.utxos.extend([
            note(&owner, ring, 1, 30, 1),
            {
                let mut deposited = note(&owner, ring, 1, 10, 2);
                deposited.ring_data_hash = Some([0; 32]);
                deposited.utxo.data = Data::new(vec![DataRecord::RingData(Vec::new())]);
                deposited
            },
            note(&owner, ring, 1, 20, 3),
            note(&owner, ring, 2, 1, 4),
        ]);
        let mut dirty = note(&owner, ring, 1, 2, 5);
        dirty.ring_data_hash = Some([1; 32]);
        wallet.utxos.push(dirty);

        let (selected_tree, selected) =
            select_candidates(&wallet, ring, SOL_MINT, 2).expect("candidates");

        assert_eq!(selected_tree, tree);
        assert_eq!(
            selected
                .into_iter()
                .map(|entry| entry.utxo.amount)
                .collect::<Vec<_>>(),
            vec![10, 20]
        );
    }

    #[test]
    fn one_note_is_not_a_merge() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let ring = CustomRing::new(Address::new_from_array([9; 32]));
        let mut wallet = Wallet::new(
            owner.shielded_address().expect("address"),
            Default::default(),
        )
        .expect("wallet");
        wallet.utxos.push(note(&owner, ring, 0, 10, 1));

        assert!(select_candidates(&wallet, ring, SOL_MINT, MAX_MERGE_INPUTS).is_none());
        assert_eq!(largest_candidate_group(&wallet, ring, SOL_MINT), 1);
    }
}
