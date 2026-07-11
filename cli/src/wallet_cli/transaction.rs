use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_merge, create_split_sync, create_transfer_sync, fetch_user_record_checked,
    submit_merge_transaction as submit_merge_action,
    submit_private_transaction as submit_private_action, validate_registered_keypair, CreateMerge,
    CreateSplit, CreateTransfer, InputSelection, SignedTransaction, SolanaRpc,
    SubmitMergeTransaction as ClientSubmitMergeTransaction,
    SubmitPrivateTransaction as ClientSubmitPrivateTransaction, ZolanaIndexer,
};
use zolana_interface::instruction::TransactWithdrawal;
use zolana_transaction::{Address, SpendableUtxo, SOL_MINT};

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::{sync_context, wait_for_indexed_output, WaitOutcome},
    util::{
        ensure_positive, format_address, parse_address, parse_hex_array, parse_shielded_address,
    },
};
use crate::args::{ConsolidateOptions, SplitOptions, TransferOptions, UtxosOptions};

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let recipient = parse_shielded_address(&opts.to)?;
    let selection = resolve_transfer_selection(&opts)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    let tree = network.tree;

    let transfer = create_transfer_sync(CreateTransfer {
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
        selection,
    })?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let (signature, outcome) = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
            withdrawal: None,
            wait_output_hash: transfer.wait_output_hash,
        },
        transfer.signed,
    )?;
    println!(
        "ok transfer amount={} mint={} to={} mode=shielded signature={}{}",
        opts.amount,
        format_address(asset),
        transfer.recipient,
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

fn resolve_transfer_selection(opts: &TransferOptions) -> Result<InputSelection> {
    match &opts.input {
        Some(input) => Ok(InputSelection::Explicit(vec![parse_hex_array::<32>(
            input,
        )?])),
        None => Ok(InputSelection::Auto),
    }
}

pub(super) fn run_split(opts: SplitOptions) -> Result<()> {
    let explicit_hash = opts
        .input
        .as_deref()
        .map(parse_hex_array::<32>)
        .transpose()?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    let (note, per_output_amount) = split_selection(
        &ctx.wallet.spendable_utxos(SOL_MINT),
        opts.parts,
        explicit_hash,
    )?;

    let split = create_split_sync(CreateSplit {
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        asset: SOL_MINT,
        num_outputs: opts.parts,
        per_output_amount,
        selection: InputSelection::Explicit(vec![note.hash]),
    })?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let (signature, outcome) = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree: network.tree,
            prover_url: &network.prover_url,
            withdrawal: None,
            wait_output_hash: split.wait_output_hash,
        },
        split.signed,
    )?;
    println!(
        "ok split parts={} amount={} signature={}{}",
        opts.parts,
        note.amount,
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

fn split_selection(
    notes: &[SpendableUtxo],
    parts: u8,
    explicit_hash: Option<[u8; 32]>,
) -> Result<(SpendableUtxo, u64)> {
    let note = match explicit_hash {
        Some(hash) => notes
            .iter()
            .find(|note| note.hash == hash)
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no spendable SOL note with hash {}; run `wallet utxos --mint SOL`",
                    hex::encode(hash)
                )
            })?,
        None => notes
            .iter()
            .max_by_key(|note| note.amount)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("wallet has no spendable SOL notes to split"))?,
    };
    if note.amount % u64::from(parts) != 0 {
        bail!(
            "note amount {} does not divide evenly into {parts} parts",
            note.amount
        );
    }
    let per_output_amount = note.amount / u64::from(parts);
    ensure_positive(per_output_amount)?;
    Ok((note, per_output_amount))
}

pub(super) fn run_consolidate(opts: ConsolidateOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let explicit_hashes = opts
        .input
        .iter()
        .map(|input| parse_hex_array::<32>(input))
        .collect::<Result<Vec<_>>>()?;
    if !explicit_hashes.is_empty() && !(2..=8).contains(&explicit_hashes.len()) {
        bail!(
            "explicit consolidation requires 2 to 8 --input values; got {}",
            explicit_hashes.len()
        );
    }

    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    let selection = if explicit_hashes.is_empty() {
        InputSelection::Auto
    } else {
        InputSelection::Explicit(explicit_hashes)
    };
    let merge = create_merge(CreateMerge {
        wallet: &ctx.wallet,
        keypair: &ctx.material.keypair,
        asset,
        selection,
    })?;

    ensure_merging_enabled(&rpc, &ctx.material)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let submitted = submit_merge_action(ClientSubmitMergeTransaction {
        rpc: &rpc,
        indexer: &indexer,
        owner: ctx.material.funding.pubkey(),
        payer: &ctx.material.funding,
        nullifier_key: &ctx.material.keypair.nullifier_key,
        tree: network.tree,
        prover_url: &network.prover_url,
        prepared: merge.prepared,
    })?;
    let outcome = wait_for_indexed_output(
        &indexer,
        &rpc,
        network.tree,
        submitted.output_hash,
        submitted.signature,
    )?;
    println!(
        "ok consolidate mint={} inputs={} amount={} signature={}{}",
        format_address(asset),
        merge.num_inputs,
        merge.merged_amount,
        submitted.signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

fn ensure_merging_enabled(rpc: &SolanaRpc, material: &WalletMaterial) -> Result<()> {
    let owner = material.funding.pubkey();
    let record = fetch_user_record_checked(rpc, owner)?;
    if !record.merging_enabled {
        bail!("merging is not enabled for this wallet; run `zolana wallet set-merging on` first");
    }
    validate_registered_keypair(rpc, owner, &material.keypair)?;
    Ok(())
}

pub(super) fn run_utxos(opts: UtxosOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let ctx = sync_context(&opts.sync)?;
    let notes = ctx.wallet.spendable_utxos(asset);
    for note in &notes {
        println!(
            "ok utxo hash={} mint={} amount={}",
            hex::encode(note.hash),
            format_address(asset),
            note.amount
        );
    }
    println!(
        "ok utxos mint={} count={}",
        format_address(asset),
        notes.len()
    );
    Ok(())
}

pub(super) struct SubmitPrivateTx<'a> {
    pub(super) rpc: &'a SolanaRpc,
    pub(super) indexer: &'a ZolanaIndexer,
    pub(super) material: &'a WalletMaterial,
    pub(super) tree: Pubkey,
    pub(super) prover_url: &'a str,
    pub(super) withdrawal: Option<TransactWithdrawal>,
    pub(super) wait_output_hash: [u8; 32],
}

pub(super) fn submit_private_transaction(
    request: SubmitPrivateTx<'_>,
    signed: SignedTransaction,
) -> Result<(Signature, WaitOutcome)> {
    let signature = submit_private_action(ClientSubmitPrivateTransaction {
        rpc: request.rpc,
        indexer: request.indexer,
        funding: &request.material.funding,
        tree: request.tree,
        prover_url: request.prover_url,
        withdrawal: request.withdrawal,
        signed,
    })?;
    let outcome = wait_for_indexed_output(
        request.indexer,
        request.rpc,
        request.tree,
        request.wait_output_hash,
        signature,
    )?;
    Ok((signature, outcome))
}

pub(super) fn maybe_airdrop(
    rpc: &mut SolanaRpc,
    material: &WalletMaterial,
    lamports: Option<u64>,
) -> Result<()> {
    let Some(lamports) = lamports else {
        return Ok(());
    };
    let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
    println!("ok airdrop signature={signature}");
    Ok(())
}
