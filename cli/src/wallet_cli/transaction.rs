use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_merge, create_split_sync, create_transfer_sync, fetch_user_record_checked,
    submit_merge_transaction as submit_merge_action,
    submit_private_transaction as submit_private_action, validate_registered_keypair, ClientError,
    CreateMerge, CreateSplit, CreateTransfer, InputSelection, PreparedMerge, SignedTransaction,
    SolanaRpc, SubmitMergeTransaction as ClientSubmitMergeTransaction,
    SubmitPrivateTransaction as ClientSubmitPrivateTransaction, ZolanaIndexer,
};
use zolana_interface::instruction::TransactWithdrawal;
use zolana_transaction::{Address, SOL_MINT};

use super::{
    material::WalletMaterial,
    resolve::get_network_with_config,
    sync::{sync_context, sync_context_with_config, wait_for_indexed_output, WaitOutcome},
    util::{
        ensure_positive, format_address, lamports_to_sol_string, parse_address,
        parse_amount_for_asset, parse_hex_array, parse_shielded_address,
    },
};

use crate::{
    args::{ConsolidateOptions, SplitOptions, TransferOptions, UtxosOptions},
    cli_config::CliConfigFile,
};

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let amount = parse_amount_for_asset(&opts.amount, asset)?;
    ensure_positive(amount)?;
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let recipient = parse_shielded_address(&opts.to)?;
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context_with_config(&opts.network.sync, &config)?;
    let tree = network.tree;

    let result: Result<()> = (|| {
        let selection = resolve_transfer_selection(&opts)?;
        let transfer = create_transfer_sync(CreateTransfer {
            wallet: &ctx.wallet,
            authority: &ctx.material,
            owner_pubkey: ctx.material.owner_pubkey(),
            payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
            recipient,
            asset,
            amount,
            assets: &ctx.wallet.registry,
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
    })();

    match result {
        Ok(()) => Ok(()),
        Err(err) if is_fragmented_balance(&err) => {
            bail!(
                "balance for {} is spread across too many notes to send in one transfer; run `zolana wallet consolidate` first, then retry",
                format_address(asset)
            )
        }
        Err(err) => Err(err),
    }
}

/// Whether an error is a surfaced [`ClientError::FragmentedBalance`].
fn is_fragmented_balance(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<ClientError>(),
        Some(ClientError::FragmentedBalance { .. })
    )
}

fn resolve_transfer_selection(opts: &TransferOptions) -> Result<InputSelection> {
    if let Some(input) = &opts.input {
        let hash = parse_hex_array::<32>(input)?;
        return Ok(InputSelection::Explicit(vec![hash]));
    }

    Ok(InputSelection::Auto)
}

fn resolve_merge_selection(explicit_hashes: &[[u8; 32]]) -> InputSelection {
    if explicit_hashes.is_empty() {
        InputSelection::Auto
    } else {
        InputSelection::Explicit(explicit_hashes.to_vec())
    }
}

pub(super) fn run_split(opts: SplitOptions) -> Result<()> {
    // `parts` is constrained to 2..=8 at the arg boundary (clap `value_parser`).
    let parts = opts.parts;
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context_with_config(&opts.network.sync, &config)?;
    let tree = network.tree;

    // A split rides the SOL note rail. Pick the note to split and derive the
    // per-part amount.
    let (selection, per_output_amount, total_amount) = split_selection(&opts, &ctx, parts)?;

    let split = create_split_sync(CreateSplit {
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        asset: SOL_MINT,
        num_outputs: parts,
        per_output_amount,
        assets: &ctx.wallet.registry,
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
            wait_output_hash: split.wait_output_hash,
        },
        split.signed,
    )?;
    println!(
        "ok split parts={} amount={} signature={}{}",
        parts,
        lamports_to_sol_string(total_amount),
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

/// Resolve which SOL note a split spends: `--input <hash>` names the exact note,
/// otherwise the largest note is chosen. Returns the selection, the per-part
/// amount, and the note's total (the amount fanned out across all parts).
fn split_selection(
    opts: &SplitOptions,
    ctx: &super::sync::SyncContext,
    parts: u8,
) -> Result<(InputSelection, u64, u64)> {
    let notes = ctx.wallet.spendable_utxos(SOL_MINT);
    if notes.is_empty() {
        bail!("wallet has no spendable SOL notes to split");
    }

    let note = match &opts.input {
        Some(input) => {
            let hash = parse_hex_array::<32>(input)?;
            notes
                .iter()
                .find(|note| note.hash == hash)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("no spendable SOL note with hash {input}; run `wallet utxos`")
                })?
        }
        None => notes
            .iter()
            .max_by_key(|note| note.amount)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("wallet has no spendable SOL notes to split"))?,
    };

    if note.amount % u64::from(parts) != 0 {
        bail!(
            "note of {} SOL does not divide evenly into {parts} parts",
            lamports_to_sol_string(note.amount)
        );
    }
    let per_output_amount = note.amount / u64::from(parts);
    ensure_positive(per_output_amount)?;

    Ok((
        InputSelection::Explicit(vec![note.hash]),
        per_output_amount,
        note.amount,
    ))
}

pub(super) fn run_utxos(opts: UtxosOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let ctx = sync_context(&opts.sync)?;
    let notes = ctx.wallet.spendable_utxos(asset);
    for note in &notes {
        if asset == SOL_MINT {
            println!(
                "ok utxo hash={} mint=SOL sol={} amount={}",
                hex::encode(note.hash),
                lamports_to_sol_string(note.amount),
                note.amount
            );
        } else {
            println!(
                "ok utxo hash={} mint={} amount={}",
                hex::encode(note.hash),
                format_address(asset),
                note.amount
            );
        }
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
    /// Committed output hash to wait on for indexing.
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

pub(super) struct SubmitMergeTx<'a> {
    pub(super) rpc: &'a SolanaRpc,
    pub(super) indexer: &'a ZolanaIndexer,
    pub(super) material: &'a WalletMaterial,
    pub(super) tree: Pubkey,
    pub(super) prover_url: &'a str,
}

/// Prove and submit a consolidation (`merge_transact`), returning the signature
/// and the merged output's committed hash (the wait target). The merge always
/// rides the P256/BSB22 rail, so the proof carries a commitment packed into the
/// fixed 192-byte `merge_transact` layout.
pub(super) fn submit_merge_transaction(
    request: SubmitMergeTx<'_>,
    prepared: PreparedMerge,
) -> Result<(Signature, [u8; 32], WaitOutcome)> {
    let submitted = submit_merge_action(ClientSubmitMergeTransaction {
        rpc: request.rpc,
        indexer: request.indexer,
        funding: &request.material.funding,
        nullifier_key: &request.material.keypair.nullifier_key,
        tree: request.tree,
        prover_url: request.prover_url,
        prepared,
    })?;
    let outcome = wait_for_indexed_output(
        request.indexer,
        request.rpc,
        request.tree,
        submitted.output_hash,
        submitted.signature,
    )?;
    Ok((submitted.signature, submitted.output_hash, outcome))
}

pub(super) fn run_consolidate(opts: ConsolidateOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context_with_config(&opts.network.sync, &config)?;
    ensure_merging_enabled(&rpc, &ctx.material)?;
    let tree = network.tree;

    let explicit_hashes = opts
        .input
        .iter()
        .map(|input| parse_hex_array::<32>(input))
        .collect::<Result<Vec<_>>>()?;
    let selection = resolve_merge_selection(&explicit_hashes);

    let merge = create_merge(CreateMerge {
        wallet: &ctx.wallet,
        keypair: &ctx.material.keypair,
        asset,
        selection,
    })?;
    let num_inputs = merge.num_inputs;
    let merged_amount = merge.merged_amount;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let (signature, _output_hash, outcome) = submit_merge_transaction(
        SubmitMergeTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
        },
        merge.prepared,
    )?;
    println!(
        "ok consolidate asset={} inputs={} merged_amount={} signature={}{}",
        format_address(asset),
        num_inputs,
        merged_amount,
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

fn ensure_merging_enabled(rpc: &SolanaRpc, material: &WalletMaterial) -> Result<()> {
    let owner = material.funding.pubkey();
    validate_registered_keypair(rpc, owner, &material.keypair)?;
    let record = fetch_user_record_checked(rpc, owner)?;
    if !record.merging_enabled {
        bail!(
            "merging is not enabled for this wallet; run `zolana wallet set-merging on` first \
             (merge_transact requires the owner to opt in)"
        );
    }
    Ok(())
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
