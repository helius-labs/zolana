use anyhow::Result;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaClient};
use zolana_transaction::Address;
use zolana_wallet::{
    create_merge, create_split, create_transfer_sync, sign_private_transaction_sync,
    submit_merge_transaction, MergeParams, SplitParams, SubmitMergeTransaction, TransferParams,
};

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::{sync_context, wait_for_indexed_leaf},
    util::{ensure_positive, format_address, parse_address, parse_hex_array, parse_pubkey},
};
use crate::args::{MergeOptions, SplitOptions, TransferOptions, UtxosOptions};

pub(crate) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = ZolanaClient::from_urls(
        rpc,
        network.sync.indexer_url.clone(),
        network.prover_url.clone(),
        Address::new_from_array(network.tree.to_bytes()),
    );
    let recipient = parse_pubkey(&opts.to)?;

    let transfer = create_transfer_sync(TransferParams {
        rpc: &client,
        wallet: &ctx.wallet,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient,
        asset,
        amount: opts.amount,
    })?;
    let transaction = sign_private_transaction_sync(
        transfer.transaction,
        &ctx.wallet,
        &ctx.material,
        &client,
        &ctx.material.funding,
    )?;
    let signature = client.rpc().send_transaction(&transaction)?;
    client.confirm_private_transaction_sync(signature)?;
    let mode = if transfer.recipient.is_public_withdrawal() {
        "withdraw"
    } else {
        "shielded"
    };
    println!(
        "ok transfer amount={} mint={} to={} mode={} signature={}",
        opts.amount,
        format_address(asset),
        transfer.recipient.pubkey(),
        mode,
        signature
    );
    Ok(())
}

/// List the wallet's spendable notes for one asset. The printed hashes are the
/// `--input` values for `wallet split` / `wallet merge`; `kind` flags which
/// notes those actions accept (only `plain` notes can be split or merged).
pub(crate) fn run_utxos(opts: UtxosOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let ctx = sync_context(&opts.sync)?;
    let mut count = 0usize;
    for entry in ctx
        .wallet
        .utxos
        .iter()
        .filter(|entry| !entry.spent && entry.utxo.asset == asset)
    {
        count += 1;
        let kind = if entry.utxo.zone_program_id.is_some() {
            "zone"
        } else if entry.data_hash.is_some() || entry.zone_data_hash.is_some() {
            "data"
        } else {
            "plain"
        };
        println!(
            "ok utxo hash={} amount={} mint={} kind={}",
            hex::encode(entry.output_context.hash),
            entry.utxo.amount,
            format_address(asset),
            kind
        );
    }
    println!("ok utxos mint={} count={count}", format_address(asset));
    Ok(())
}

pub(crate) fn run_split(opts: SplitOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = ZolanaClient::from_urls(
        rpc,
        network.sync.indexer_url.clone(),
        network.prover_url.clone(),
        Address::new_from_array(network.tree.to_bytes()),
    );
    let input = opts
        .input
        .as_deref()
        .map(parse_hex_array::<32>)
        .transpose()?;

    let split = create_split(SplitParams {
        wallet: &ctx.wallet,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        asset,
        parts: opts.parts,
        input,
    })?;
    let parts = split.num_outputs;
    let per_output = split.per_output_amount;
    let transaction = sign_private_transaction_sync(
        split.transaction,
        &ctx.wallet,
        &ctx.material,
        &client,
        &ctx.material.funding,
    )?;
    let signature = client.rpc().send_transaction(&transaction)?;
    client.confirm_private_transaction_sync(signature)?;
    println!(
        "ok split parts={} amount={} mint={} signature={}",
        parts,
        per_output,
        format_address(asset),
        signature
    );
    Ok(())
}

pub(crate) fn run_merge(opts: MergeOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;

    // No `--input` auto-sweeps the smallest plain notes; explicit hashes name the
    // exact notes to consolidate.
    let inputs = if opts.input.is_empty() {
        None
    } else {
        Some(
            opts.input
                .iter()
                .map(|hash| parse_hex_array::<32>(hash))
                .collect::<Result<Vec<_>>>()?,
        )
    };

    let created = create_merge(MergeParams {
        wallet: &ctx.wallet,
        keypair: &ctx.material.keypair,
        asset,
        inputs,
    })?;
    let num_inputs = created.num_inputs;
    let merged_amount = created.merged_amount;
    let tree = created.tree;

    // Bind the client (and its indexer) to the resolved spend tree so input Merkle
    // proofs and the appended-output lookup query the right tree.
    let client = ZolanaClient::from_urls(
        rpc,
        network.sync.indexer_url.clone(),
        network.prover_url.clone(),
        Address::new_from_array(tree.to_bytes()),
    );
    let submitted = submit_merge_transaction(SubmitMergeTransaction {
        rpc: &client,
        indexer: &client,
        owner: ctx.material.funding.pubkey(),
        payer: &ctx.material.funding,
        keypair: &ctx.material.keypair,
        tree: Pubkey::new_from_array(tree.to_bytes()),
        prover_url: &network.prover_url,
        prepared: created.prepared,
    })?;
    // `merge_transact` output is off the view-tag confirmation path, so wait for
    // the consolidated leaf before returning.
    wait_for_indexed_leaf(
        &client,
        Address::new_from_array(tree.to_bytes()),
        submitted.output_hash,
    )?;

    println!(
        "ok merge inputs={} amount={} mint={} signature={}",
        num_inputs,
        merged_amount,
        format_address(asset),
        submitted.signature
    );
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
