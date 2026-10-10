use std::collections::HashSet;

use anyhow::{bail, Result};
use solana_signer::Signer;
use zolana_client::{
    check_service_url, indexer::ZolanaIndexer, prover::ProverClient,
    user_registry::try_resolve_registered_address, MergeSubmission, Rpc, SolanaRpc, ZolanaClient,
};
use zolana_interface::shape::Shape;
use zolana_transaction::{
    instructions::{
        merge::{MergeTransaction, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
        transact::ConfidentialTransaction,
    },
    select_merge, select_spend, Address, WalletUtxo, SOL_MINT,
};

use super::{
    material::WalletMaterial,
    resolve::{get_network, ResolvedNetworkOptions},
    spend::{send_private, Send},
    sync::{sync_context, sync_rpc, SyncContext},
    util::{
        ensure_positive, format_address, parse_address, parse_hex_array, parse_pubkey,
        resolve_spl_token_program,
    },
};
use crate::args::{MergeOptions, SplitOptions, TransferOptions, UtxosOptions};

pub(super) fn client(
    rpc: SolanaRpc,
    network: &ResolvedNetworkOptions,
) -> Result<ZolanaClient<SolanaRpc>> {
    let Some(policy) = &network.prover_tee else {
        return Ok(ZolanaClient::from_urls(
            rpc,
            &network.sync.indexer_url,
            network.prover_url.clone(),
        )?);
    };
    // The policy is the prover client's, so the client is built around one
    // that carries it; the transport check `from_urls` runs still runs.
    check_service_url(&network.sync.indexer_url, "indexer_url")?;
    check_service_url(&network.prover_url, "prover_url")?;
    let prover = ProverClient::new(network.prover_url.clone()).with_tee(policy.clone());
    Ok(ZolanaClient::new(
        rpc,
        ZolanaIndexer::new(&network.sync.indexer_url),
        prover,
    ))
}

/// Send privately to `--to`'s registered shielded address. An account without
/// one is paid by a public withdrawal instead.
pub(crate) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync, &rpc)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = client(rpc, &network)?;
    let recipient = parse_pubkey(&opts.to)?;

    let inputs = select_spend(ctx.spendable.utxos(), asset, opts.amount)?;
    let mut transaction = ConfidentialTransaction::new(inputs, payer(&ctx))?;
    let (mode, settlement_transfers) = match try_resolve_registered_address(&client, recipient)? {
        Some(registered) => {
            if asset == SOL_MINT {
                transaction.transfer_sol(&registered.address, opts.amount)?;
            } else {
                transaction.transfer(&registered.address, asset, opts.amount)?;
            }
            ("shielded", Vec::new())
        }
        None => {
            let spl_token_program = spl_token_program(&client, asset)?;
            let settlement =
                transaction.withdraw_to(asset, opts.amount, recipient, spl_token_program)?;
            ("withdraw", vec![settlement])
        }
    };
    let signature = send_private(&ctx, &client, transaction, settlement_transfers, Send::Fast)?;
    println!(
        "ok transfer amount={} mint={} to={} mode={} signature={}",
        opts.amount,
        format_address(asset),
        recipient,
        mode,
        signature
    );
    Ok(())
}

/// List the wallet's spendable utxos for one asset. The printed hashes are the
/// `--input` values for `wallet split` / `wallet merge`; `kind` flags which
/// utxos those actions accept (only `plain` utxos can be split or merged).
pub(crate) fn run_utxos(opts: UtxosOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let ctx = sync_context(&opts.sync, &sync_rpc(&opts.sync)?)?;
    let mut count = 0usize;
    for entry in ctx
        .spendable
        .utxos()
        .filter(|entry| entry.utxo.asset.asset == asset)
    {
        count += 1;
        let kind = if !entry.is_default_ring_spendable() {
            "ring"
        } else if !entry.is_plain() {
            "data"
        } else {
            "plain"
        };
        println!(
            "ok utxo hash={} amount={} mint={} kind={}",
            hex::encode(entry.utxo_hash),
            entry.utxo.amount,
            format_address(asset),
            kind
        );
    }
    println!("ok utxos mint={} count={count}", format_address(asset));
    Ok(())
}

/// Spend one plain utxo into `--parts` equal self-owned utxos.
pub(crate) fn run_split(opts: SplitOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync, &rpc)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = client(rpc, &network)?;
    let max_parts = Shape::IN1_OUT16.n_outputs() as u8;
    if !(2..=max_parts).contains(&opts.parts) {
        bail!("--parts must be between 2 and {max_parts}");
    }
    let input = opts
        .input
        .as_deref()
        .map(parse_hex_array::<32>)
        .transpose()?;
    let input = split_input(&ctx, asset, opts.parts, input)?;
    let per_output = input.utxo.amount / u64::from(opts.parts);

    let address = ctx.material.keypair.shielded_address()?;
    let mut transaction = ConfidentialTransaction::new(vec![input], payer(&ctx))?;
    for _ in 0..opts.parts {
        if asset == SOL_MINT {
            transaction.transfer_sol(&address, per_output)?;
        } else {
            transaction.transfer(&address, asset, per_output)?;
        }
    }
    let signature = send_private(&ctx, &client, transaction, Vec::new(), Send::Fast)?;
    println!(
        "ok split parts={} amount={} mint={} signature={}",
        opts.parts,
        per_output,
        format_address(asset),
        signature
    );
    Ok(())
}

/// The named utxo, or the largest plain one that divides into `parts`.
fn split_input(
    ctx: &SyncContext,
    asset: Address,
    parts: u8,
    input: Option<[u8; 32]>,
) -> Result<WalletUtxo> {
    let parts = u64::from(parts);
    let entry = match input {
        Some(hash) => ctx
            .spendable
            .utxos()
            .find(|entry| entry.utxo.asset.asset == asset && entry.utxo_hash == hash)
            .ok_or_else(|| anyhow::anyhow!("utxo {} is not spendable", hex::encode(hash)))?,
        None => ctx
            .spendable
            .utxos()
            .filter(|entry| {
                entry.utxo.asset.asset == asset
                    && entry.is_plain()
                    && entry.utxo.amount % parts == 0
            })
            .max_by_key(|entry| entry.utxo.amount)
            .ok_or_else(|| anyhow::anyhow!("no plain utxo divides into {parts} parts"))?,
    };
    if !entry.is_plain() {
        bail!(
            "utxo {} carries a ring or data",
            hex::encode(entry.utxo_hash)
        );
    }
    if entry.utxo.amount % parts != 0 {
        bail!("{} does not divide into {parts} parts", entry.utxo.amount);
    }
    Ok(entry.clone())
}

/// Consolidate plain utxos of one tree into one. No `--input` sweeps the
/// smallest ones; explicit hashes name the exact utxos.
pub(crate) fn run_merge(opts: MergeOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync, &rpc)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = client(rpc, &network)?;
    let hashes = opts
        .input
        .iter()
        .map(|hash| parse_hex_array::<32>(hash))
        .collect::<Result<Vec<_>>>()?;
    let inputs = merge_inputs(&ctx, asset, &hashes)?;
    let num_inputs = inputs.len();
    let tree_id = inputs[0].tree_id();

    let keypair = &ctx.material.keypair;
    // The merged UTXO stays on the inputs' tree.
    let prepared = MergeTransaction::new(inputs)?
        .with_output_tree_id(tree_id)
        .encrypt(keypair)?;
    let merged_amount = prepared.output_utxo.amount;
    let address = keypair.shielded_address()?;
    let signature = MergeSubmission::new(
        &prepared,
        ctx.material.owner_pubkey(),
        &address,
        &keypair.nullifier_key,
        payer(&ctx),
    )
    .send_sync(&client, &[&ctx.material.funding])?;

    println!(
        "ok merge inputs={} amount={} mint={} signature={}",
        num_inputs,
        merged_amount,
        format_address(asset),
        signature
    );
    Ok(())
}

/// The named utxos, or up to the default merge width of the smallest plain
/// utxos of the asset's fuller tree. Every input is checked here, before the
/// registry fetch and the proof requests.
fn merge_inputs(ctx: &SyncContext, asset: Address, hashes: &[[u8; 32]]) -> Result<Vec<WalletUtxo>> {
    if hashes.is_empty() {
        return Ok(select_merge(
            ctx.spendable.utxos(),
            asset,
            MERGE_DEFAULT_INPUT_COUNT,
            &HashSet::new(),
        )?);
    }
    if !(2..=MAX_MERGE_INPUTS).contains(&hashes.len()) {
        bail!("--input takes 2 to {MAX_MERGE_INPUTS} utxos");
    }
    let mut selected: Vec<WalletUtxo> = Vec::with_capacity(hashes.len());
    for hash in hashes {
        if selected.iter().any(|entry| entry.utxo_hash == *hash) {
            bail!("utxo {} is named twice", hex::encode(hash));
        }
        let entry = ctx
            .spendable
            .utxos()
            .find(|entry| entry.utxo.asset.asset == asset && entry.utxo_hash == *hash)
            .ok_or_else(|| anyhow::anyhow!("utxo {} is not spendable", hex::encode(hash)))?;
        if !entry.is_plain() {
            bail!("utxo {} carries a ring or data", hex::encode(hash));
        }
        if selected
            .first()
            .is_some_and(|first| first.tree_id() != entry.tree_id())
        {
            bail!("utxo {} is on another tree", hex::encode(hash));
        }
        selected.push(entry.clone());
    }
    Ok(selected)
}

fn payer(ctx: &SyncContext) -> Address {
    Address::new_from_array(ctx.material.funding.pubkey().to_bytes())
}

/// The token program of an SPL `asset`; `None` for SOL.
pub(super) fn spl_token_program<R: Rpc>(
    rpc: &R,
    asset: Address,
) -> Result<Option<solana_pubkey::Pubkey>> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let mint = solana_pubkey::Pubkey::new_from_array(asset.to_bytes());
    Ok(Some(resolve_spl_token_program(rpc, &mint)?))
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
