use anyhow::Result;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_transfer_sync, submit_private_transaction as submit_private_action, CreateTransfer,
    InputSelection, SignedTransaction, SolanaRpc,
    SubmitPrivateTransaction as ClientSubmitPrivateTransaction, ZolanaIndexer,
};
use zolana_interface::instruction::TransactWithdrawal;
use zolana_transaction::Address;

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::{sync_context, wait_for_indexed_output, WaitOutcome},
    util::{
        ensure_positive, format_address, parse_address, parse_hex_array, parse_shielded_address,
    },
};
use crate::args::{TransferOptions, UtxosOptions};

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
