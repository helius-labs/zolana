use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_merge, create_split_sync, create_transfer_sync, fetch_user_record_checked,
    prover::merge::MergeProver, prover::transact::assemble, ClientError, CreateMerge, CreateSplit,
    CreateTransfer, InputCommitment, InputSelection, MergeWitness, PreparedMerge, ProofCompressed,
    ProverClient, ProverInputs, Rpc, SignedTransaction, SolanaRpc, SpendProof, SpendableUtxo,
    ZolanaIndexer, MAX_TRANSFER_INPUTS, MERGE_INPUTS,
};
use zolana_interface::instruction::{MergeTransact, Transact, TransactWithdrawal};
use zolana_transaction::{Address, SOL_MINT};
use zolana_user_registry_interface::user_record_pda;

use super::{
    material::WalletMaterial,
    reservation::{
        inflight_dir, refresh_all, reserve_covering, reserve_hash, reserve_hashes, Reservation,
    },
    resolve::{get_network_with_config, resolve_sync_with_config},
    sync::{sync_context, wait_for_indexed_output_refreshing, SyncContext, WaitOutcome},
    util::{
        ensure_positive, format_address, lamports_to_sol_string, parse_address,
        parse_amount_for_asset, parse_hex_array, parse_sol_amount, resolve_recipient_pubkey,
    },
};

use crate::{
    args::{ConsolidateOptions, SplitOptions, SyncOptions, TransferOptions, UtxosOptions},
    cli_config::CliConfigFile,
};

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let amount = parse_amount_for_asset(&opts.amount, asset)?;
    ensure_positive(amount)?;
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let recipient_owner = resolve_recipient_pubkey(&opts.to)?;
    let tree = network.tree;

    // First attempt over the freshly synced wallet. A balance spread over more
    // notes than a transfer can spend surfaces as `FragmentedBalance`; in that
    // case consolidate once and retry against a re-synced wallet.
    match try_transfer(
        &opts,
        &config,
        &rpc,
        &indexer,
        &network,
        &ctx,
        asset,
        amount,
        recipient_owner,
    ) {
        Ok(()) => Ok(()),
        Err(err) if is_fragmented_balance(&err) => {
            eprintln!(
                "notice: balance for {} is too fragmented for one transfer; consolidating first",
                format_address(asset)
            );
            let (selection, reservations) =
                resolve_merge_selection(&opts.network.sync, &config, &ctx, asset, &[])?;
            let merge = create_merge(CreateMerge {
                wallet: &ctx.wallet,
                keypair: &ctx.material.keypair,
                asset,
                selection,
            })?;
            let (signature, _output_hash, outcome) = submit_merge_transaction(
                SubmitMergeTx {
                    rpc: &rpc,
                    indexer: &indexer,
                    material: &ctx.material,
                    tree,
                    prover_url: &network.prover_url,
                    reservations: &reservations,
                },
                merge.prepared,
            )?;
            eprintln!(
                "notice: consolidated {} notes signature={signature}",
                merge.num_inputs
            );
            if outcome == WaitOutcome::ConfirmedPendingIndex {
                bail!(
                    "consolidation succeeded but indexing is still pending; retry the transfer after sync catches up"
                );
            }
            // Retry once against a re-synced wallet; propagate any error, including a
            // second fragmentation (do not loop).
            let ctx = sync_context(&opts.network.sync)?;
            try_transfer(
                &opts,
                &config,
                &rpc,
                &indexer,
                &network,
                &ctx,
                asset,
                amount,
                recipient_owner,
            )
        }
        Err(err) => Err(err),
    }
}

/// Whether an error is a surfaced [`ClientError::FragmentedBalance`] (the auto
/// consolidation trigger). The action returns the typed error wrapped by
/// `anyhow`, so match on the downcast.
fn is_fragmented_balance(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<ClientError>(),
        Some(ClientError::FragmentedBalance { .. })
    )
}

/// Build and submit one transfer over `ctx`. Factored out of [`run_transfer`] so
/// the auto-consolidation path can retry it against a re-synced wallet.
#[allow(clippy::too_many_arguments)]
fn try_transfer(
    opts: &TransferOptions,
    config: &CliConfigFile,
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    network: &super::resolve::ResolvedNetworkOptions,
    ctx: &SyncContext,
    asset: Address,
    amount: u64,
    recipient_owner: Pubkey,
) -> Result<()> {
    // Resolve which notes to spend. An explicit `--input` wins; otherwise reserve
    // the actual note set selected for the transfer so concurrent commands do not
    // collide. Held reservations stay alive through proving, submission, and the
    // indexer wait.
    let (selection, reservations) = resolve_transfer_selection(opts, config, ctx, asset, amount)?;

    let transfer = create_transfer_sync(CreateTransfer {
        rpc,
        wallet: &ctx.wallet,
        authority: &ctx.material,
        owner_pubkey: ctx.material.owner_pubkey(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient_owner,
        asset,
        amount,
        assets: &ctx.wallet.registry,
        selection,
    })?;
    let (signature, outcome) = submit_private_transaction(
        SubmitPrivateTx {
            rpc,
            indexer,
            material: &ctx.material,
            tree: network.tree,
            prover_url: &network.prover_url,
            withdrawal: transfer.recipient.withdrawal().cloned(),
            wait_output_hash: transfer.wait_output_hash,
            reservations: &reservations,
        },
        transfer.signed,
    )?;
    let mode = if transfer.recipient.is_public_withdrawal() {
        "withdraw"
    } else {
        "shielded"
    };
    println!(
        "ok transfer amount={} mint={} to={} mode={} signature={}{}",
        opts.amount,
        format_address(asset),
        transfer.recipient.pubkey(),
        mode,
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

/// Decide the transfer's [`InputSelection`], returning any held [`Reservation`]
/// the caller must keep alive until submission completes.
///
/// - `--input <hash>` -> reserve and spend exactly that note (`Explicit`).
/// - otherwise, reserve the selected unspent note set under the wallet's
///   `.inflight` lock dir and spend it (`Explicit`), holding the locks.
/// - if no reservation dir is usable, fall back to SDK `Auto` selection.
fn resolve_transfer_selection(
    opts: &TransferOptions,
    config: &CliConfigFile,
    ctx: &super::sync::SyncContext,
    asset: Address,
    amount: u64,
) -> Result<(InputSelection, Vec<Reservation>)> {
    if let Some(input) = &opts.input {
        let hash = parse_hex_array::<32>(input)?;
        let sync = resolve_sync_with_config(&opts.network.sync, config)?;
        let reservations = match inflight_dir(&sync.keypair_path) {
            Some(dir) => reserve_hashes(&dir, &[hash])?,
            None => Vec::new(),
        };
        return Ok((InputSelection::Explicit(vec![hash]), reservations));
    }

    resolve_auto_spend_selection(&opts.network.sync, config, ctx, asset, amount)
}

pub(super) fn resolve_auto_spend_selection(
    sync_opts: &SyncOptions,
    config: &CliConfigFile,
    ctx: &SyncContext,
    asset: Address,
    amount: u64,
) -> Result<(InputSelection, Vec<Reservation>)> {
    let sync = resolve_sync_with_config(sync_opts, config)?;
    let Some(dir) = inflight_dir(&sync.keypair_path) else {
        return Ok((InputSelection::Auto, Vec::new()));
    };

    let candidates = ctx.wallet.spendable_utxos(asset);
    match reserve_transfer_inputs(&dir, &candidates, amount) {
        Ok((selection, reservations)) => Ok((selection, reservations)),
        // Lock dir not creatable/readable: single-transfer behavior is unchanged.
        Err(err) if err.downcast_ref::<std::io::Error>().is_some() => {
            Ok((InputSelection::Auto, Vec::new()))
        }
        Err(err) => Err(err),
    }
}

fn reserve_transfer_inputs(
    dir: &std::path::Path,
    candidates: &[SpendableUtxo],
    amount: u64,
) -> Result<(InputSelection, Vec<Reservation>)> {
    let mut candidates = candidates.to_vec();
    candidates.sort_by_key(|note| std::cmp::Reverse(note.amount));
    if let Some(reservation) = reserve_covering(dir, &candidates, amount)? {
        return Ok((
            InputSelection::Explicit(vec![reservation.hash]),
            vec![reservation],
        ));
    }

    let mut reservations = Vec::new();
    let mut total = 0u64;
    for (index, note) in candidates.iter().copied().enumerate() {
        if total >= amount {
            break;
        }
        if let Some(reservation) = reserve_hash(dir, note.hash)? {
            if reservations.len() >= MAX_TRANSFER_INPUTS {
                drop(reservation);
                let (notes, available) =
                    greedy_note_count(total, candidates.get(index..).unwrap_or(&[]), amount);
                if available < amount {
                    return Err(ClientError::InsufficientBalance {
                        requested: amount,
                        available,
                    }
                    .into());
                }
                return Err(ClientError::FragmentedBalance {
                    requested: amount,
                    notes,
                    max_inputs: MAX_TRANSFER_INPUTS,
                }
                .into());
            }
            total = total
                .checked_add(note.amount)
                .ok_or(ClientError::SelectedBalanceOverflow)?;
            reservations.push(reservation);
        }
    }

    if total < amount {
        bail!(
            "insufficient unreserved balance: requested {amount}, available {total}; another wallet command may be in flight"
        );
    }

    let hashes = reservations
        .iter()
        .map(|reservation| reservation.hash)
        .collect();
    Ok((InputSelection::Explicit(hashes), reservations))
}

fn greedy_note_count(mut total: u64, notes: &[SpendableUtxo], amount: u64) -> (usize, u64) {
    let mut count = MAX_TRANSFER_INPUTS;
    for note in notes {
        count += 1;
        total = total.saturating_add(note.amount);
        if total >= amount {
            break;
        }
    }
    (count, total)
}

fn resolve_merge_selection(
    sync_opts: &SyncOptions,
    config: &CliConfigFile,
    ctx: &SyncContext,
    asset: Address,
    explicit_hashes: &[[u8; 32]],
) -> Result<(InputSelection, Vec<Reservation>)> {
    let fallback_selection = if explicit_hashes.is_empty() {
        InputSelection::Auto
    } else {
        InputSelection::Explicit(explicit_hashes.to_vec())
    };
    let sync = resolve_sync_with_config(sync_opts, config)?;
    let Some(dir) = inflight_dir(&sync.keypair_path) else {
        return Ok((fallback_selection, Vec::new()));
    };

    if !explicit_hashes.is_empty() {
        let reservations = reserve_hashes(&dir, explicit_hashes)?;
        return Ok((
            InputSelection::Explicit(explicit_hashes.to_vec()),
            reservations,
        ));
    }

    let mut candidates = ctx.wallet.spendable_utxos(asset);
    candidates.sort_by_key(|note| note.amount);

    let mut reservations = Vec::new();
    for note in candidates {
        if reservations.len() >= MERGE_INPUTS {
            break;
        }
        if let Some(reservation) = reserve_hash(&dir, note.hash)? {
            reservations.push(reservation);
        }
    }
    if reservations.len() < 2 {
        bail!(
            "not enough unreserved notes to consolidate; another wallet command may be in flight"
        );
    }
    let hashes = reservations
        .iter()
        .map(|reservation| reservation.hash)
        .collect();
    Ok((InputSelection::Explicit(hashes), reservations))
}

pub(super) fn run_split(opts: SplitOptions) -> Result<()> {
    let parts = opts.parts;
    if parts < 2 {
        bail!("split requires at least 2 parts");
    }
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let tree = network.tree;

    // A split rides the SOL note rail. Pick the note to split and derive the
    // per-part amount.
    let (selection, per_output_amount, reservations) =
        split_selection(&opts, &config, &ctx, parts)?;

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
    let (signature, outcome) = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
            withdrawal: None,
            wait_output_hash: split.wait_output_hash,
            reservations: &reservations,
        },
        split.signed,
    )?;
    println!(
        "ok split parts={} amount={} signature={}{}",
        parts,
        lamports_to_sol_string(per_output_amount * u64::from(parts)),
        signature,
        outcome.pending_suffix(),
    );
    Ok(())
}

/// Resolve which SOL note a split spends and the per-part amount. With
/// `--part-sol`, every part is that many lamports and the input must total
/// `parts * part_sol`; without it, the largest note is split evenly (its balance
/// must divide by `parts`). `--input <hash>` names the exact note to split.
fn split_selection(
    opts: &SplitOptions,
    config: &CliConfigFile,
    ctx: &super::sync::SyncContext,
    parts: u8,
) -> Result<(InputSelection, u64, Vec<Reservation>)> {
    let notes = ctx.wallet.spendable_utxos(SOL_MINT);
    if notes.is_empty() {
        bail!("wallet has no spendable SOL notes to split");
    }
    let sync = resolve_sync_with_config(&opts.network.sync, config)?;
    let dir = inflight_dir(&sync.keypair_path);
    let requested_per_output = opts.part_sol.as_deref().map(parse_sol_amount).transpose()?;
    if let Some(amount) = requested_per_output {
        ensure_positive(amount)?;
    }
    let requested_total = requested_per_output
        .map(|amount| {
            amount
                .checked_mul(u64::from(parts))
                .ok_or(ClientError::SelectedBalanceOverflow)
        })
        .transpose()?;

    let (note, reservations) = match &opts.input {
        Some(input) => {
            let hash = parse_hex_array::<32>(input)?;
            let note = notes
                .iter()
                .find(|note| note.hash == hash)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("no spendable SOL note with hash {input}; run `wallet utxos`")
                })?;
            let reservations = match &dir {
                Some(dir) => reserve_hashes(dir, &[hash])?,
                None => Vec::new(),
            };
            (note, reservations)
        }
        None => {
            let mut candidates = notes;
            candidates.sort_by_key(|note| std::cmp::Reverse(note.amount));
            if let Some(total) = requested_total {
                candidates.retain(|note| note.amount == total);
            }
            let mut selected = None;
            for note in candidates {
                match &dir {
                    Some(dir) => {
                        if let Some(reservation) = reserve_hash(dir, note.hash)? {
                            selected = Some((note, vec![reservation]));
                            break;
                        }
                    }
                    None => {
                        selected = Some((note, Vec::new()));
                        break;
                    }
                }
            }
            selected.ok_or_else(|| {
                anyhow::anyhow!(
                    "no unreserved SOL note is available to split{}",
                    requested_total
                        .map(|total| format!(" with total amount {total}"))
                        .unwrap_or_default()
                )
            })?
        }
    };

    let per_output_amount = match requested_per_output {
        Some(part_sol) => {
            if Some(note.amount) != requested_total {
                bail!(
                    "selected note holds {} SOL but split total is {} SOL",
                    lamports_to_sol_string(note.amount),
                    lamports_to_sol_string(requested_total.unwrap_or(0))
                );
            }
            part_sol
        }
        None => {
            if note.amount % u64::from(parts) != 0 {
                bail!(
                    "note of {} SOL does not divide evenly into {parts} parts; pass --part-sol",
                    lamports_to_sol_string(note.amount)
                );
            }
            note.amount / u64::from(parts)
        }
    };
    ensure_positive(per_output_amount)?;

    Ok((
        InputSelection::Explicit(vec![note.hash]),
        per_output_amount,
        reservations,
    ))
}

pub(super) fn run_utxos(opts: UtxosOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync)?;
    let notes = ctx.wallet.spendable_utxos(SOL_MINT);
    for note in &notes {
        println!(
            "ok utxo hash={} sol={} amount={}",
            hex::encode(note.hash),
            lamports_to_sol_string(note.amount),
            note.amount
        );
    }
    println!("ok utxos count={}", notes.len());
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
    pub(super) reservations: &'a [Reservation],
}

pub(super) fn submit_private_transaction(
    request: SubmitPrivateTx<'_>,
    signed: SignedTransaction,
) -> Result<(Signature, WaitOutcome)> {
    refresh_all(request.reservations)?;
    let commitments = signed.input_commitments()?;
    let proofs = spend_proofs(request.indexer, request.tree, &commitments)?;
    refresh_all(request.reservations)?;
    // `assemble` runs the witness build once: the per-input nullifiers, root
    // indices, and dummy padding come out of the prover, so the instruction data
    // and the proof commit to identical values by construction.
    let assembled = assemble(signed, &proofs)?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => prover.prove_transfer_p256(inputs)?,
        ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs)?,
    };
    refresh_all(request.reservations)?;
    let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
    let data = assembled.with_proof(proof);
    let ix = Transact {
        payer: request.material.funding.pubkey(),
        tree: request.tree,
        withdrawal: request.withdrawal,
        data,
    }
    .instruction();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        ix,
    ];
    let signature = request.rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(request.material.funding.pubkey().to_bytes()),
        &[&request.material.funding],
    )?;
    let _ = refresh_all(request.reservations);
    let outcome = wait_for_indexed_output_refreshing(
        request.indexer,
        request.rpc,
        request.tree,
        request.wait_output_hash,
        signature,
        || refresh_all(request.reservations),
    )?;
    Ok((signature, outcome))
}

pub(super) struct SubmitMergeTx<'a> {
    pub(super) rpc: &'a SolanaRpc,
    pub(super) indexer: &'a ZolanaIndexer,
    pub(super) material: &'a WalletMaterial,
    pub(super) tree: Pubkey,
    pub(super) prover_url: &'a str,
    pub(super) reservations: &'a [Reservation],
}

/// Prove and submit a consolidation (`merge_transact`), returning the signature
/// and the merged output's committed hash (the wait target). The merge always
/// rides the P256/BSB22 rail, so the proof carries a commitment packed into the
/// fixed 192-byte `merge_transact` layout.
pub(super) fn submit_merge_transaction(
    request: SubmitMergeTx<'_>,
    prepared: PreparedMerge,
) -> Result<(Signature, [u8; 32], WaitOutcome)> {
    refresh_all(request.reservations)?;
    let owner = request.material.funding.pubkey();
    // `merge_transact` unconditionally requires the owner to have opted into
    // merging (see programs/shielded-pool/.../merge/processor.rs). Fail fast with
    // an actionable hint before the expensive proof, rather than surfacing a raw
    // on-chain program error after proving + submitting.
    let record = fetch_user_record_checked(request.rpc, owner)?;
    if !record.merging_enabled {
        bail!(
            "merging is not enabled for this wallet; run `zolana wallet merge --enable` first \
             (merge_transact requires the owner to opt in)"
        );
    }
    let commitments = prepared.input_commitments()?;
    let proofs = spend_proofs(request.indexer, request.tree, &commitments)?;
    refresh_all(request.reservations)?;
    let result = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key: request.material.keypair.nullifier_key.clone(),
        proofs,
    })?
    .build()?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = prover.prove_merge(&result.inputs)?;
    refresh_all(request.reservations)?;
    let proof = ProofCompressed::try_from(proof)?.to_merge_proof()?;
    let data = result.instruction_data(proof);
    let ix = MergeTransact {
        tree: request.tree,
        payer: request.material.funding.pubkey(),
        user_record: user_record_pda(&owner).0,
        data,
    }
    .instruction();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        ix,
    ];
    let signature = request.rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(owner.to_bytes()),
        &[&request.material.funding],
    )?;
    let _ = refresh_all(request.reservations);
    let outcome = wait_for_indexed_output_refreshing(
        request.indexer,
        request.rpc,
        request.tree,
        result.output_hash,
        signature,
        || refresh_all(request.reservations),
    )?;
    Ok((signature, result.output_hash, outcome))
}

pub(super) fn run_consolidate(opts: ConsolidateOptions) -> Result<()> {
    let asset = parse_address(&opts.mint)?;
    let config = CliConfigFile::load()?;
    let network = get_network_with_config(&opts.network, &config)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let tree = network.tree;

    let explicit_hashes = opts
        .input
        .iter()
        .map(|input| parse_hex_array::<32>(input))
        .collect::<Result<Vec<_>>>()?;
    let (selection, reservations) =
        resolve_merge_selection(&opts.network.sync, &config, &ctx, asset, &explicit_hashes)?;

    let merge = create_merge(CreateMerge {
        wallet: &ctx.wallet,
        keypair: &ctx.material.keypair,
        asset,
        selection,
    })?;
    let num_inputs = merge.num_inputs;
    let merged_amount = merge.merged_amount;
    let (signature, _output_hash, outcome) = submit_merge_transaction(
        SubmitMergeTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
            reservations: &reservations,
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

fn spend_proofs(
    indexer: &ZolanaIndexer,
    tree: Pubkey,
    commitments: &[InputCommitment],
) -> Result<Vec<SpendProof>> {
    let tree_address = Address::new_from_array(tree.to_bytes());
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let state_proofs = indexer.get_merkle_proofs(tree_address, leaves)?.proofs;
    let nullifier_proofs = indexer
        .get_non_inclusion_proofs(tree_address, nullifiers)?
        .proofs;
    if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
        bail!("indexer returned incomplete input proofs");
    }

    // The indexer's merkle / non-inclusion proofs carry the tree root indices the
    // witness build resolves placement against; `SpendProof` wraps them directly.
    Ok(state_proofs
        .into_iter()
        .zip(nullifier_proofs)
        .map(|(state, nullifier)| SpendProof { state, nullifier })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{note, temp_dir};
    use super::*;

    #[test]
    fn fragmented_balance_reports_actual_greedy_note_count() {
        let dir = temp_dir("zolana-transfer-selection", "fragmented-count");
        let notes = (0..7).map(|tag| note(10, tag)).collect::<Vec<_>>();
        let err = match reserve_transfer_inputs(&dir, &notes, 65) {
            Ok(_) => panic!("seven notes should exceed transfer cap"),
            Err(err) => err,
        };
        assert!(matches!(
            err.downcast_ref::<ClientError>(),
            Some(ClientError::FragmentedBalance {
                requested: 65,
                notes: 7,
                max_inputs: MAX_TRANSFER_INPUTS,
            })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserve_transfer_inputs_holds_multi_note_selection_largest_first() {
        let dir = temp_dir("zolana-transfer-selection", "multi-note");
        let notes = vec![note(10, 1), note(35, 2), note(30, 3), note(40, 4)];

        let (selection, reservations) =
            reserve_transfer_inputs(&dir, &notes, 100).expect("multi-note reservation");

        assert_eq!(
            selection,
            InputSelection::Explicit(vec![[4u8; 32], [2u8; 32], [3u8; 32]])
        );
        assert_eq!(reservations.len(), 3);
        for hash in [[4u8; 32], [2u8; 32], [3u8; 32]] {
            assert!(dir.join(hex::encode(hash)).exists());
        }
        drop(reservations);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserve_transfer_inputs_skips_note_held_by_another_reservation() {
        let dir = temp_dir("zolana-transfer-selection", "skip-held");
        let notes = vec![note(50, 5), note(45, 4), note(30, 3)];
        let held = reserve_hash(&dir, [5u8; 32]).unwrap().expect("pre-claim");

        let (selection, reservations) =
            reserve_transfer_inputs(&dir, &notes, 70).expect("skip held note");

        assert_eq!(
            selection,
            InputSelection::Explicit(vec![[4u8; 32], [3u8; 32]])
        );
        assert!(dir.join(hex::encode([5u8; 32])).exists());
        for hash in [[4u8; 32], [3u8; 32]] {
            assert!(dir.join(hex::encode(hash)).exists());
        }
        drop(reservations);
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
