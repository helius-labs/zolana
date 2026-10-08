use anyhow::{bail, Result};
use solana_signer::Signer;
use zolana_client::{
    prover::merge::MergeProver,
    user_registry::{
        fetch_user_record_checked, resolved_address_from_record, try_resolve_registered_address,
    },
    ClientError, ProofCompressed, ProverExt, Rpc, SolanaRpc, ZolanaClient,
};
use zolana_interface::{pda, shape::Shape};
use zolana_program::instruction::MergeTransact;
use zolana_transaction::{
    instructions::{
        merge::{MergeTransaction, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
        transact::ConfidentialTransaction,
    },
    Address, WalletUtxo, SOL_MINT,
};
use zolana_user_registry_interface::user_record_pda;

use super::{
    material::WalletMaterial,
    resolve::{get_network, ResolvedNetworkOptions},
    spend::{
        is_default_ring_spendable, is_plain_utxo, select_notes, send_private, spend_tree,
        withdraw_to, Send,
    },
    sync::{sync_context, wait_for_indexed_leaf, SyncContext},
    util::{
        ensure_positive, format_address, parse_address, parse_hex_array, parse_pubkey,
        resolve_spl_token_program,
    },
};
use crate::args::{MergeOptions, SplitOptions, TransferOptions, UtxosOptions};

/// A `merge_transact` verifies a Groth16 proof on chain, above the default
/// per-instruction budget. The widest shape, "Merge 54x1" in
/// program-tests/shielded-pool/CU_BENCHMARK.md, measures 296,879 CU.
const MERGE_CU_LIMIT: u32 = 1_400_000;

pub(super) fn client(
    rpc: SolanaRpc,
    network: &ResolvedNetworkOptions,
) -> Result<ZolanaClient<SolanaRpc>> {
    let client = ZolanaClient::from_urls(
        rpc,
        network.sync.indexer_url.clone(),
        network.prover_url.clone(),
    )?;
    Ok(match &network.prover_tee {
        Some(policy) => client.with_prover_tee(policy.clone())?,
        None => client,
    })
}

/// Send privately to `--to`'s registered shielded address. An account without
/// one is paid by a public withdrawal instead.
pub(crate) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = client(rpc, &network)?;
    let recipient = parse_pubkey(&opts.to)?;

    let inputs = select_notes(&ctx.spendable, asset, opts.amount)?;
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
            let settlement = withdraw_to(
                &mut transaction,
                recipient,
                asset,
                opts.amount,
                spl_token_program,
            )?;
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
    let ctx = sync_context(&opts.sync)?;
    let mut count = 0usize;
    for entry in ctx
        .spendable
        .utxos()
        .filter(|entry| entry.utxo.asset.asset == asset)
    {
        count += 1;
        let kind = if !is_default_ring_spendable(entry) {
            "ring"
        } else if !is_plain_utxo(entry) {
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
    let ctx = sync_context(&opts.network.sync)?;
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
        None => {
            let tree = spend_tree(&ctx.spendable, asset, is_plain_utxo)?;
            ctx.spendable
                .utxos()
                .filter(|entry| {
                    entry.utxo.asset.asset == asset
                        && pda::tree(entry.tree_id()) == tree
                        && is_plain_utxo(entry)
                        && entry.utxo.amount % parts == 0
                })
                .max_by_key(|entry| entry.utxo.amount)
                .ok_or_else(|| anyhow::anyhow!("no plain utxo divides into {parts} parts"))?
        }
    };
    if !is_plain_utxo(entry) {
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
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let client = client(rpc, &network)?;
    let hashes = opts
        .input
        .iter()
        .map(|hash| parse_hex_array::<32>(hash))
        .collect::<Result<Vec<_>>>()?;
    let (tree, inputs) = merge_inputs(&ctx, asset, &hashes)?;
    let num_inputs = inputs.len();

    let owner = ctx.material.owner_pubkey();
    let keypair = &ctx.material.keypair;
    let record = fetch_user_record_checked(&client, owner)?;
    if !record.merging_enabled {
        return Err(ClientError::MergeDisabled { owner }.into());
    }
    // The program checks the merge keys against the record; check first, so a
    // mismatch does not cost a proof.
    if resolved_address_from_record(owner, &record)?.address != keypair.shielded_address()? {
        bail!("the user registry holds other keys for {owner}");
    }
    let prepared = MergeTransaction::new(inputs)?.encrypt(keypair)?;
    let merged_amount = prepared.output_utxo.amount;
    let proofs = client.get_input_merkle_proofs(&prepared.input_utxo_hashes()?, None)?;
    let dummy_nullifiers = prepared.dummy_nullifiers();
    let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        client
            .get_non_inclusion_proofs(tree, dummy_nullifiers, None)?
            .proofs
    };
    // A merge proof verifies only against the tree its input proofs came
    // from; check before paying for the proof.
    let proof_trees = proofs
        .iter()
        .flat_map(|proof| {
            [
                proof.state.merkle_context.tree,
                proof.nullifier.merkle_context.tree,
            ]
        })
        .chain(
            dummy_nullifier_proofs
                .iter()
                .map(|proof| proof.merkle_context.tree),
        );
    if let Some(other) = proof_trees
        .into_iter()
        .find(|proof_tree| *proof_tree != tree)
    {
        bail!("indexer returned proofs for tree {other}, expected {tree}");
    }
    let result = MergeProver {
        transaction: prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs,
        dummy_nullifier_proofs,
        cache: None,
    }
    .build()?;
    let proof = network.prover().prove_merge(&result.inputs)?;
    let merge = MergeTransact {
        input_tree: tree,
        output_tree: tree,
        payer: ctx.material.funding.pubkey(),
        user_record: user_record_pda(&owner).0,
        data: result.instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?),
        cache: None,
    }
    .instruction();
    let signature = client.create_and_send_transaction(
        &[merge],
        payer(&ctx),
        &[&ctx.material.funding],
        zolana_client::ComputeBudgetConfig::new(MERGE_CU_LIMIT),
    )?;
    // A merge output is not on the view-tag confirmation path a transfer
    // uses, so wait for its leaf before returning.
    wait_for_indexed_leaf(&client, tree, result.output_hash)?;

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
/// utxos on the asset's one tree, and that tree. Every input is checked here,
/// before the registry fetch and the proof requests.
fn merge_inputs(
    ctx: &SyncContext,
    asset: Address,
    hashes: &[[u8; 32]],
) -> Result<(Address, Vec<WalletUtxo>)> {
    if hashes.is_empty() {
        let tree = spend_tree(&ctx.spendable, asset, is_plain_utxo)?;
        let mut candidates: Vec<&WalletUtxo> = ctx
            .spendable
            .utxos()
            .filter(|entry| {
                entry.utxo.asset.asset == asset
                    && pda::tree(entry.tree_id()) == tree
                    && is_plain_utxo(entry)
            })
            .collect();
        candidates.sort_by_key(|entry| entry.utxo.amount);
        candidates.truncate(MERGE_DEFAULT_INPUT_COUNT);
        if candidates.len() < 2 {
            bail!("nothing to merge: fewer than two plain utxos");
        }
        return Ok((tree, candidates.into_iter().cloned().collect()));
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
        if !is_plain_utxo(entry) {
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
    let Some(first) = selected.first() else {
        bail!("--input takes 2 to {MAX_MERGE_INPUTS} utxos");
    };
    Ok((pda::tree(first.tree_id()), selected))
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
