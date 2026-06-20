use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    CircuitType, InputCommitment, InputTreeIndices, ProofCompressed, ProverClient, Rpc, SolanaRpc,
    SpendProof, SpendUtxo, StateInclusionProof, Transaction, ZolanaIndexer, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_interface::instruction::{Transact, TransactWithdrawal};
use zolana_transaction::{Address, SOL_MINT};

use crate::args::TransferOptions;

use super::material::WalletMaterial;
use super::registry::resolve_transfer_recipient;
use super::sync::{sync_context, wait_for_indexed_transaction, SyncContext};
use super::util::{ensure_positive, ensure_sol, parse_pubkey};

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let mut rpc = SolanaRpc::new(opts.network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, opts.network.airdrop_lamports)?;
    let recipient = resolve_transfer_recipient(&opts.to, &opts.network.sync)?;
    let tree = parse_pubkey(&opts.network.tree)?;

    let sender_view_tag = next_sender_view_tag(&ctx)?;
    let inputs = select_inputs(&ctx, SOL_MINT, opts.amount)?;
    let mut tx = Transaction::new(
        ctx.material.keypair.shielded_address()?,
        inputs,
        Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
    );
    tx.send(
        &recipient.address,
        SOL_MINT,
        opts.amount,
        recipient.view_tag,
    )?;
    let signed = tx.sign(&ctx.material.keypair, &ctx.assets, sender_view_tag)?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &opts.network.prover_url,
            withdrawal: None,
            wait_tag: sender_view_tag,
        },
        signed,
    )?;
    println!(
        "ok transfer amount={} mint=SOL to={} signature={}",
        opts.amount, recipient.owner, signature
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
    pub(super) wait_tag: [u8; 32],
}

pub(super) fn submit_private_transaction(
    request: SubmitPrivateTx<'_>,
    signed: zolana_client::SignedTransaction,
) -> Result<Signature> {
    let commitments = signed.input_commitments()?;
    let (proofs, indices) = spend_proofs(request.indexer, request.tree, &commitments)?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = match signed.clone().into_prover(&proofs)? {
        CircuitType::P256(prover_inputs) => {
            let built = prover_inputs.build()?;
            prover.prove_transfer_p256(&built.inputs)?
        }
        CircuitType::Eddsa(prover_inputs) => {
            let built = prover_inputs.build()?;
            prover.prove_transfer(&built.inputs)?
        }
    };
    let proof_bytes = ProofCompressed::try_from(proof)?.to_transact_proof_bytes();
    let data = signed.into_transact_ix_data(proof_bytes, Some(&indices))?;
    let ix = Transact {
        payer: request.material.funding.pubkey(),
        tree: request.tree,
        cpi_signer: None,
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
    wait_for_indexed_transaction(request.indexer, request.wait_tag, signature)?;
    Ok(signature)
}

fn spend_proofs(
    indexer: &ZolanaIndexer,
    tree: Pubkey,
    commitments: &[InputCommitment],
) -> Result<(Vec<SpendProof>, Vec<InputTreeIndices>)> {
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

    let mut proofs = Vec::with_capacity(commitments.len());
    let mut indices = Vec::with_capacity(commitments.len());
    for (state, nullifier) in state_proofs.into_iter().zip(nullifier_proofs) {
        indices.push(InputTreeIndices {
            utxo_tree_root_index: state.root_index,
            nullifier_tree_root_index: nullifier.root_index,
            tree_index: 0,
            eddsa_signer_index: 0,
        });
        proofs.push(SpendProof {
            state: StateInclusionProof {
                path_elements: fixed_path::<STATE_TREE_HEIGHT>(state.path, "state path")?,
                leaf_index: state.leaf_index,
                root: state.root,
            },
            nullifier: zolana_client::NullifierNonInclusionProof {
                low_value: nullifier.low_element,
                next_value: nullifier.high_element,
                low_path_elements: fixed_path::<NULLIFIER_TREE_HEIGHT>(
                    nullifier.path,
                    "nullifier path",
                )?,
                low_leaf_index: nullifier.low_element_index,
                root: nullifier.root,
            },
        });
    }
    Ok((proofs, indices))
}

fn fixed_path<const N: usize>(path: Vec<[u8; 32]>, name: &str) -> Result<[[u8; 32]; N]> {
    let actual = path.len();
    path.try_into()
        .map_err(|_| anyhow::anyhow!("{name} length mismatch: expected {N}, got {actual}"))
}

pub(super) fn select_inputs(
    ctx: &SyncContext,
    mint: Address,
    amount: u64,
) -> Result<Vec<SpendUtxo>> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for entry in &ctx.wallet.utxos {
        if entry.spent || entry.utxo.asset != mint {
            continue;
        }
        selected.push(SpendUtxo::from((entry.utxo.clone(), &ctx.material.keypair)));
        total = total
            .checked_add(entry.utxo.amount)
            .ok_or_else(|| anyhow::anyhow!("selected balance overflow"))?;
        if total >= amount {
            break;
        }
    }
    if total < amount {
        bail!("insufficient private balance: requested {amount}, available {total}");
    }
    Ok(selected)
}

pub(super) fn next_sender_view_tag(ctx: &SyncContext) -> Result<[u8; 32]> {
    let entry = ctx
        .wallet
        .viewing_key_history
        .last()
        .ok_or_else(|| anyhow::anyhow!("wallet viewing history missing"))?;
    Ok(ctx.material.keypair.get_sender_view_tag(entry.tx_count)?)
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
