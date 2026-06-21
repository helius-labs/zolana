use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_transfer, CreateTransfer, InputCommitment, ProofCompressed, ProverClient, ProverInputs,
    Rpc, SignedTransaction, SolanaRpc, SpendProof, ZolanaIndexer,
};
use zolana_interface::instruction::{Transact, TransactWithdrawal};
use zolana_transaction::Address;

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::{sync_context, wait_for_indexed_transaction},
    util::{ensure_positive, format_address, parse_address, parse_pubkey},
};
use crate::args::TransferOptions;

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let recipient_owner = parse_pubkey(&opts.to)?;
    let tree = network.tree;

    let transfer = create_transfer(CreateTransfer {
        rpc: &rpc,
        wallet: &ctx.wallet,
        authority: &ctx.material,
        inbox: ctx.material.inbox(),
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient_owner,
        asset,
        amount: opts.amount,
        assets: &ctx.assets,
        public_recipient_token_account: None,
    })?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &network.prover_url,
            withdrawal: transfer.recipient.withdrawal().cloned(),
            wait_tag: transfer.wait_tag,
        },
        transfer.signed,
    )?;
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
    signed: SignedTransaction,
) -> Result<Signature> {
    let commitments = signed.input_commitments()?;
    let proofs = spend_proofs(request.indexer, request.tree, &commitments)?;
    // `assemble` runs the witness build once: the per-input nullifiers, root
    // indices, and dummy padding come out of the prover, so the instruction data
    // and the proof commit to identical values by construction.
    let assembled = signed.assemble(&proofs)?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => prover.prove_transfer_p256(inputs)?,
        ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs)?,
    };
    let proof_bytes = ProofCompressed::try_from(proof)?.to_transact_proof_bytes();
    let data = assembled.with_proof(proof_bytes);
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
