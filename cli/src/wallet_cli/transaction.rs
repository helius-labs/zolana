use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_transfer_sync, create_withdrawal_sync, prover::transact::assemble,
    try_resolve_registered_address, CreateTransfer, CreateWithdrawal, InputCommitment,
    ProofCompressed, ProverClient, ProverInputs, Rpc, SignedTransaction, SolanaRpc, SpendProof,
    ZolanaIndexer,
};
use zolana_interface::instruction::{Transact, TransactWithdrawal};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::Address;

use super::{
    material::WalletMaterial,
    resolve::get_network,
    sync::{sync_context, wait_for_indexed_transaction},
    util::{ensure_positive, format_address, parse_address, parse_recipient, RecipientInput},
};
use crate::args::TransferOptions;

/// A `transfer --to` recipient after resolution.
enum TransferTarget {
    /// A self-contained shielded address (shared directly), or a Solana pubkey
    /// with a user-registry record. Sent as a confidential shielded transfer.
    Shielded(ShieldedAddress),
    /// A Solana pubkey with no registry record. The transfer degrades to a
    /// public withdrawal to that pubkey (spec Single Player, lookup-negative).
    Public(Pubkey),
}

/// Resolve `--to`: a shielded address is used directly; a Solana pubkey is
/// looked up in the user registry, silently falling back to a public withdrawal
/// when the recipient has no registry record.
fn resolve_transfer_recipient(rpc: &SolanaRpc, to: &str) -> Result<TransferTarget> {
    match parse_recipient(to)? {
        RecipientInput::Shielded(address) => Ok(TransferTarget::Shielded(address)),
        RecipientInput::Pubkey(owner) => match try_resolve_registered_address(rpc, owner)? {
            Some(address) => Ok(TransferTarget::Shielded(address)),
            None => Ok(TransferTarget::Public(owner)),
        },
    }
}

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let network = get_network(&opts.network)?;
    let mut rpc = SolanaRpc::new(network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, network.airdrop_lamports)?;
    let tree = network.tree;
    let owner_pubkey = ctx.material.owner_pubkey();
    let payer = Address::new_from_array(ctx.material.funding.pubkey().to_bytes());

    match resolve_transfer_recipient(&rpc, &opts.to)? {
        TransferTarget::Shielded(recipient) => {
            let transfer = create_transfer_sync(CreateTransfer {
                wallet: &ctx.wallet,
                authority: &ctx.material,
                owner_pubkey,
                payer,
                recipient,
                asset,
                amount: opts.amount,
            })?;
            let signature = submit_private_transaction(
                SubmitPrivateTx {
                    rpc: &rpc,
                    indexer: &indexer,
                    material: &ctx.material,
                    tree,
                    prover_url: &network.prover_url,
                    withdrawal: None,
                    wait_tag: transfer.wait_tag,
                },
                transfer.signed,
            )?;
            println!(
                "ok transfer amount={} mint={} to={} mode=shielded signature={}",
                opts.amount,
                format_address(asset),
                transfer.recipient,
                signature
            );
        }
        TransferTarget::Public(recipient) => {
            let withdrawal = create_withdrawal_sync(CreateWithdrawal {
                wallet: &ctx.wallet,
                authority: &ctx.material,
                owner_pubkey,
                payer,
                recipient,
                asset,
                amount: opts.amount,
            })?;
            let signature = submit_private_transaction(
                SubmitPrivateTx {
                    rpc: &rpc,
                    indexer: &indexer,
                    material: &ctx.material,
                    tree,
                    prover_url: &network.prover_url,
                    withdrawal: Some(withdrawal.withdrawal),
                    wait_tag: withdrawal.wait_tag,
                },
                withdrawal.signed,
            )?;
            println!(
                "ok transfer amount={} mint={} to={} mode=withdraw signature={}",
                opts.amount,
                format_address(asset),
                recipient,
                signature
            );
        }
    }
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
    let assembled = assemble(signed, &proofs)?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => prover.prove_transfer_p256(inputs)?,
        ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs)?,
    };
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

#[cfg(test)]
mod tests {
    use zolana_keypair::ShieldedKeypair;

    use super::*;

    // The registry is never queried for a shielded-address string or invalid
    // input, so these branches resolve without touching the RPC.
    fn unused_rpc() -> SolanaRpc {
        SolanaRpc::new("http://127.0.0.1:0".to_string())
    }

    #[test]
    fn resolves_shielded_address_string_directly() {
        let address = ShieldedKeypair::new()
            .expect("keypair")
            .shielded_address()
            .expect("address");
        match resolve_transfer_recipient(&unused_rpc(), &address.to_string()).expect("resolve") {
            TransferTarget::Shielded(resolved) => assert_eq!(resolved, address),
            TransferTarget::Public(_) => {
                panic!("a shielded address must resolve to a shielded target")
            }
        }
    }

    #[test]
    fn rejects_input_that_is_neither_address_nor_pubkey() {
        let err = match resolve_transfer_recipient(&unused_rpc(), "definitely-not-valid") {
            Ok(_) => panic!("must reject an input that is neither an address nor a pubkey"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("shielded address"));
        assert!(err.to_string().contains("Solana pubkey"));
    }
}
