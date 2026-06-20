use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    create_transfer, CircuitType, CreateTransfer, InputCommitment, InputTreeIndices,
    ProofCompressed, ProverClient, Rpc, SignedTransaction, SolanaRpc, SpendProof,
    StateInclusionProof, ZolanaIndexer, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::instruction::{Transact, TransactWithdrawal};
use zolana_transaction::Address;

use crate::args::TransferOptions;
use crate::cli_config::CliConfigFile;

use super::material::WalletMaterial;
use super::resolve::get_network;
use super::sync::{sync_context, wait_for_indexed_transaction};
use super::util::{
    configured_spl_token_account, ensure_positive, format_address, parse_address, parse_pubkey,
};

pub(super) fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let asset = parse_address(&opts.mint)?;
    let config = CliConfigFile::load()?;
    let public_recipient_token_account = configured_spl_token_account(&config, asset)?;
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
        keypair: &ctx.material.keypair,
        payer: Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
        recipient_owner,
        asset,
        amount: opts.amount,
        assets: &ctx.assets,
        public_recipient_token_account,
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
