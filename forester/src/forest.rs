//! Submit a single nullifier-tree maintenance transaction to SPP.
//!
//! Proof generation lives in `prover/client`; this module handles the on-chain
//! submission path once a compressed proof and proposed root are available.

use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::instruction::{BatchUpdateNullifierTree, BatchUpdateNullifierTreeData};

#[derive(Debug, thiserror::Error)]
pub enum ForestError {
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("transaction failed: {0}")]
    TxFailed(String),
}

pub struct ForestParams<'a> {
    pub rpc_url: &'a str,
    pub authority: &'a Keypair,
    pub pool_tree: Pubkey,
    pub batch_update: BatchUpdateNullifierTreeData,
}

pub fn batch_update_nullifier_tree_once(
    params: ForestParams<'_>,
) -> Result<Signature, ForestError> {
    let authority = params.authority.pubkey();
    let batch_update = params.batch_update;
    let ix = BatchUpdateNullifierTree {
        authority,
        tree: params.pool_tree,
        new_root: batch_update.new_root,
        old_root: batch_update.old_root,
        zkp_batch_index: batch_update.zkp_batch_index,
        compressed_proof_a: batch_update.compressed_proof.a,
        compressed_proof_b: batch_update.compressed_proof.b,
        compressed_proof_c: batch_update.compressed_proof.c,
    }
    .instruction();

    let rpc =
        RpcClient::new_with_commitment(params.rpc_url.to_string(), CommitmentConfig::confirmed());
    let blockhash = rpc
        .get_latest_blockhash()
        .map_err(|e| ForestError::Rpc(e.to_string()))?;
    let msg = Message::new(&[ix], Some(&authority));
    let tx = Transaction::new(&[params.authority], msg, blockhash);
    rpc.send_and_confirm_transaction(&tx)
        .map_err(|e| ForestError::TxFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use zolana_interface::{instruction::tag, pda, SHIELDED_POOL_PROGRAM_ID};

    use super::*;

    #[test]
    fn maintenance_instruction_targets_spp() {
        let authority = Pubkey::new_unique();
        let tree = Pubkey::new_unique();
        let ix = BatchUpdateNullifierTree {
            authority,
            tree,
            new_root: [1u8; 32],
            old_root: [5u8; 32],
            zkp_batch_index: 0,
            compressed_proof_a: [2u8; 32],
            compressed_proof_b: [3u8; 64],
            compressed_proof_c: [4u8; 32],
        }
        .instruction();

        assert_eq!(
            ix.program_id,
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
        );
        assert_eq!(ix.data[0], tag::BATCH_UPDATE_NULLIFIER_TREE);
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts[0].pubkey, authority);
        assert!(ix.accounts[0].is_signer);
        assert_eq!(ix.accounts[1].pubkey, pda::protocol_config());
        assert_eq!(ix.accounts[2].pubkey, tree);
        assert!(ix.accounts[2].is_writable);
        // Program account last, loadable for the `emit_event` self-CPI.
        assert_eq!(
            ix.accounts[3].pubkey,
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
        );
    }
}
