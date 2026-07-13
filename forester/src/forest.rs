//! Submit a single nullifier-tree maintenance transaction to SPP through the
//! forester's smart-account vault.
//!
//! The tree's `forester_authority` is a Squads smart-account vault (consistent
//! with the SPP's other protocol authorities), so the update is not signed by a
//! plain key: `execute_sync_ix` has the smart-account program CPI into the
//! shielded pool with the vault PDA as the signer, and the outer transaction is
//! signed by a smart-account member. Proof generation lives in `prover/client`;
//! this module handles submission once a compressed proof and root are ready.

use solana_commitment_config::CommitmentConfig;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::instruction::{BatchUpdateNullifierTree, BatchUpdateNullifierTreeData};
use zolana_smart_account_client::{execute_sync_ix, smart_account_pda};

#[derive(Debug, thiserror::Error)]
pub enum ForestError {
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("transaction failed: {0}")]
    TxFailed(String),
}

pub struct ForestParams<'a> {
    pub rpc_url: &'a str,
    /// Smart-account member that signs the outer transaction and pays fees.
    pub member: &'a Keypair,
    /// Forester smart-account settings account.
    pub settings: Pubkey,
    /// Vault index within the settings (the vault at this index is the tree's
    /// `forester_authority`).
    pub account_index: u8,
    pub pool_tree: Pubkey,
    pub batch_update: BatchUpdateNullifierTreeData,
}

/// Build the smart-account `execute_sync` instruction that CPIs
/// `batch_update_nullifier_tree` into SPP with `vault` as the signer.
pub fn build_forester_execute_ix(
    settings: &Pubkey,
    account_index: u8,
    member: &Pubkey,
    pool_tree: Pubkey,
    batch_update: &BatchUpdateNullifierTreeData,
) -> Instruction {
    let (vault, _) = smart_account_pda(settings, account_index);
    let inner = BatchUpdateNullifierTree {
        authority: vault,
        tree: pool_tree,
        new_root: batch_update.new_root,
        old_root: batch_update.old_root,
        zkp_batch_index: batch_update.zkp_batch_index,
        compressed_proof_a: batch_update.compressed_proof.a,
        compressed_proof_b: batch_update.compressed_proof.b,
        compressed_proof_c: batch_update.compressed_proof.c,
    }
    .instruction();
    execute_sync_ix(settings, account_index, &[*member], &[inner])
}

pub fn batch_update_nullifier_tree_once(
    params: ForestParams<'_>,
) -> Result<Signature, ForestError> {
    let member = params.member.pubkey();
    let execute = build_forester_execute_ix(
        &params.settings,
        params.account_index,
        &member,
        params.pool_tree,
        &params.batch_update,
    );

    let rpc =
        RpcClient::new_with_commitment(params.rpc_url.to_string(), CommitmentConfig::confirmed());
    let blockhash = rpc
        .get_latest_blockhash()
        .map_err(|e| ForestError::Rpc(e.to_string()))?;
    let msg = Message::new(&[execute], Some(&member));
    let tx = Transaction::new(&[params.member], msg, blockhash);
    rpc.send_and_confirm_transaction(&tx)
        .map_err(|e| ForestError::TxFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use solana_instruction::AccountMeta;
    use zolana_interface::{
        instruction::{encode_instruction, tag},
        pda, SHIELDED_POOL_PROGRAM_ID,
    };
    use zolana_smart_account_client::SMART_ACCOUNT_PROGRAM_ID;

    use super::*;

    fn sample_batch_update() -> BatchUpdateNullifierTreeData {
        BatchUpdateNullifierTreeData {
            new_root: [1u8; 32],
            old_root: [5u8; 32],
            zkp_batch_index: 0,
            compressed_proof: zolana_interface::instruction::CompressedProof {
                a: [2u8; 32],
                b: [3u8; 64],
                c: [4u8; 32],
            },
        }
    }

    #[test]
    fn inner_instruction_targets_spp_with_vault_authority() {
        let settings = Pubkey::new_unique();
        let tree = Pubkey::new_unique();
        let (vault, _) = smart_account_pda(&settings, 0);

        let ix = BatchUpdateNullifierTree {
            authority: vault,
            tree,
            new_root: [1u8; 32],
            old_root: [5u8; 32],
            zkp_batch_index: 0,
            compressed_proof_a: [2u8; 32],
            compressed_proof_b: [3u8; 64],
            compressed_proof_c: [4u8; 32],
        }
        .instruction();

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let data = BatchUpdateNullifierTreeData {
            new_root: [1u8; 32],
            old_root: [5u8; 32],
            zkp_batch_index: 0,
            compressed_proof: zolana_interface::instruction::CompressedProof {
                a: [2u8; 32],
                b: [3u8; 64],
                c: [4u8; 32],
            },
        };
        let expected = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(vault, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(tree, false),
                AccountMeta::new_readonly(program_id, false),
            ],
            data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &data),
        };

        assert_eq!(ix, expected);
    }

    #[test]
    fn execute_wraps_batch_update_for_smart_account() {
        let settings = Pubkey::new_unique();
        let member = Pubkey::new_unique();
        let tree = Pubkey::new_unique();

        let execute =
            build_forester_execute_ix(&settings, 0, &member, tree, &sample_batch_update());

        // Submitted instruction targets the smart-account program, carries the
        // settings account, and the member is an outer signer.
        assert_eq!(execute.program_id, SMART_ACCOUNT_PROGRAM_ID);
        assert_eq!(execute.accounts.first().unwrap().pubkey, settings);
        assert!(execute
            .accounts
            .iter()
            .any(|meta| meta.pubkey == member && meta.is_signer));
    }
}
