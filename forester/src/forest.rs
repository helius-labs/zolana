//! Submit a single `forest_address_tree` transaction against the registry.
//!
//! The forester reads a pre-built Groth16 proof for the shielded-pool's
//! address sub-tree (proof generation lives in `prover/client` and is wired in
//! a follow-up) and submits it via the registry's CPI authority. This module
//! handles the on-chain part: derive PDAs, build the instruction, sign, send.

use borsh::BorshSerialize;
use light_registry::constants::{CPI_AUTHORITY_PDA_SEED, FORESTER_EPOCH_SEED, FORESTER_SEED};
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::{instruction::BatchUpdateAddressTreeData, SHIELDED_POOL_PROGRAM_ID};

/// Anchor sighash for `light_registry::forest_address_tree` — the first 8
/// bytes of sha256("global:forest_address_tree"). Pinned by the unit test
/// below so a rename to either side is loud.
const FOREST_ADDRESS_TREE_DISCRIMINATOR: [u8; 8] = [0x34, 0x25, 0xfc, 0xdb, 0xad, 0xb6, 0xbe, 0x08];

#[derive(Debug, thiserror::Error)]
pub enum ForestError {
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("transaction failed: {0}")]
    TxFailed(String),
}

pub struct ForestParams<'a> {
    pub rpc_url: &'a str,
    pub forester: &'a Keypair,
    pub pool_tree: Pubkey,
    pub epoch: u64,
    pub batch_update: BatchUpdateAddressTreeData,
    /// `light_registry`'s declared program id.
    pub registry_program: Pubkey,
}

pub fn forest_address_tree_once(mut params: ForestParams<'_>) -> Result<Signature, ForestError> {
    let registry_program = params.registry_program;
    let forester_pubkey = params.forester.pubkey();

    // Derive PDAs.
    let (forester_pda, _) = Pubkey::find_program_address(
        &[FORESTER_SEED, forester_pubkey.as_ref()],
        &registry_program,
    );
    let (forester_epoch_pda, _) = Pubkey::find_program_address(
        &[
            FORESTER_EPOCH_SEED,
            forester_pda.as_ref(),
            &params.epoch.to_le_bytes(),
        ],
        &registry_program,
    );
    let (cpi_authority, cpi_bump) =
        Pubkey::find_program_address(&[CPI_AUTHORITY_PDA_SEED], &registry_program);

    // The bump is embedded in the instruction data so shielded-pool can
    // re-derive the CPI authority PDA and verify the signer.
    params.batch_update.cpi_authority_bump = cpi_bump;

    // Build instruction data: 8-byte anchor sighash + borsh-serialized args.
    let mut data = Vec::with_capacity(8 + 1 + 32 + 32 + 64 + 32);
    data.extend_from_slice(&FOREST_ADDRESS_TREE_DISCRIMINATOR);
    params
        .batch_update
        .serialize(&mut data)
        .expect("infallible");

    let shielded_pool_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let ix = Instruction {
        program_id: registry_program,
        accounts: vec![
            AccountMeta::new(forester_pubkey, true),
            AccountMeta::new_readonly(forester_pda, false),
            AccountMeta::new(forester_epoch_pda, false),
            AccountMeta::new(params.pool_tree, false),
            AccountMeta::new_readonly(cpi_authority, false),
            AccountMeta::new_readonly(shielded_pool_program, false),
        ],
        data,
    };

    let rpc =
        RpcClient::new_with_commitment(params.rpc_url.to_string(), CommitmentConfig::confirmed());
    let blockhash = rpc
        .get_latest_blockhash()
        .map_err(|e| ForestError::Rpc(e.to_string()))?;
    let msg = Message::new(&[ix], Some(&forester_pubkey));
    let tx = Transaction::new(&[params.forester], msg, blockhash);
    rpc.send_and_confirm_transaction(&tx)
        .map_err(|e| ForestError::TxFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the discriminator constant to anchor's real sha256("global:forest_address_tree").
    #[test]
    fn discriminator_matches_anchor() {
        use solana_sdk::hash::hash;
        let real = &hash(b"global:forest_address_tree").to_bytes()[..8];
        assert_eq!(real, &FOREST_ADDRESS_TREE_DISCRIMINATOR);
    }
}
