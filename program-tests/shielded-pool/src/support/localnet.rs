//! Shared Solana RPC helpers for shielded-pool local-validator tests.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{Rpc, SolanaRpc};
use zolana_event::{indexed_events_from_instruction_groups, instruction_may_emit_events};
use zolana_interface::{instruction::CreateProtocolConfig, state::tree_account_size};
use zolana_program_test::{
    create_tree_instructions, index_events, parsed_instruction_from_compiled, IndexedEvent,
    IndexedTransaction, TestIndexer,
};
use zolana_tree::TreeAccount;

pub struct LocalnetPool {
    pub payer: Keypair,
    pub authority: Keypair,
    pub tree: Keypair,
}

/// Fund the standard payer and authority, then create a protocol config and
/// tree through ordinary Solana RPC transactions.
pub fn initialize_pool(rpc: &mut SolanaRpc) -> Result<LocalnetPool> {
    let (payer, authority) = funded_pool_signers(rpc)?;
    let create_config = protocol_config_instruction(&authority);
    print_signature(
        "create_protocol_config",
        &send_transaction(rpc, &[create_config], &authority.pubkey(), &[&authority])?,
    );

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    print_signature(
        "create_tree",
        &send_transaction(
            rpc,
            &create_tree,
            &payer.pubkey(),
            &[&payer, &tree, &authority],
        )?,
    );
    Ok(LocalnetPool {
        payer,
        authority,
        tree,
    })
}

/// [`initialize_pool`] with event-aware sends through the test indexer.
pub fn initialize_indexed_pool(
    rpc: &mut SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
) -> Result<LocalnetPool> {
    let (payer, authority) = funded_pool_signers(rpc)?;
    let create_config = protocol_config_instruction(&authority);
    let create_config_tx = send_indexed(
        rpc,
        indexer,
        program_id,
        &[create_config],
        &authority.pubkey(),
        &[&authority],
    )?;
    print_signature("create_protocol_config", &create_config_tx.signature);

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    let create_tree_tx = send_indexed(
        rpc,
        indexer,
        program_id,
        &create_tree,
        &payer.pubkey(),
        &[&payer, &tree, &authority],
    )?;
    print_signature("create_tree", &create_tree_tx.signature);
    Ok(LocalnetPool {
        payer,
        authority,
        tree,
    })
}

fn funded_pool_signers(rpc: &mut SolanaRpc) -> Result<(Keypair, Keypair)> {
    let payer = Keypair::new();
    let authority = Keypair::new();
    print_signature(
        "airdrop payer",
        &rpc.airdrop(&payer.pubkey(), 20_000_000_000)?,
    );
    print_signature(
        "airdrop authority",
        &rpc.airdrop(&authority.pubkey(), 1_000_000_000)?,
    );
    Ok((payer, authority))
}

fn protocol_config_instruction(authority: &Keypair) -> Instruction {
    let authority_bytes = authority.pubkey().to_bytes();
    CreateProtocolConfig {
        authority: authority.pubkey(),
        protocol_authority: authority_bytes.into(),
        tree_creation_authority: authority_bytes.into(),
        tree_creation_is_permissionless: false,
        forester_authority: authority_bytes.into(),
        zone_creation_authority: authority_bytes.into(),
        zone_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction()
}

/// Read the UTXO root at `utxo_index` and nullifier root at history index zero.
pub fn on_chain_roots(
    rpc: &SolanaRpc,
    tree: &Pubkey,
    utxo_index: u16,
) -> Result<([u8; 32], [u8; 32])> {
    let address = Address::new_from_array(tree.to_bytes());
    let mut data = rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("load tree account: {err:?}"))?;
    Ok((
        account
            .get_utxo_tree_root(utxo_index)
            .map_err(|err| anyhow!("get utxo root {utxo_index}: {err:?}"))?,
        account
            .get_nullifier_tree_root(0)
            .map_err(|err| anyhow!("get nullifier root: {err:?}"))?,
    ))
}

/// Return an account's lamports, treating a missing account as zero.
pub fn account_lamports(rpc: &SolanaRpc, pubkey: &Pubkey) -> Result<u64> {
    let address = Address::new_from_array(pubkey.to_bytes());
    Ok(rpc
        .get_account(address)?
        .map(|account| account.lamports)
        .unwrap_or(0))
}

/// Send a transaction and index any shielded-pool events it can emit.
pub fn send_indexed(
    rpc: &mut SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
    instructions: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> Result<IndexedTransaction> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(instructions, Some(payer));
    let produces_events = produces_shielded_events(program_id, &message);
    let transaction = Transaction::new(signers, message, blockhash);
    let signature = rpc.send_transaction(&transaction)?;
    let events = if produces_events {
        fetch_indexed_events(rpc, indexer, program_id, &signature)?
    } else {
        Vec::new()
    };
    Ok(IndexedTransaction { signature, events })
}

pub fn send_transaction(
    rpc: &mut SolanaRpc,
    instructions: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> Result<Signature> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(instructions, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    Ok(rpc.send_transaction(&transaction)?)
}

fn fetch_indexed_events(
    rpc: &SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
    signature: &Signature,
) -> Result<Vec<IndexedEvent>> {
    let confirmed = rpc.fetch_confirmed_instruction_groups(signature)?;
    let events = indexed_events_from_instruction_groups(program_id, &confirmed.groups);
    index_events(indexer, &events, *signature)?;
    Ok(events)
}

/// Whether a message contains a shielded-pool instruction that can emit events.
pub fn produces_shielded_events(program_id: Pubkey, message: &Message) -> bool {
    message.instructions.iter().any(|instruction| {
        parsed_instruction_from_compiled(&message.account_keys, instruction, Some(1))
            .is_ok_and(|instruction| instruction_may_emit_events(program_id, &instruction))
    })
}

pub fn print_signature(label: &str, signature: &Signature) {
    println!("{label}: {signature}");
}

#[cfg(test)]
mod tests {
    use solana_instruction::{AccountMeta, Instruction};
    use zolana_interface::instruction::tag;

    use super::*;

    #[test]
    fn shielded_event_detection_checks_program_context() {
        let shielded_pool = Pubkey::new_unique();
        let other_program = Pubkey::new_unique();

        let unrelated = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: Vec::new(),
                data: vec![tag::DEPOSIT],
            }],
            None,
        );
        assert!(!produces_shielded_events(shielded_pool, &unrelated));

        let direct = Message::new(
            &[Instruction {
                program_id: shielded_pool,
                accounts: Vec::new(),
                data: vec![tag::DEPOSIT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &direct));

        let zone_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::ZONE_DEPOSIT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &zone_wrapper));

        let direct_transact = Message::new(
            &[Instruction {
                program_id: shielded_pool,
                accounts: Vec::new(),
                data: vec![tag::TRANSACT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &direct_transact));

        let zone_transact_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::ZONE_TRANSACT],
            }],
            None,
        );
        assert!(produces_shielded_events(
            shielded_pool,
            &zone_transact_wrapper
        ));

        let zone_merge_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::ZONE_MERGE_TRANSACT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &zone_merge_wrapper));

        let false_positive = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::TRANSACT],
            }],
            None,
        );
        assert!(!produces_shielded_events(shielded_pool, &false_positive));
    }
}
