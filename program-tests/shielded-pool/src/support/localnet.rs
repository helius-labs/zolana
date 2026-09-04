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
use zolana_client::{PublicInputs, PublicTransfers, Rpc, SolanaRpc, TransferInput, TransferOutput};
use zolana_event::{indexed_events_from_instruction_groups, instruction_may_emit_events};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, TransactIxData},
        CreateProtocolConfig,
    },
    state::{default_tree_fees, nullifier_tree_params},
};
use zolana_program_test::{
    create_tree_instructions, index_events, parsed_instruction_from_compiled, IndexedEvent,
    IndexedTransaction, TestIndexer,
};
use zolana_test_utils::transact::{
    build_transfer_prover_inputs, dummy_transfer_output, eddsa_input_utxo, external_data_hash, fe,
    inline_outputs, new_transact_ix_data, output_owner_pk_hashes, prove_and_verify_transfer,
    set_output_owner_tags, sol_public_slots, ResolvedInterfaceTransfer, TransferProverInputsArgs,
};
use zolana_transaction::instructions::transact::PrivateTxHash;
use zolana_tree::TreeAccount;

pub struct LocalnetPool {
    pub payer: Keypair,
    pub authority: Keypair,
    pub tree: Pubkey,
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

    let create_tree = create_tree_instructions(
        rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        nullifier_tree_params(),
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .ok_or_else(|| anyhow!("default tree fees do not fit the zkp batch size"))?,
    )?;
    print_signature(
        "create_tree",
        &send_transaction(
            rpc,
            &create_tree.instructions,
            &payer.pubkey(),
            &[&payer, &authority],
        )?,
    );
    Ok(LocalnetPool {
        payer,
        authority,
        tree: create_tree.tree,
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

    let create_tree = create_tree_instructions(
        rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        nullifier_tree_params(),
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .ok_or_else(|| anyhow!("default tree fees do not fit the zkp batch size"))?,
    )?;
    let create_tree_tx = send_indexed(
        rpc,
        indexer,
        program_id,
        &create_tree.instructions,
        &payer.pubkey(),
        &[&payer, &authority],
    )?;
    print_signature("create_tree", &create_tree_tx.signature);
    Ok(LocalnetPool {
        payer,
        authority,
        tree: create_tree.tree,
    })
}

fn funded_pool_signers(rpc: &mut SolanaRpc) -> Result<(Keypair, Keypair)> {
    let payer = Keypair::new();
    let authority = Keypair::new();
    print_signature(
        "airdrop payer",
        &rpc.airdrop(&payer.pubkey(), 100_000_000_000)?,
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
        ring_creation_authority: authority_bytes.into(),
        ring_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
        fee_authority: authority_bytes.into(),
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

/// A 32-byte big-endian field element read back off a witness input.
fn field_bytes(value: &num_bigint::BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Inputs for [`build_sol_transfer_witness`]: the indexer-agnostic half of a
/// two-input/three-output SOL transfer or withdrawal. Callers fetch the
/// merkle/non-inclusion proofs and assemble the spend inputs their own way
/// (local `TestIndexer` mirrors or a Photon indexer); this helper owns
/// everything from instruction-data assembly through prover submission. The
/// per-slot nullifiers and (UTXO, nullifier) roots the proof binds are read
/// back off `spend_inputs`, so callers pass no parallel vectors for them.
pub struct SolTransferWitnessArgs {
    /// Witness inputs in slot order (real spend input first, then dummies).
    pub spend_inputs: Vec<TransferInput>,
    /// UTXO-tree root index the eddsa input slots bind to.
    pub root_index: u16,
    /// Output utxo hashes and their owner view tags, per output slot.
    pub output_hashes: Vec<[u8; 32]>,
    pub view_tags: Vec<[u8; 32]>,
    /// Witness outputs before `set_output_owner_tags` stamps the confidential tags.
    pub outputs: Vec<TransferOutput>,
    /// Per-output nullifier pubkeys (zero for dummies, whose owner is unconstrained).
    pub output_nullifier_pks: [[u8; 32]; 3],
    /// Declared interface transfers (empty for a pure shielded transfer).
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// Resolved interface transfers bound into the external-data hash.
    pub resolved_transfers: Vec<ResolvedInterfaceTransfer>,
    /// Private-tx-hash input/output leaves (zero-padded to the circuit shape).
    pub private_tx_inputs: [[u8; 32]; 2],
    pub private_tx_outputs: [[u8; 32]; 3],
    /// Public SOL movement field (zero when no SOL enters or leaves).
    pub public_sol_amount: [u8; 32],
    /// `hash_bytes` of the fee payer's address: the sole unique signer-run
    /// element for these flows (owner == payer), zero-padded to width 3.
    pub payer_pubkey_hash: [u8; 32],
    /// Label for hashing/prover error contexts ("transfer", "withdraw").
    pub label: &'static str,
}

/// Assemble a proven two-input/three-output `transact` instruction payload for
/// the SOL rail: build the instruction data from the declared inputs/outputs,
/// stamp witness owner tags, hash external data and public inputs, then prove
/// and locally verify the witness. Both localnet SOL cycles (`TestIndexer` and
/// Photon) share this; they differ only in how `spend_inputs` were fetched.
pub fn build_sol_transfer_witness(mut args: SolTransferWitnessArgs) -> Result<TransactIxData> {
    let nullifiers: Vec<[u8; 32]> = args
        .spend_inputs
        .iter()
        .map(|input| field_bytes(&input.nullifier))
        .collect();
    let utxo_roots: Vec<[u8; 32]> = args
        .spend_inputs
        .iter()
        .map(|input| field_bytes(&input.utxo_tree_root))
        .collect();
    let nullifier_roots: Vec<[u8; 32]> = args
        .spend_inputs
        .iter()
        .map(|input| field_bytes(&input.nullifier_tree_root))
        .collect();
    let mut ix_data = new_transact_ix_data(
        nullifiers
            .iter()
            .map(|nullifier| eddsa_input_utxo(*nullifier, args.root_index))
            .collect(),
        args.interface_transfers,
        inline_outputs(&args.output_hashes, &args.view_tags),
    );
    let owner_pk_hashes = output_owner_pk_hashes(&ix_data.outputs)
        .map_err(|err| anyhow!("{} output owner pk hashes: {err}", args.label))?;
    set_output_owner_tags(
        &mut args.outputs,
        &owner_pk_hashes,
        &args.output_nullifier_pks,
    );
    let external_hash = external_data_hash(&ix_data, &args.resolved_transfers)?;
    let private_tx = PrivateTxHash::new(
        &args.private_tx_inputs,
        &args.private_tx_outputs,
        &external_hash,
    )
    .hash()?;
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(args.public_sol_amount);
    let signer_hashes = [args.payer_pubkey_hash, [0u8; 32], [0u8; 32]];
    let public_input = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &args.output_hashes,
        utxo_roots: &utxo_roots,
        nullifier_tree_roots: &nullifier_roots,
        private_tx: &private_tx,
        external_data_hash: &external_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &[0u8; 32],
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()?;
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: args.spend_inputs,
        outputs: args.outputs,
        external_data_hash: external_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes.to_vec(),
        public_input_hash: public_input,
    });
    ix_data.proof = prove_and_verify_transfer(&prover_inputs, public_input, args.label)?;
    ix_data.private_tx_hash = private_tx;
    Ok(ix_data)
}

/// Build one dummy witness output per blinding, returning the outputs and
/// their utxo hashes in matching order. Used for all-dummy output sets (a full
/// withdrawal whose value leaves through the public SOL slot).
pub fn dummy_witness_outputs(
    blindings: &[[u8; 31]],
) -> Result<(Vec<TransferOutput>, Vec<[u8; 32]>)> {
    let pairs = blindings
        .iter()
        .map(|blinding| {
            dummy_transfer_output(blinding).map_err(|err| anyhow!("dummy output: {err}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(pairs.into_iter().unzip())
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

        let ring_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::RING_DEPOSIT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &ring_wrapper));

        let direct_transact = Message::new(
            &[Instruction {
                program_id: shielded_pool,
                accounts: Vec::new(),
                data: vec![tag::TRANSACT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &direct_transact));

        let ring_transact_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::RING_TRANSACT],
            }],
            None,
        );
        assert!(produces_shielded_events(
            shielded_pool,
            &ring_transact_wrapper
        ));

        let ring_merge_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::RING_MERGE_TRANSACT],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &ring_merge_wrapper));

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
