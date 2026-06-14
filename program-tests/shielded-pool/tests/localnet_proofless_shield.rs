//! Local-validator proofless shield test.

use std::{
    error::Error,
    io,
    thread::sleep,
    time::{Duration, Instant},
};

use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::api::config::RpcTransactionConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransaction, UiInstruction, UiMessage,
    UiTransactionEncoding,
};
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CpiSignerData, CreateProtocolConfigData, CreateTreeData,
        ProoflessShieldEvent, ZoneProoflessShieldIxData,
    },
    state::{state_root_offset, tree_account_size},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPP_PROTOCOL_CONFIG_PDA_SEED,
};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::{
    index_events, indexed_events_from_instructions, proofless_shield_sol_instruction,
    single_proofless_shield_event, system_create_account_ix, zone_auth_pda,
    zone_proofless_shield_sol_instruction, ParsedInstruction, PoolIndexer, PoolTestRig,
    ZONE_TEST_PROGRAM_ID,
};
use zolana_transaction::{Blinding, Wallet};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEPOSIT_LAMPORTS: u64 = 750_000_000;

#[test]
fn proofless_shield_sol_on_localnet_prints_signatures() -> Result<(), Box<dyn Error>> {
    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let rpc = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let zone_program_id = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
    assert_executable(&rpc, &program_id)?;
    assert_executable(&rpc, &zone_program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let depositor = Keypair::new();
    print_signature(
        "airdrop payer",
        &airdrop_and_confirm(&rpc, &payer.pubkey(), 20_000_000_000)?,
    );
    print_signature(
        "airdrop authority",
        &airdrop_and_confirm(&rpc, &authority.pubkey(), 1_000_000_000)?,
    );
    print_signature(
        "airdrop depositor",
        &airdrop_and_confirm(&rpc, &depositor.pubkey(), 5_000_000_000)?,
    );

    let protocol_config =
        Pubkey::find_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], &program_id).0;
    let create_config = create_protocol_config_ix(program_id, authority.pubkey(), protocol_config);
    print_signature(
        "create_protocol_config",
        &send_and_confirm(&rpc, &[create_config], &[&authority], &authority.pubkey())?,
    );

    let tree = Keypair::new();
    let create_tree = create_tree_ixs(
        &rpc,
        program_id,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
    )?;
    print_signature(
        "create_tree",
        &send_and_confirm(
            &rpc,
            &create_tree,
            &[&payer, &tree, &authority],
            &payer.pubkey(),
        )?,
    );

    let mut indexer = PoolIndexer::new();

    let mut direct_recipient = Wallet::new(ShieldedKeypair::new()?)?;
    let (direct_data, direct_blinding) = PoolTestRig::wallet_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &direct_recipient,
        &[3u8; BLINDING_LEN],
        0,
    )?;
    let direct_root_before = state_root(&rpc, &tree.pubkey())?;
    let direct_ix = proofless_shield_sol_instruction(
        program_id,
        tree.pubkey(),
        depositor.pubkey(),
        Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY),
        &direct_data,
    );
    let direct_signature =
        send_and_confirm(&rpc, &[direct_ix], &[&payer, &depositor], &payer.pubkey())?;
    print_signature("proofless_shield", &direct_signature);
    let direct_root_after = state_root(&rpc, &tree.pubkey())?;
    assert_ne!(direct_root_after, direct_root_before);
    let direct_event =
        index_proofless_event_from_transaction(&rpc, &mut indexer, program_id, &direct_signature)?;
    assert_eq!(direct_root_after, indexer.root());
    assert_wallet_discovers(&mut direct_recipient, &direct_event, direct_blinding)?;

    let mut zone_recipient = Wallet::new(ShieldedKeypair::new()?)?;
    let (zone_auth, zone_auth_bump) = zone_auth_pda(&zone_program_id);
    let (mut zone_data, zone_blinding) = wallet_zone_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &zone_recipient,
        &[5u8; BLINDING_LEN],
        0,
        zone_auth_bump,
    )?;
    zone_data.policy_data_hash = Some([5u8; 32]);
    let zone_root_before = state_root(&rpc, &tree.pubkey())?;
    let zone_ix = zone_proofless_shield_sol_instruction(
        program_id,
        zone_program_id,
        tree.pubkey(),
        depositor.pubkey(),
        zone_auth,
        Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY),
        &zone_data,
    );
    let zone_signature =
        send_and_confirm(&rpc, &[zone_ix], &[&payer, &depositor], &payer.pubkey())?;
    print_signature("zone_proofless_shield", &zone_signature);
    let zone_root_after = state_root(&rpc, &tree.pubkey())?;
    assert_ne!(zone_root_after, zone_root_before);
    let zone_event =
        index_proofless_event_from_transaction(&rpc, &mut indexer, program_id, &zone_signature)?;
    assert_eq!(zone_root_after, indexer.root());
    assert_wallet_discovers(&mut zone_recipient, &zone_event, zone_blinding)?;

    println!("localnet proofless shield test passed via {rpc_url}");
    Ok(())
}

fn create_protocol_config_ix(
    program_id: Pubkey,
    authority: Pubkey,
    protocol_config: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(protocol_config, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(
            tag::CREATE_PROTOCOL_CONFIG,
            &CreateProtocolConfigData {
                authority: authority.to_bytes(),
                merge_authorities: Vec::new(),
            },
        ),
    }
}

fn create_tree_ixs(
    rpc: &RpcClient,
    program_id: Pubkey,
    payer: &Pubkey,
    authority: &Pubkey,
    tree: &Pubkey,
) -> Result<Vec<Instruction>, Box<dyn Error>> {
    let account_size = tree_account_size() as u64;
    let rent = rpc.get_minimum_balance_for_rent_exemption(account_size as usize)?;
    let create_account = system_create_account_ix(payer, tree, rent, account_size, &program_id);
    let create_tree = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], &program_id).0,
                false,
            ),
            AccountMeta::new(*tree, false),
        ],
        data: encode_instruction(tag::CREATE_TREE, &CreateTreeData),
    };
    Ok(vec![create_account, create_tree])
}

fn wallet_zone_sol_shield_data(
    lamports: u64,
    recipient: &Wallet,
    blinding_seed: &[u8; BLINDING_LEN],
    position: u8,
    zone_auth_bump: u8,
) -> Result<(ZoneProoflessShieldIxData, Blinding), Box<dyn Error>> {
    let (data, blinding) =
        PoolTestRig::wallet_sol_shield_data(lamports, recipient, blinding_seed, position)?;
    Ok((
        ZoneProoflessShieldIxData {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_sol_amount: data.public_sol_amount,
            public_spl_amount: data.public_spl_amount,
            cpi_signer: CpiSignerData {
                program_id: ZONE_TEST_PROGRAM_ID,
                bump: zone_auth_bump,
            },
            policy_data_hash: None,
            zone_data: None,
            program_data_hash: None,
            program_data: None,
        },
        blinding,
    ))
}

fn assert_wallet_discovers(
    wallet: &mut Wallet,
    event: &ProoflessShieldEvent,
    blinding: Blinding,
) -> Result<(), Box<dyn Error>> {
    let event = zolana_program_test::proofless_event_for_wallet(event);
    assert!(wallet.sync_proofless_deposit(&event, blinding)?);
    assert_eq!(wallet.utxos.len(), 1);
    assert_eq!(wallet.utxos[0].hash, event.utxo_hash);
    Ok(())
}

fn index_proofless_event_from_transaction(
    rpc: &RpcClient,
    indexer: &mut PoolIndexer,
    program_id: Pubkey,
    signature: &Signature,
) -> Result<ProoflessShieldEvent, Box<dyn Error>> {
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };
    let transaction = rpc.get_transaction_with_config(signature, config)?;
    let encoded = transaction.transaction;
    let meta = encoded
        .meta
        .ok_or_else(|| io::Error::other("transaction missing metadata"))?;
    let account_keys = account_keys_from_transaction(encoded.transaction)?;
    let inner = match meta.inner_instructions {
        OptionSerializer::Some(inner) => inner,
        OptionSerializer::None | OptionSerializer::Skip => {
            return Err(io::Error::other("transaction missing inner instructions").into());
        }
    };
    let instructions = inner
        .iter()
        .flat_map(|inner| inner.instructions.iter())
        .map(|instruction| parsed_instruction_from_ui(instruction, &account_keys))
        .collect::<Result<Vec<_>, _>>()?;
    let events = indexed_events_from_instructions(program_id, &instructions)?;
    index_events(indexer, &events)?;
    Ok(single_proofless_shield_event(&events)?)
}

fn account_keys_from_transaction(
    transaction: EncodedTransaction,
) -> Result<Vec<Pubkey>, Box<dyn Error>> {
    let EncodedTransaction::Json(transaction) = transaction else {
        return Err(io::Error::other("expected JSON-encoded transaction").into());
    };
    let UiMessage::Raw(message) = transaction.message else {
        return Err(io::Error::other("expected raw transaction message").into());
    };
    message
        .account_keys
        .into_iter()
        .map(|key| key.parse::<Pubkey>().map_err(Into::into))
        .collect()
}

fn parsed_instruction_from_ui(
    instruction: &UiInstruction,
    account_keys: &[Pubkey],
) -> Result<ParsedInstruction, Box<dyn Error>> {
    let UiInstruction::Compiled(instruction) = instruction else {
        return Err(io::Error::other("expected compiled inner instruction").into());
    };
    let program_id = account_keys
        .get(instruction.program_id_index as usize)
        .copied()
        .ok_or_else(|| io::Error::other("inner instruction program id index out of bounds"))?;
    let accounts = instruction
        .accounts
        .iter()
        .map(|index| {
            account_keys.get(*index as usize).copied().ok_or_else(|| {
                io::Error::other(format!(
                    "inner instruction account index {index} out of bounds"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedInstruction {
        program_id,
        accounts,
        data: bs58::decode(&instruction.data).into_vec()?,
    })
}

fn state_root(rpc: &RpcClient, tree: &Pubkey) -> Result<[u8; 32], Box<dyn Error>> {
    let account = rpc.get_account(tree)?;
    let offset = state_root_offset();
    let slice = account
        .data
        .get(offset..offset + 32)
        .ok_or_else(|| io::Error::other("tree account missing state root"))?;
    let mut root = [0u8; 32];
    root.copy_from_slice(slice);
    Ok(root)
}

fn assert_executable(rpc: &RpcClient, program_id: &Pubkey) -> Result<(), Box<dyn Error>> {
    let account = rpc.get_account(program_id)?;
    if !account.executable {
        return Err(io::Error::other(format!("program is not executable: {program_id}")).into());
    }
    Ok(())
}

fn airdrop_and_confirm(
    rpc: &RpcClient,
    pubkey: &Pubkey,
    lamports: u64,
) -> Result<solana_signature::Signature, Box<dyn Error>> {
    let signature = rpc.request_airdrop(pubkey, lamports)?;
    wait_for_signature(rpc, &signature)?;
    Ok(signature)
}

fn send_and_confirm(
    rpc: &RpcClient,
    instructions: &[Instruction],
    signers: &[&Keypair],
    payer: &Pubkey,
) -> Result<solana_signature::Signature, Box<dyn Error>> {
    let blockhash = rpc.get_latest_blockhash()?;
    let message = Message::new(instructions, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    let signature = rpc.send_and_confirm_transaction(&transaction)?;
    Ok(signature)
}

fn wait_for_signature(
    rpc: &RpcClient,
    signature: &solana_signature::Signature,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if rpc.confirm_transaction(signature)? {
            return Ok(());
        }
        sleep(Duration::from_millis(250));
    }
    Err(io::Error::other(format!("signature not confirmed: {signature}")).into())
}

fn print_signature(label: &str, signature: &solana_signature::Signature) {
    println!("{label}: {signature}");
}
