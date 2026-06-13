//! Local-validator proofless shield smoke.

use std::{
    error::Error,
    io,
    thread::sleep,
    time::{Duration, Instant},
};

use shielded_pool_program::instructions::create_tree::init::{
    state_root_offset, tree_account_size,
};
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CpiSignerData, CreateProtocolConfigData, CreateTreeData,
        ProoflessShieldEvent, ProoflessShieldIxData, ZoneProoflessShieldIxData,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPP_PROTOCOL_CONFIG_PDA_SEED,
};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::{
    proofless_shield_sol_instruction, zone_auth_pda, zone_proofless_shield_sol_instruction,
    PoolIndexer, PoolTestRig, ZONE_TEST_PROGRAM_ID,
};
use zolana_transaction::{Address, Blinding, Utxo, Wallet};

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
        airdrop_and_confirm(&rpc, &payer.pubkey(), 20_000_000_000)?,
    );
    print_signature(
        "airdrop authority",
        airdrop_and_confirm(&rpc, &authority.pubkey(), 1_000_000_000)?,
    );
    print_signature(
        "airdrop depositor",
        airdrop_and_confirm(&rpc, &depositor.pubkey(), 5_000_000_000)?,
    );

    let protocol_config =
        Pubkey::find_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], &program_id).0;
    let create_config = create_protocol_config_ix(program_id, authority.pubkey(), protocol_config);
    print_signature(
        "create_protocol_config",
        send_and_confirm(&rpc, &[create_config], &[&authority], &authority.pubkey())?,
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
        send_and_confirm(
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
    print_signature(
        "proofless_shield",
        send_and_confirm(&rpc, &[direct_ix], &[&payer, &depositor], &payer.pubkey())?,
    );
    let direct_root_after = state_root(&rpc, &tree.pubkey())?;
    assert_ne!(direct_root_after, direct_root_before);
    let direct_event = event_from_proofless(&direct_data, None)?;
    indexer.record_proofless_shield(&direct_event)?;
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
    print_signature(
        "zone_proofless_shield",
        send_and_confirm(&rpc, &[zone_ix], &[&payer, &depositor], &payer.pubkey())?,
    );
    let zone_root_after = state_root(&rpc, &tree.pubkey())?;
    assert_ne!(zone_root_after, zone_root_before);
    let zone_event = event_from_zone_proofless(&zone_data)?;
    indexer.record_proofless_shield(&zone_event)?;
    assert_eq!(zone_root_after, indexer.root());
    assert_wallet_discovers(&mut zone_recipient, &zone_event, zone_blinding)?;

    println!("localnet proofless shield smoke passed via {rpc_url}");
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

fn event_from_proofless(
    data: &ProoflessShieldIxData,
    zone: Option<([u8; 32], [u8; 32], Option<Vec<u8>>)>,
) -> Result<ProoflessShieldEvent, Box<dyn Error>> {
    let amount = data
        .public_sol_amount
        .ok_or_else(|| io::Error::other("expected SOL proofless data"))?;
    let (zone_program_id, policy_data_hash, zone_data) = match zone {
        Some((program_id, hash, zone_data)) => (Some(program_id), Some(hash), zone_data),
        None => (None, None, None),
    };
    let program_data_hash = data.program_data_hash.unwrap_or([0u8; 32]);
    let zone_data_hash = policy_data_hash.unwrap_or([0u8; 32]);
    let utxo_hash = Utxo::commitment_from_owner_utxo_hash(
        Address::new_from_array([0u8; 32]),
        amount,
        &program_data_hash,
        &zone_data_hash,
        zone_program_id.map(Address::new_from_array),
        &data.owner_utxo_hash,
    )?;
    Ok(ProoflessShieldEvent {
        view_tag: data.view_tag,
        utxo_hash,
        asset: [0u8; 32],
        amount,
        zone_program_id,
        policy_data_hash,
        owner_utxo_hash: data.owner_utxo_hash,
        salt: data.salt,
        program_data_hash: data.program_data_hash,
        program_data: data.program_data.clone(),
        zone_data,
    })
}

fn event_from_zone_proofless(
    data: &ZoneProoflessShieldIxData,
) -> Result<ProoflessShieldEvent, Box<dyn Error>> {
    let proofless = ProoflessShieldIxData {
        view_tag: data.view_tag,
        owner_utxo_hash: data.owner_utxo_hash,
        salt: data.salt,
        public_sol_amount: data.public_sol_amount,
        public_spl_amount: data.public_spl_amount,
        program_data_hash: data.program_data_hash,
        program_data: data.program_data.clone(),
        cpi_signer: Some(data.cpi_signer),
    };
    event_from_proofless(
        &proofless,
        Some((
            data.cpi_signer.program_id,
            data.policy_data_hash.unwrap_or([0u8; 32]),
            data.zone_data.clone(),
        )),
    )
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

fn system_create_account_ix(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
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

fn print_signature(label: &str, signature: solana_signature::Signature) {
    println!("{label}: {signature}");
}
