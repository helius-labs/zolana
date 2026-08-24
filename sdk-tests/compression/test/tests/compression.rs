use std::{path::Path, process::Command};

use anyhow::{anyhow, bail, Context, Result};
use num_bigint::BigUint;
use solana_address::{address, Address};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    prover::field::be, ProofCompressed, ProverClient, PublicInputs, PublicTransfers, Rpc,
    SolanaRpc, TransferInput, TransferInputs, TransferOutput, ZolanaIndexer, STATE_TREE_HEIGHT,
};
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput,
        },
        Transact,
    },
    ADDRESS_DOMAIN, DEFAULT_TREE_ADDRESS, N_PUBLIC_SLOTS,
};
use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey, ShieldedAddress, ViewingKey};
use zolana_test_utils::{
    localnet::{isolated_temp_path, LocalnetValidator, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
    test_validator_asserts::{wait_for_indexed_utxo, wait_for_non_inclusion_proof},
};
use zolana_transaction::{
    instructions::{
        transact::{PrivateTxHash, SppProofInputs},
        types::SppProofInputUtxo,
    },
    serialization::{
        plaintext::{PlaintextEncode, PlaintextTransfer},
        OwnerCx, UtxoSerialization,
    },
    AssetRegistry, Data, DataRecord, ExternalData, ProofInputUtxo, SppProofOutputUtxo, Utxo,
    WalletUtxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

const ACCOUNT_PDA_SEED: &[u8] = b"compressed-account";
const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";
const CREATE: u8 = 0;
const UPDATE: u8 = 1;
const RECIPIENT_POSITION: u8 = 2;
const STATE_DATA_LEN: usize = 72;
const TRANSACT_CU_LIMIT: u32 = 1_400_000;
const SPP_PROGRAM: Address = address!("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");

struct Environment {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    authority: Keypair,
    tree: Address,
}

struct AccountState {
    address: [u8; 32],
    authority: [u8; 32],
    value: u64,
}

struct BuiltTransaction {
    instruction: Instruction,
    output: Utxo,
    output_hash: [u8; 32],
    input_nullifier: [u8; 32],
}

fn setup() -> Result<Environment> {
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."));
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let xtask = artifacts.path("target/debug/xtask");
    let account_dir = isolated_temp_path("zolana-compression-accounts");
    let ledger = isolated_temp_path("zolana-compression-ledger");
    for (label, path) in [("zolana CLI", cli.as_str()), ("xtask", xtask.as_str())] {
        if !Path::new(path).is_file() {
            bail!("{label} is missing at {path}; build it before running this test");
        }
    }
    let snapshot_status = Command::new(&xtask)
        .current_dir(artifacts.root())
        .args([
            "generate-account-snapshots",
            "--deploy-dir",
            "target/deploy",
            "--accounts-dir",
            &account_dir,
        ])
        .status()
        .context("generate canonical default-tree snapshots")?;
    if !snapshot_status.success() {
        bail!("default-tree snapshot generation failed");
    }

    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".into());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".into());
    LocalnetValidator {
        cli_bin: cli,
        working_dir: artifacts.root(),
        rpc_port: rpc_port.clone(),
        photon_port: photon_port.clone(),
        ledger,
        account_dir,
        programs: vec![
            (
                compression_example_program::ID.to_string(),
                artifacts.path("target/deploy/compression_example_program.so"),
            ),
            (
                SPP_PROGRAM.to_string(),
                artifacts.path("target/deploy/shielded_pool_program.so"),
            ),
        ],
    }
    .start();
    spawn_workspace_prover();

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{rpc_port}"));
    let indexer_url = std::env::var("ZOLANA_INDEXER_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{photon_port}"));
    let mut rpc = SolanaRpc::new(rpc_url);
    let authority = Keypair::new();
    rpc.airdrop(&authority.pubkey(), 10_000_000_000)?;
    let tree = DEFAULT_TREE_ADDRESS
        .parse::<Address>()
        .context("parse default tree address")?;
    if rpc.get_account(tree)?.is_none() {
        bail!("default tree {tree} was not loaded");
    }
    Ok(Environment {
        rpc,
        indexer: ZolanaIndexer::new(indexer_url),
        authority,
        tree,
    })
}

fn account_pda(authority: &Address) -> Address {
    Address::find_program_address(
        &[ACCOUNT_PDA_SEED, authority.as_array()],
        &compression_example_program::ID,
    )
    .0
}

fn zero_nullifier_key() -> NullifierKey {
    NullifierKey::from_secret([0u8; 31])
}

fn field_u64(value: u64) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

fn decode_state(data: &[u8]) -> Result<AccountState> {
    if data.len() != STATE_DATA_LEN {
        bail!(
            "state data has {} bytes, expected {STATE_DATA_LEN}",
            data.len()
        );
    }
    let address = data
        .get(..32)
        .ok_or_else(|| anyhow!("missing address"))?
        .try_into()
        .map_err(|_| anyhow!("invalid address"))?;
    let authority = data
        .get(32..64)
        .ok_or_else(|| anyhow!("missing authority"))?
        .try_into()
        .map_err(|_| anyhow!("invalid authority"))?;
    let value = u64::from_le_bytes(
        data.get(64..72)
            .ok_or_else(|| anyhow!("missing value"))?
            .try_into()
            .map_err(|_| anyhow!("invalid value"))?,
    );
    Ok(AccountState {
        address,
        authority,
        value,
    })
}

fn encode_state(address: [u8; 32], authority: [u8; 32], value: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(STATE_DATA_LEN);
    data.extend_from_slice(&address);
    data.extend_from_slice(&authority);
    data.extend_from_slice(&value.to_le_bytes());
    data
}

fn state_data_hash(state: &AccountState) -> Result<[u8; 32]> {
    let domain = hash_bytes(ACCOUNT_DATA_DOMAIN)?;
    let authority = hash_bytes(&state.authority)?;
    Ok(Poseidon::hashv(&[
        &state.address,
        &domain,
        &authority,
        &field_u64(state.value),
    ])?)
}

fn address_input(pda: &Address) -> Result<(ProofInputUtxo, [u8; 32], [u8; 32])> {
    let key = zero_nullifier_key();
    let nullifier_pk = key.pubkey()?;
    let owner = PublicKey::from_pda(pda);
    let address_seed = hash_bytes(pda.as_array())?;
    let input = ProofInputUtxo {
        domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
        owner_hash: owner_hash(&owner, &nullifier_pk)?,
        blinding: address_seed,
        ..ProofInputUtxo::default()
    };
    let input_hash = input.hash()?;
    let address = key.nullifier(&input_hash, &address_seed)?;
    Ok((input, input_hash, address))
}

fn pda_address(pda: &Address) -> Result<ShieldedAddress> {
    Ok(ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(pda),
        nullifier_pubkey: zero_nullifier_key().pubkey()?,
        viewing_pubkey: ViewingKey::from_bytes(&[5u8; 32])?.pubkey(),
    })
}

fn output_for(
    pda: &Address,
    authority: &Address,
    address: [u8; 32],
    value: u64,
    output_seed: [u8; 32],
) -> Result<(SppProofOutputUtxo, Utxo, Vec<u8>, [u8; 32])> {
    let state = AccountState {
        address,
        authority: authority.to_bytes(),
        value,
    };
    let state_data = encode_state(state.address, state.authority, state.value);
    let data_hash = state_data_hash(&state)?;
    let blinding = zolana_transaction::derive_blinding(&output_seed, RECIPIENT_POSITION);
    let owner = PublicKey::from_pda(pda);
    let utxo = Utxo {
        owner,
        asset: SOL_MINT,
        amount: 0,
        blinding,
        ring_program_id: None,
        data: Data::new(vec![DataRecord::UtxoData(state_data.clone())]),
    };
    let output = SppProofOutputUtxo {
        asset: SOL_MINT,
        amount: 0,
        blinding,
        data_hash: Some(data_hash),
        owner_address: Some(pda_address(pda)?),
        owner_tag: Some(pda.to_bytes()),
        data: utxo.data.clone(),
        ..SppProofOutputUtxo::default()
    };
    let encoded = PlaintextTransfer::encode(
        core::slice::from_ref(&utxo),
        &OwnerCx {
            owner,
            assets: &AssetRegistry::default(),
            ring_program_id: None,
        },
        pda.to_bytes(),
        &PlaintextEncode {
            blinding_seed: output_seed,
        },
    )?;
    Ok((output, utxo, encoded.data, data_hash))
}

fn external_data(output_hash: [u8; 32], pda: &Address, payload: Vec<u8>) -> ExternalData {
    ExternalData::new(
        [0u8; 33],
        [0u8; 16],
        vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(pda.to_bytes()),
            data: Some(payload),
        }],
        vec![pda.to_bytes()],
        Vec::new(),
    )
}

fn tree_root(rpc: &SolanaRpc, tree: Address) -> Result<(u16, [u8; 32])> {
    let mut data = rpc
        .get_account(tree)?
        .ok_or_else(|| anyhow!("tree account {tree} is missing"))?
        .data;
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|error| anyhow!("load tree: {error:?}"))?;
    let index = account.utxo_tree().current_root_index();
    let root = account
        .get_utxo_tree_root(index)
        .map_err(|error| anyhow!("read state root: {error:?}"))?;
    Ok((index, root))
}

fn wrap_instruction(
    authority: Address,
    pda: Address,
    tree: Address,
    transact: TransactIxData,
    mut wrapper_data: Vec<u8>,
) -> Result<Instruction> {
    let mut instruction = Transact {
        payer: authority,
        input_tree: tree,
        output_tree: tree,
        owner_signers: vec![pda],
        interface_transfer_accounts: Vec::new(),
        data: transact.clone(),
    }
    .instruction();
    let owner_meta = instruction
        .accounts
        .iter_mut()
        .find(|meta| meta.pubkey == pda)
        .ok_or_else(|| anyhow!("SPP instruction omitted the PDA owner"))?;
    owner_meta.is_signer = false;
    instruction.program_id = compression_example_program::ID;
    wrapper_data.extend_from_slice(&transact.serialize()?);
    instruction.data = wrapper_data;
    Ok(instruction)
}

fn build_create(
    env: &Environment,
    pda: Address,
    value: u64,
    output_seed: [u8; 32],
) -> Result<BuiltTransaction> {
    let (address_utxo, address_hash, address_nullifier) = address_input(&pda)?;
    let non_inclusion = wait_for_non_inclusion_proof(&env.indexer, env.tree, address_nullifier);
    let (utxo_root_index, utxo_root) = tree_root(&env.rpc, env.tree)?;
    let zero = [0u8; 32];
    let owner_pk_hash = hash_bytes(pda.as_array())?;
    let input = TransferInput {
        utxo: address_utxo,
        is_dummy: BigUint::ZERO,
        state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
        state_path_index: BigUint::ZERO,
        nullifier_low_value: be(&non_inclusion.low_element),
        nullifier_next_value: be(&non_inclusion.high_element),
        nullifier_low_path_elements: non_inclusion.path.iter().map(be).collect(),
        nullifier_low_path_index: BigUint::from(non_inclusion.low_element_index),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&non_inclusion.root),
        nullifier: be(&address_nullifier),
        owner_pk_hash: be(&owner_pk_hash),
        nullifier_secret: BigUint::ZERO,
    };

    let (output, output_utxo, payload, _) = output_for(
        &pda,
        &env.authority.pubkey(),
        address_nullifier,
        value,
        output_seed,
    )?;
    let output_hash = output.hash()?;
    let proof_output = ProofInputUtxo::try_from(&output)?;
    let transfer_output = TransferOutput {
        utxo: proof_output,
        is_dummy: BigUint::ZERO,
        hash: be(&output_hash),
        owner_pk_hash: be(&owner_pk_hash),
        nullifier_pk: be(&zero_nullifier_key().pubkey()?),
    };
    let external = external_data(output_hash, &pda, payload);
    let external_hash = external.hash()?;
    let private_tx = PrivateTxHash {
        input_hashes: &[zero],
        output_hashes: &[output_hash],
        address_hashes: Some(&[address_hash]),
        external_data_hash: &external_hash,
    }
    .hash()?;
    let payer_hash = hash_bytes(env.authority.pubkey().as_array())?;
    let signer_hashes = [payer_hash, owner_pk_hash];
    let output_owner_hashes = [owner_pk_hash];
    let public_transfers = PublicTransfers::default();
    let allow_dummy_inputs = field_u64(1);
    let public_hash = PublicInputs {
        nullifiers: &[address_nullifier],
        output_hashes: &[output_hash],
        utxo_roots: &[utxo_root],
        nullifier_tree_roots: &[non_inclusion.root],
        private_tx: &private_tx,
        external_data_hash: &external_hash,
        public_transfers: &public_transfers,
        ring_program_id: &zero,
        allow_dummy_inputs: &allow_dummy_inputs,
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&output_owner_hashes),
    }
    .hash()?;
    let proof = ProverClient::local().prove_transfer(&TransferInputs {
        inputs: vec![input],
        outputs: vec![transfer_output],
        external_data_hash: be(&external_hash),
        private_tx_hash: be(&private_tx),
        public_assets: core::array::from_fn(|_| BigUint::ZERO),
        public_amounts: core::array::from_fn(|_| BigUint::ZERO),
        ring_program_id: BigUint::ZERO,
        signer_pk_hashes: signer_hashes.iter().map(be).collect(),
        allow_dummy_inputs: BigUint::from(1u8),
        published_output_owner_pk_hashes: output_owner_hashes.iter().map(be).collect(),
        public_input_hash: be(&public_hash),
    })?;
    let transact = TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: private_tx,
        circuit: CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
        inputs: vec![InputUtxo {
            nullifier_hash: address_nullifier,
            nullifier_tree_root_index: non_inclusion.root_index,
            utxo_tree_root_index: utxo_root_index,
        }],
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: external.outputs.clone(),
        messages: Vec::new(),
    };
    let mut wrapper = Vec::with_capacity(1 + 8 + 32);
    wrapper.push(CREATE);
    wrapper.extend_from_slice(&value.to_le_bytes());
    wrapper.extend_from_slice(&output_seed);
    Ok(BuiltTransaction {
        instruction: wrap_instruction(env.authority.pubkey(), pda, env.tree, transact, wrapper)?,
        output: output_utxo,
        output_hash,
        input_nullifier: address_nullifier,
    })
}

fn build_update(
    env: &Environment,
    pda: Address,
    current: &WalletUtxo,
    new_value: u64,
    output_seed: [u8; 32],
) -> Result<BuiltTransaction> {
    let current_data = current
        .utxo
        .data
        .utxo_data()
        .ok_or_else(|| anyhow!("current UTXO has no state data"))?;
    let current_state = decode_state(current_data)?;
    let (output, output_utxo, payload, _) = output_for(
        &pda,
        &env.authority.pubkey(),
        current_state.address,
        new_value,
        output_seed,
    )?;
    let output_hash = output.hash()?;
    let external = external_data(output_hash, &pda, payload);
    let input = SppProofInputUtxo::new(current.utxo.clone(), zero_nullifier_key()).with_data_hash(
        current
            .data_hash
            .ok_or_else(|| anyhow!("missing current data hash"))?,
    );
    let proof_inputs =
        SppProofInputs::new(vec![input], vec![output], external, env.authority.pubkey());
    let transact = env.indexer.prove_transact(env.tree, proof_inputs)?;
    let mut wrapper = Vec::with_capacity(1 + 8 + 32 + 8 + 32);
    wrapper.push(UPDATE);
    wrapper.extend_from_slice(&current_state.value.to_le_bytes());
    wrapper.extend_from_slice(&current.utxo.blinding);
    wrapper.extend_from_slice(&new_value.to_le_bytes());
    wrapper.extend_from_slice(&output_seed);
    Ok(BuiltTransaction {
        instruction: wrap_instruction(env.authority.pubkey(), pda, env.tree, transact, wrapper)?,
        output: output_utxo,
        output_hash,
        input_nullifier: current.nullifier,
    })
}

fn send(env: &Environment, instruction: Instruction, cu_price: Option<u64>) -> Result<Signature> {
    let mut instructions = vec![ComputeBudgetInstruction::set_compute_unit_limit(
        TRANSACT_CU_LIMIT,
    )];
    if let Some(price) = cu_price {
        instructions.push(ComputeBudgetInstruction::set_compute_unit_price(price));
    }
    instructions.push(instruction);
    Ok(env.rpc.create_and_send_transaction(
        &instructions,
        env.authority.pubkey(),
        &[&env.authority],
    )?)
}

fn decode_wallet_utxo(
    indexed: zolana_client::EncryptedUtxoMatch,
    pda: &Address,
) -> Result<WalletUtxo> {
    if indexed.tx_viewing_pk.is_some() || indexed.salt.is_some() {
        bail!("indexed output is encrypted");
    }
    let output_data = indexed
        .output_slot
        .output_data()
        .ok_or_else(|| anyhow!("invalid output-data envelope"))?;
    let OutputDataEncoding::Plaintext(blob) = output_data else {
        bail!("indexed output is not plaintext");
    };
    let (scheme, body) = blob
        .split_first()
        .ok_or_else(|| anyhow!("empty plaintext output"))?;
    if *scheme != 7 {
        bail!("unexpected plaintext scheme {scheme}");
    }
    let plaintext = PlaintextTransfer::deserialize(body)?;
    let owner = PublicKey::from_pda(pda);
    let utxo = plaintext
        .into_utxos(&AssetRegistry::default(), None)?
        .into_iter()
        .find(|utxo| utxo.owner == owner)
        .ok_or_else(|| anyhow!("plaintext output has no PDA-owned UTXO"))?;
    let state = decode_state(
        utxo.data
            .utxo_data()
            .ok_or_else(|| anyhow!("plaintext UTXO has no state data"))?,
    )?;
    let data_hash = state_data_hash(&state)?;
    let nullifier_key = zero_nullifier_key();
    let hash = utxo.hash(&nullifier_key.pubkey()?, &data_hash, &[0u8; 32])?;
    if hash != indexed.output_slot.output_context.hash {
        bail!("decoded UTXO commitment does not match indexed output");
    }
    let nullifier = nullifier_key.nullifier(&hash, &utxo.blinding)?;
    Ok(WalletUtxo {
        utxo,
        output_context: indexed.output_slot.output_context,
        nullifier,
        data_hash: Some(data_hash),
        ring_data_hash: None,
        spent: false,
    })
}

fn discover_account(env: &Environment, pda: Address) -> Result<WalletUtxo> {
    let mut cursor = None;
    let mut candidates = Vec::new();
    loop {
        let response = env.indexer.get_encrypted_utxos_by_tags(
            vec![pda.to_bytes()],
            cursor,
            Some(100),
            None,
        )?;
        for indexed in response.matches {
            let candidate = decode_wallet_utxo(indexed, &pda)?;
            let spend = env.indexer.get_shielded_transactions_by_nullifiers(
                vec![candidate.nullifier],
                None,
                Some(1),
                None,
            )?;
            if spend.transactions.is_empty() {
                candidates.push(candidate);
            }
        }
        cursor = response.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    candidates
        .into_iter()
        .max_by_key(|candidate| candidate.output_context.leaf_index)
        .ok_or_else(|| anyhow!("no unspent UTXO found for PDA {pda}"))
}

fn assert_account(
    wallet_utxo: &WalletUtxo,
    expected_output: &Utxo,
    expected_hash: [u8; 32],
    expected_authority: Address,
    expected_value: u64,
    expected_tree: Address,
) -> Result<()> {
    let state = decode_state(
        wallet_utxo
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("state data missing"))?,
    )?;
    if wallet_utxo.utxo != *expected_output
        || wallet_utxo.output_context.hash != expected_hash
        || wallet_utxo.output_context.tree != expected_tree
        || state.authority != expected_authority.to_bytes()
        || state.value != expected_value
        || state.address == [0u8; 32]
        || wallet_utxo.spent
    {
        bail!("discovered account does not match expected state");
    }
    Ok(())
}

#[test]
fn create_and_update_plaintext_compressed_account() -> Result<()> {
    let env = setup()?;
    let pda = account_pda(&env.authority.pubkey());

    let create = build_create(&env, pda, 1, [11u8; 32])?;
    let create_signature = send(&env, create.instruction.clone(), None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), create_signature);
    let current = discover_account(&env, pda)?;
    assert_account(
        &current,
        &create.output,
        create.output_hash,
        env.authority.pubkey(),
        1,
        env.tree,
    )?;
    let created_state = decode_state(
        current
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("created state data missing"))?,
    )?;
    if created_state.address != create.input_nullifier {
        bail!("compressed address is not the address-input nullifier");
    }

    if send(&env, create.instruction, Some(1)).is_ok() {
        bail!("duplicate create unexpectedly succeeded");
    }

    let update = build_update(&env, pda, &current, 2, [12u8; 32])?;
    if update.input_nullifier != current.nullifier {
        bail!("update does not spend the discovered UTXO nullifier");
    }
    let update_signature = send(&env, update.instruction.clone(), None)?;
    wait_for_indexed_utxo(&env.indexer, pda.to_bytes(), update_signature);
    let updated = discover_account(&env, pda)?;
    assert_account(
        &updated,
        &update.output,
        update.output_hash,
        env.authority.pubkey(),
        2,
        env.tree,
    )?;
    let old_state = decode_state(
        current
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("old state data missing"))?,
    )?;
    let new_state = decode_state(
        updated
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("new state data missing"))?,
    )?;
    if old_state.address != new_state.address || current.utxo.owner != updated.utxo.owner {
        bail!("update changed the compressed address or PDA owner");
    }
    if send(&env, update.instruction, Some(1)).is_ok() {
        bail!("stale update unexpectedly succeeded");
    }
    Ok(())
}
