use groth16_solana_bsb22::{decompression, groth16::Groth16Verifier};
use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use light_program_test::{PoolTestRig, RigError};
use light_prover_client::proof::{bsb22_proof_bytes_from_json_struct, GnarkProofJson};
use light_sparse_merkle_tree::SparseMerkleTree;
use serde::Deserialize;
use shielded_pool_program::instructions::create_pool_tree::init::{
    address_sub_tree_slice_mut, current_state_root_index, pool_tree_account_size,
    state_next_index_offset, state_root_by_index, state_root_offset, STATE_HEIGHT,
};
use shielded_pool_program::instructions::transact::verifying_keys;
use solana_account::Account as SolanaAccount;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use spl_token::state::{Account as TokenAccount, Mint};
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateProtocolConfigData, CreateSplInterfaceData,
        InputUtxoSignerIndex, PauseTreeData, TransactData, UpdateProtocolConfigData,
    },
    FIRST_SPL_ASSET_ID, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
    SPL_ASSET_COUNTER_PDA_SEED, SPL_ASSET_REGISTRY_ACCOUNT_LEN, SPL_ASSET_REGISTRY_PDA_SEED,
    SPL_ASSET_VAULT_PDA_SEED,
};

fn rig() -> Option<PoolTestRig> {
    let payer = fixture_payer();
    assert_eq!(
        fixtures().solana_signer_pubkey,
        hex::encode(payer.pubkey().to_bytes())
    );
    match PoolTestRig::new_with_payer(payer) {
        Ok(r) => Some(r),
        Err(RigError::MissingProgram(_)) => {
            eprintln!("skipping shielded-pool transact e2e test: shielded_pool_program.so missing");
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

fn fixture_payer() -> Keypair {
    Keypair::new_from_array([0x42; 32])
}

fn tree_account_size() -> u64 {
    pool_tree_account_size() as u64
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct FixtureSet {
    shape: serde_json::Value,
    solana_signer_pubkey: String,
    fixtures: Vec<Fixture>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct Fixture {
    name: String,
    expiry_unix_ts: u64,
    sender_view_tag: String,
    proof: serde_json::Value,
    relayer_fee: u16,
    nullifiers: Vec<String>,
    output_utxo_hashes: Vec<String>,
    utxo_tree_root_index: Vec<u16>,
    nullifier_tree_root_index: Vec<u16>,
    private_tx_hash: String,
    public_amount_mode: u8,
    public_sol_amount: Option<u64>,
    public_spl_amount: Option<u64>,
    public_spl_asset_id: u64,
    encrypted_utxos: String,
    expected_state_next_index: u64,
    expected_queue_next_index: u64,
    expected_state_root: String,
    public_input_hash: String,
    external_data_hash: String,
    user_sol_account: String,
    user_spl_token_account: String,
    spl_token_interface: String,
    #[serde(default)]
    solana_owner_input_indices: Vec<u8>,
    debug_input_utxo_hashes: Vec<String>,
    debug_output_utxo_hashes: Vec<String>,
    debug_utxo_tree_roots: Vec<String>,
    debug_nullifier_tree_roots: Vec<String>,
}

fn fixtures() -> FixtureSet {
    serde_json::from_str(include_str!("fixtures/spp_e2e.json")).expect("valid SPP fixture JSON")
}

fn fixture(name: &str) -> Fixture {
    fixtures()
        .fixtures
        .into_iter()
        .find(|fixture| fixture.name == name)
        .unwrap_or_else(|| panic!("fixture {name} not found"))
}

fn field_from_hex(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value.trim_start_matches("0x")).expect("valid field hex");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn bytes_from_hex(value: &str) -> Vec<u8> {
    hex::decode(value.trim_start_matches("0x")).expect("valid bytes hex")
}

fn proof_bytes(value: &serde_json::Value) -> [u8; 192] {
    let proof: GnarkProofJson =
        serde_json::from_value(value.clone()).expect("valid gnark proof fixture");
    bsb22_proof_bytes_from_json_struct(proof).expect("valid BSB22 proof fixture")
}

fn transact_data(fixture: &Fixture) -> TransactData {
    TransactData {
        expiry_unix_ts: fixture.expiry_unix_ts,
        sender_view_tag: field_from_hex(&fixture.sender_view_tag),
        proof: proof_bytes(&fixture.proof),
        relayer_fee: fixture.relayer_fee,
        public_amount_mode: fixture.public_amount_mode,
        nullifiers: fixture
            .nullifiers
            .iter()
            .map(|value| field_from_hex(value))
            .collect(),
        output_utxo_hashes: fixture
            .output_utxo_hashes
            .iter()
            .map(|value| field_from_hex(value))
            .collect(),
        utxo_tree_root_index: fixture.utxo_tree_root_index.clone(),
        nullifier_tree_root_index: fixture.nullifier_tree_root_index.clone(),
        private_tx_hash: field_from_hex(&fixture.private_tx_hash),
        public_sol_amount: fixture.public_sol_amount,
        public_spl_amount: fixture.public_spl_amount,
        cpi_signer: None,
        in_utxo_signer_indices: input_signer_indices(&fixture.solana_owner_input_indices),
        encrypted_utxos: bytes_from_hex(&fixture.encrypted_utxos),
    }
}

fn input_signer_indices(input_indices: &[u8]) -> Option<Vec<InputUtxoSignerIndex>> {
    if input_indices.is_empty() {
        return None;
    }
    Some(
        input_indices
            .iter()
            .map(|input_index| InputUtxoSignerIndex {
                account_index: 1,
                input_index: *input_index,
            })
            .collect(),
    )
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn read_state_root(data: &[u8]) -> [u8; 32] {
    let offset = state_root_offset();
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[offset..offset + 32]);
    root
}

fn address_queue_next_index(mut data: Vec<u8>, tree_pubkey: Pubkey) -> u64 {
    let tree_address = pinocchio::Address::new_from_array(tree_pubkey.to_bytes());
    let address_slice = address_sub_tree_slice_mut(&mut data).expect("address sub-tree slice");
    let tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_address).unwrap();
    tree.get_metadata().queue_batches.next_index
}

fn assert_pool_state(
    rig: &PoolTestRig,
    tree_pubkey: Pubkey,
    reference: &SparseMerkleTree<light_hasher::Poseidon, STATE_HEIGHT>,
    fixture: &Fixture,
) {
    let data = rig.account_data(&tree_pubkey).expect("account data");
    assert_eq!(
        read_u64(&data, state_next_index_offset()),
        fixture.expected_state_next_index
    );
    assert_eq!(read_state_root(&data), reference.root());
    assert_eq!(
        reference.root(),
        field_from_hex(&fixture.expected_state_root)
    );
    let current_index = current_state_root_index(&data).expect("state root history index");
    assert_eq!(
        state_root_by_index(&data, current_index).expect("state root by index"),
        reference.root()
    );
    assert_eq!(
        address_queue_next_index(data, tree_pubkey),
        fixture.expected_queue_next_index
    );
}

fn append_reference(
    reference: &mut SparseMerkleTree<light_hasher::Poseidon, STATE_HEIGHT>,
    leaves: &[[u8; 32]],
) {
    for leaf in leaves {
        reference.append(*leaf);
    }
}

fn fixture_output_hashes(fixture: &Fixture) -> Vec<[u8; 32]> {
    fixture
        .output_utxo_hashes
        .iter()
        .map(|value| field_from_hex(value))
        .collect()
}

fn assert_error_contains(err: RigError, expected: &str) {
    let msg = format!("{err}");
    assert!(
        msg.contains(expected),
        "expected error containing {expected}, got: {msg}"
    );
}

#[derive(Clone, Copy)]
struct SplSettlement {
    cpi_authority: Pubkey,
    protocol_config: Pubkey,
    asset_counter: Pubkey,
    mint: Pubkey,
    user_token: Pubkey,
    vault: Pubkey,
    registry: Pubkey,
}

impl SplSettlement {
    fn metas(&self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(self.cpi_authority, false),
            AccountMeta::new(self.user_token, false),
            AccountMeta::new(self.vault, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ]
    }
}

#[derive(Clone, Copy)]
struct SolSettlement {
    cpi_authority: Pubkey,
    user_sol: Pubkey,
}

impl SolSettlement {
    fn metas(&self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(self.cpi_authority, false),
            AccountMeta::new(self.user_sol, false),
        ]
    }
}

fn set_cpi_authority_account(rig: &mut PoolTestRig) -> Pubkey {
    let cpi_authority = Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
    rig.svm
        .set_account(
            cpi_authority,
            SolanaAccount {
                lamports: 1_000_000,
                data: Vec::new(),
                owner: Pubkey::default(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("set cpi authority account");
    cpi_authority
}

fn setup_sol_settlement(rig: &mut PoolTestRig, user_sol: Pubkey) -> SolSettlement {
    let cpi_authority = set_cpi_authority_account(rig);
    if rig.svm.get_account(&user_sol).is_none() {
        rig.airdrop(&user_sol, 1_000_000)
            .expect("fund SOL recipient account");
    }
    SolSettlement {
        cpi_authority,
        user_sol,
    }
}

fn setup_spl_settlement(rig: &mut PoolTestRig, asset_id: u64) -> SplSettlement {
    let cpi_authority = set_cpi_authority_account(rig);

    let payer = rig.payer.insecure_clone();
    let mint = Keypair::new_from_array([0x24; 32]);
    let user_token = Keypair::new_from_array([0x22; 32]);
    let token_program = spl_token::id();
    let mint_len = Mint::LEN;
    let token_len = TokenAccount::LEN;
    let payer_pubkey = payer.pubkey();
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let (asset_counter, _) =
        Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &program_id);
    let (registry, _) = Pubkey::find_program_address(
        &[SPL_ASSET_REGISTRY_PDA_SEED, mint.pubkey().as_ref()],
        &program_id,
    );
    let (vault, _) = Pubkey::find_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.pubkey().as_ref()],
        &program_id,
    );
    let shield_fixture = fixture("shield");
    assert_eq!(shield_fixture.public_spl_asset_id, asset_id);
    assert_eq!(asset_id, FIRST_SPL_ASSET_ID);
    assert_eq!(
        shield_fixture.user_spl_token_account,
        hex::encode(user_token.pubkey().to_bytes())
    );
    assert_eq!(
        shield_fixture.spl_token_interface,
        hex::encode(vault.to_bytes())
    );

    let ixs: Vec<Instruction> = vec![
        system_instruction::create_account(
            &payer_pubkey,
            &mint.pubkey(),
            rig.svm.minimum_balance_for_rent_exemption(mint_len),
            mint_len as u64,
            &token_program,
        ),
        spl_token::instruction::initialize_mint2(
            &token_program,
            &mint.pubkey(),
            &payer_pubkey,
            None,
            0,
        )
        .expect("initialize mint"),
        system_instruction::create_account(
            &payer_pubkey,
            &user_token.pubkey(),
            rig.svm.minimum_balance_for_rent_exemption(token_len),
            token_len as u64,
            &token_program,
        ),
        spl_token::instruction::initialize_account3(
            &token_program,
            &user_token.pubkey(),
            &mint.pubkey(),
            &payer_pubkey,
        )
        .expect("initialize user token"),
        spl_token::instruction::mint_to(
            &token_program,
            &mint.pubkey(),
            &user_token.pubkey(),
            &payer_pubkey,
            &[],
            1_000_000,
        )
        .expect("mint user tokens"),
    ];
    rig.send_instructions(&ixs, &[&payer, &mint, &user_token])
        .expect("create token settlement accounts");

    let protocol_config = rig
        .create_protocol_config_account()
        .expect("create protocol config account");
    rig.create_shielded_pool_protocol_config(
        &protocol_config,
        &payer,
        CreateProtocolConfigData {
            authority: payer_pubkey.to_bytes(),
        },
    )
    .expect("create protocol config");
    let create_registry_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer_pubkey, true),
            AccountMeta::new_readonly(protocol_config.pubkey(), false),
            AccountMeta::new(asset_counter, false),
            AccountMeta::new(registry, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(cpi_authority, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: encode_instruction(tag::CREATE_SPL_INTERFACE, &CreateSplInterfaceData),
    };
    rig.send_instructions(&[create_registry_ix], &[&payer])
        .expect("initialize asset registry");

    SplSettlement {
        cpi_authority,
        protocol_config: protocol_config.pubkey(),
        asset_counter,
        mint: mint.pubkey(),
        user_token: user_token.pubkey(),
        vault,
        registry,
    }
}

fn token_amount(rig: &PoolTestRig, token_account: &Pubkey) -> u64 {
    let account = rig.svm.get_account(token_account).expect("token account");
    TokenAccount::unpack(&account.data)
        .expect("valid token account")
        .amount
}

fn lamports(rig: &PoolTestRig, account: &Pubkey) -> u64 {
    rig.svm
        .get_account(account)
        .map(|account| account.lamports)
        .unwrap_or(0)
}

fn submit_data(
    rig: &mut PoolTestRig,
    tree: &Keypair,
    data: TransactData,
    settlement: Option<&SplSettlement>,
) -> Result<(), RigError> {
    if data.public_spl_amount.unwrap_or(0) != 0 {
        rig.transact_with_extra_accounts(tree, data, settlement.expect("SPL settlement").metas())
    } else {
        rig.transact(tree, data)
    }
}

fn submit_sol_fixture(
    rig: &mut PoolTestRig,
    tree: &Keypair,
    fixture: &Fixture,
    settlement: &SolSettlement,
) -> Result<(), RigError> {
    rig.transact_with_extra_accounts(tree, transact_data(fixture), settlement.metas())
}

fn submit_fixture(
    rig: &mut PoolTestRig,
    tree: &Keypair,
    fixture: &Fixture,
    settlement: Option<&SplSettlement>,
) -> Result<(), RigError> {
    submit_data(rig, tree, transact_data(fixture), settlement)
}

fn compact_u16_len(value: usize) -> usize {
    match value {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        _ => 3,
    }
}

fn legacy_tx_size(
    instruction_data_len: usize,
    account_count: usize,
    ix_account_count: usize,
) -> usize {
    let signature_count = 1usize;
    let signatures = compact_u16_len(signature_count) + signature_count * 64;
    let account_keys = compact_u16_len(account_count) + account_count * 32;
    let instruction = 1
        + compact_u16_len(ix_account_count)
        + ix_account_count
        + compact_u16_len(instruction_data_len)
        + instruction_data_len;
    signatures + 3 + account_keys + 32 + compact_u16_len(1) + instruction
}

fn transact_wire_size(data: &TransactData, account_count: usize, ix_account_count: usize) -> usize {
    let instruction_data = encode_instruction(tag::TRANSACT, data);
    legacy_tx_size(instruction_data.len(), account_count, ix_account_count)
}

#[test]
fn transact_fixture_wire_sizes_are_golden() {
    let transfer_accounts = 3; // tree, payer, program id
    let transfer_ix_accounts = 2; // tree, payer
    let spl_accounts = 8; // tree, payer, cpi authority, token accounts, registry, token program, program id
    let spl_ix_accounts = 7;
    let sol_accounts = 6; // tree, payer, system program, cpi authority, user SOL, program id
    let sol_ix_accounts = 5;

    let cases = [
        (
            "spl_shield",
            transact_wire_size(
                &transact_data(&fixture("shield")),
                spl_accounts,
                spl_ix_accounts,
            ),
            705,
        ),
        (
            "transfer",
            transact_wire_size(
                &transact_data(&fixture("transfer")),
                transfer_accounts,
                transfer_ix_accounts,
            ),
            607,
        ),
        (
            "spl_unshield",
            transact_wire_size(
                &transact_data(&fixture("unshield")),
                spl_accounts,
                spl_ix_accounts,
            ),
            714,
        ),
        (
            "sol_shield",
            transact_wire_size(
                &transact_data(&fixture("sol_shield")),
                sol_accounts,
                sol_ix_accounts,
            ),
            639,
        ),
        (
            "sol_unshield",
            transact_wire_size(
                &transact_data(&fixture("sol_unshield")),
                sol_accounts,
                sol_ix_accounts,
            ),
            648,
        ),
    ];

    for (name, size, expected) in cases {
        assert_eq!(size, expected, "{name} canonical wire size changed");
        assert!(size <= 1232, "{name} wire size {size} exceeds packet limit");
    }
}

#[test]
fn create_spl_interface_rejects_initialized_registry() {
    let Some(mut rig) = rig() else {
        return;
    };
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);
    let payer = rig.payer.insecure_clone();
    let create_registry_ix = Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(settlement.protocol_config, false),
            AccountMeta::new(settlement.asset_counter, false),
            AccountMeta::new(settlement.registry, false),
            AccountMeta::new_readonly(settlement.mint, false),
            AccountMeta::new(settlement.vault, false),
            AccountMeta::new_readonly(settlement.cpi_authority, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: encode_instruction(tag::CREATE_SPL_INTERFACE, &CreateSplInterfaceData),
    };

    rig.svm.expire_blockhash();
    let err = rig
        .send_instructions(&[create_registry_ix], &[&payer])
        .expect_err("initialized SPL registry must reject reinitialization");
    assert_error_contains(err, "Custom(15)");
}

#[test]
fn protocol_config_can_pause_and_unpause_tree() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let config = rig
        .create_protocol_config_account()
        .expect("create protocol config account");
    let authority = Keypair::new_from_array([0x31; 32]);
    rig.create_shielded_pool_protocol_config(
        &config,
        &authority,
        CreateProtocolConfigData {
            authority: authority.pubkey().to_bytes(),
        },
    )
    .expect("create protocol config");

    rig.pause_tree(&config, &tree, &authority, PauseTreeData { paused: true })
        .expect("pause tree");
    let before = rig.account_data(&tree.pubkey()).expect("tree account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);
    let err = submit_fixture(&mut rig, &tree, &fixture("shield"), Some(&settlement))
        .expect_err("paused tree must reject transact");
    assert_error_contains(err, "Custom(17)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("tree account data"),
        before
    );
    assert_eq!(token_amount(&rig, &settlement.user_token), 1_000_000);
    assert_eq!(token_amount(&rig, &settlement.vault), 0);

    rig.svm.expire_blockhash();
    rig.pause_tree(&config, &tree, &authority, PauseTreeData { paused: false })
        .expect("unpause tree");
    submit_fixture(&mut rig, &tree, &fixture("shield"), Some(&settlement))
        .expect("unpaused tree accepts transact");
}

#[test]
fn protocol_config_authority_can_rotate() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let config = rig
        .create_protocol_config_account()
        .expect("create protocol config account");
    let old_authority = Keypair::new_from_array([0x32; 32]);
    let new_authority = Keypair::new_from_array([0x33; 32]);

    rig.create_shielded_pool_protocol_config(
        &config,
        &old_authority,
        CreateProtocolConfigData {
            authority: old_authority.pubkey().to_bytes(),
        },
    )
    .expect("create protocol config");
    rig.update_shielded_pool_protocol_config(
        &config,
        &old_authority,
        UpdateProtocolConfigData {
            new_authority: new_authority.pubkey().to_bytes(),
        },
    )
    .expect("rotate protocol config authority");

    let err = rig
        .pause_tree(
            &config,
            &tree,
            &old_authority,
            PauseTreeData { paused: true },
        )
        .expect_err("old authority must not pause after rotation");
    assert_error_contains(err, "Custom(5)");
    rig.pause_tree(
        &config,
        &tree,
        &new_authority,
        PauseTreeData { paused: true },
    )
    .expect("new authority pauses");
}

#[test]
fn fixture_proofs_verify_against_committed_verifying_key() {
    for fixture in fixtures().fixtures {
        let data = transact_data(&fixture);
        let public_input_hash = field_from_hex(&fixture.public_input_hash);
        let proof_a: [u8; 32] = data.proof[..32].try_into().unwrap();
        let proof_b: [u8; 64] = data.proof[32..96].try_into().unwrap();
        let proof_c: [u8; 32] = data.proof[96..128].try_into().unwrap();
        let commitment: [u8; 32] = data.proof[128..160].try_into().unwrap();
        let commitment_pok: [u8; 32] = data.proof[160..192].try_into().unwrap();
        let proof_a = decompression::decompress_g1(&proof_a).unwrap();
        let proof_b = decompression::decompress_g2(&proof_b).unwrap();
        let proof_c = decompression::decompress_g1(&proof_c).unwrap();
        let commitment = decompression::decompress_g1(&commitment).unwrap();
        let commitment_pok = decompression::decompress_g1(&commitment_pok).unwrap();
        let public_inputs = [public_input_hash];
        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a,
            &proof_b,
            &proof_c,
            &commitment,
            &commitment_pok,
            &public_inputs,
            &verifying_keys::spp_1_2::VERIFYINGKEY,
        )
        .unwrap_or_else(|err| {
            panic!(
                "fixture {} BSB22 verifier init failed: {err:?}",
                fixture.name
            )
        });
        verifier.verify().unwrap_or_else(|err| {
            panic!("fixture {} proof does not verify: {err:?}", fixture.name)
        });
    }
}

#[test]
fn transact_shield_transfer_unshield_updates_state_and_nullifier_queue() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let mut reference = SparseMerkleTree::<light_hasher::Poseidon, STATE_HEIGHT>::new_empty();
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    for name in ["shield", "transfer", "unshield"] {
        let fixture = fixture(name);
        submit_fixture(&mut rig, &tree, &fixture, Some(&settlement))
            .unwrap_or_else(|err| panic!("{name} transact failed: {err}"));
        append_reference(&mut reference, &fixture_output_hashes(&fixture));
        assert_pool_state(&rig, tree.pubkey(), &reference, &fixture);
    }
    assert_eq!(token_amount(&rig, &settlement.user_token), 999_940);
    assert_eq!(token_amount(&rig, &settlement.vault), 60);
}

#[test]
fn transact_supports_two_output_transfer() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let mut reference = SparseMerkleTree::<light_hasher::Poseidon, STATE_HEIGHT>::new_empty();
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("shield transact");
    append_reference(&mut reference, &fixture_output_hashes(&shield));

    let transfer = fixture("transfer");
    assert_eq!(transfer.output_utxo_hashes.len(), 2);
    submit_fixture(&mut rig, &tree, &transfer, Some(&settlement)).expect("two-output transfer");
    append_reference(&mut reference, &fixture_output_hashes(&transfer));
    assert_pool_state(&rig, tree.pubkey(), &reference, &transfer);
}

#[test]
fn transact_accepts_p256_owned_input_without_solana_owner_signer() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let mut reference = SparseMerkleTree::<light_hasher::Poseidon, STATE_HEIGHT>::new_empty();
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("p256_shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("P256 shield transact");
    append_reference(&mut reference, &fixture_output_hashes(&shield));

    let transfer = fixture("p256_transfer");
    assert!(transact_data(&transfer).in_utxo_signer_indices.is_none());
    submit_fixture(&mut rig, &tree, &transfer, Some(&settlement)).expect("P256 transfer transact");
    append_reference(&mut reference, &fixture_output_hashes(&transfer));
    assert_pool_state(&rig, tree.pubkey(), &reference, &transfer);
}

#[test]
fn transact_supports_full_unshield_without_change_output() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let mut reference = SparseMerkleTree::<light_hasher::Poseidon, STATE_HEIGHT>::new_empty();
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    for name in ["shield", "transfer"] {
        let fixture = fixture(name);
        submit_fixture(&mut rig, &tree, &fixture, Some(&settlement))
            .unwrap_or_else(|err| panic!("{name} transact failed: {err}"));
        append_reference(&mut reference, &fixture_output_hashes(&fixture));
    }
    let before_unshield_root = reference.root();

    let unshield = fixture("unshield");
    assert!(unshield.output_utxo_hashes.is_empty());
    submit_fixture(&mut rig, &tree, &unshield, Some(&settlement)).expect("full unshield transact");
    assert_eq!(reference.root(), before_unshield_root);
    assert_pool_state(&rig, tree.pubkey(), &reference, &unshield);
}

#[test]
fn transact_rejects_tampered_output_hash_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    let mut data = transact_data(&shield);
    data.output_utxo_hashes[0][31] ^= 1;

    let err = rig
        .transact_with_extra_accounts(&tree, data, settlement.metas())
        .expect_err("tampered output hash must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_tampered_encrypted_utxos_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    let mut data = transact_data(&shield);
    data.encrypted_utxos[0] ^= 1;

    let err = rig
        .transact_with_extra_accounts(&tree, data, settlement.metas())
        .expect_err("tampered encrypted UTXO blob must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_tampered_proof_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    let mut data = transact_data(&shield);
    data.proof[0] ^= 1;

    let err = rig
        .transact_with_extra_accounts(&tree, data, settlement.metas())
        .expect_err("tampered proof must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_missing_bsb22_commitment_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    let mut data = transact_data(&shield);
    data.proof[128..160].fill(0);

    let err = rig
        .transact_with_extra_accounts(&tree, data, settlement.metas())
        .expect_err("missing BSB22 commitment must fail");
    assert_error_contains(err, "Custom(11)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_tampered_bsb22_commitment_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    let mut data = transact_data(&shield);
    data.proof[128] ^= 1;

    let err = rig
        .transact_with_extra_accounts(&tree, data, settlement.metas())
        .expect_err("tampered BSB22 commitment must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_duplicate_sender_view_tag_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("initial shield");
    let after_initial = rig.account_data(&tree.pubkey()).expect("account data");
    let user_after_initial = token_amount(&rig, &settlement.user_token);
    let vault_after_initial = token_amount(&rig, &settlement.vault);
    rig.svm.expire_blockhash();

    let err = rig
        .transact_with_extra_accounts(&tree, transact_data(&shield), settlement.metas())
        .expect_err("duplicate sender view tag must fail");
    assert_error_contains(err, "Custom(7)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        after_initial
    );
    assert_eq!(
        token_amount(&rig, &settlement.user_token),
        user_after_initial
    );
    assert_eq!(token_amount(&rig, &settlement.vault), vault_after_initial);
}

#[test]
fn transact_rejects_mismatched_root_indices_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("shield transact");
    let before = rig.account_data(&tree.pubkey()).expect("account data");

    let transfer = fixture("transfer");
    let mut data = transact_data(&transfer);
    data.utxo_tree_root_index.clear();

    let err = rig.transact(&tree, data).expect_err("shape must fail");
    assert_error_contains(err, "Custom(10)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_stale_root_index_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("shield transact");
    let before = rig.account_data(&tree.pubkey()).expect("account data");

    let transfer = fixture("transfer");
    let mut data = transact_data(&transfer);
    data.utxo_tree_root_index[0] = 199;

    let err = submit_data(&mut rig, &tree, data, None)
        .expect_err("unknown root index must fail before proof/state mutation");
    assert_error_contains(err, "Custom(10)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_stale_nullifier_root_index_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("shield transact");
    let before = rig.account_data(&tree.pubkey()).expect("account data");

    let transfer = fixture("transfer");
    let mut data = transact_data(&transfer);
    data.nullifier_tree_root_index[0] = 199;

    let err = submit_data(&mut rig, &tree, data, None)
        .expect_err("unknown nullifier root index must fail before proof/state mutation");
    assert_error_contains(err, "Custom(10)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_invalid_input_signer_indices_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("shield transact");
    let before = rig.account_data(&tree.pubkey()).expect("account data");

    let transfer = fixture("transfer");
    let mut data = transact_data(&transfer);
    data.in_utxo_signer_indices = Some(vec![InputUtxoSignerIndex {
        account_index: 250,
        input_index: 0,
    }]);

    let err = submit_data(&mut rig, &tree, data, None).expect_err("bad signer index must fail");
    assert_error_contains(err, "Custom(10)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_sol_withdraw_recipient_substitution_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let payer = rig.payer.pubkey();
    let settlement = setup_sol_settlement(&mut rig, payer);

    let sol_shield = fixture("sol_shield");
    assert_eq!(sol_shield.public_sol_amount, Some(80));
    assert_eq!(sol_shield.user_sol_account, hex::encode(payer.to_bytes()));
    submit_sol_fixture(&mut rig, &tree, &sol_shield, &settlement).expect("SOL shield transact");

    let substitute = Keypair::new();
    rig.airdrop(&substitute.pubkey(), 1_000_000)
        .expect("fund substituted recipient");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let cpi_before = lamports(&rig, &settlement.cpi_authority);
    let substitute_before = lamports(&rig, &substitute.pubkey());
    let substituted = SolSettlement {
        user_sol: substitute.pubkey(),
        ..settlement
    };

    let err = submit_sol_fixture(&mut rig, &tree, &fixture("sol_unshield"), &substituted)
        .expect_err("substituted SOL withdrawal recipient must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
    assert_eq!(lamports(&rig, &settlement.cpi_authority), cpi_before);
    assert_eq!(lamports(&rig, &substitute.pubkey()), substitute_before);
}

#[test]
fn transact_rejects_public_spl_mint_substitution_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let asset_id = fixture("shield").public_spl_asset_id;
    let settlement = setup_spl_settlement(&mut rig, asset_id);
    let before = rig.account_data(&tree.pubkey()).expect("account data");

    let fake_registry = Pubkey::new_unique();
    let fake_mint = Pubkey::new_unique();
    let mut registry_data = vec![0u8; SPL_ASSET_REGISTRY_ACCOUNT_LEN];
    registry_data[0..8].copy_from_slice(&zolana_interface::SPL_ASSET_REGISTRY_MAGIC);
    registry_data[8..40].copy_from_slice(fake_mint.as_ref());
    registry_data[40..48].copy_from_slice(&asset_id.to_le_bytes());
    rig.svm
        .set_account(
            fake_registry,
            SolanaAccount {
                lamports: 1_000_000,
                data: registry_data,
                owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("set fake asset registry");

    let substituted = SplSettlement {
        registry: fake_registry,
        ..settlement
    };
    let err = submit_fixture(&mut rig, &tree, &fixture("shield"), Some(&substituted))
        .expect_err("SPL mint substitution must fail");
    assert_error_contains(err, "Custom(13)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
    assert_eq!(token_amount(&rig, &settlement.user_token), 1_000_000);
    assert_eq!(token_amount(&rig, &settlement.vault), 0);
}

#[test]
fn transact_rejects_instruction_discriminator_mismatch_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    let shield = fixture("shield");
    submit_fixture(&mut rig, &tree, &shield, Some(&settlement)).expect("shield transact");
    let before = rig.account_data(&tree.pubkey()).expect("account data");

    let wrong = fixture("wrong_discriminator");
    let err = submit_fixture(&mut rig, &tree, &wrong, None)
        .expect_err("proof for another discriminator must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_spl_withdraw_recipient_substitution_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    for name in ["shield", "transfer"] {
        let fixture = fixture(name);
        submit_fixture(&mut rig, &tree, &fixture, Some(&settlement))
            .unwrap_or_else(|err| panic!("{name} transact failed: {err}"));
    }

    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let user_before = token_amount(&rig, &settlement.user_token);
    let vault_before = token_amount(&rig, &settlement.vault);
    let mut substituted = settlement;
    substituted.user_token = settlement.vault;

    let err = submit_fixture(&mut rig, &tree, &fixture("unshield"), Some(&substituted))
        .expect_err("substituted SPL withdrawal recipient must fail");
    assert_error_contains(err, "Custom(12)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
    assert_eq!(token_amount(&rig, &settlement.user_token), user_before);
    assert_eq!(token_amount(&rig, &settlement.vault), vault_before);
}

#[test]
fn transact_rejects_replayed_nullifier_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);

    submit_fixture(&mut rig, &tree, &fixture("shield"), Some(&settlement))
        .expect("shield transact");
    let transfer = fixture("transfer");
    submit_fixture(&mut rig, &tree, &transfer, Some(&settlement)).expect("transfer transact");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    rig.svm.expire_blockhash();

    let err = submit_fixture(&mut rig, &tree, &fixture("double_spend"), Some(&settlement))
        .expect_err("replayed nullifier must fail");
    assert_error_contains(err, "Custom(7)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
}

#[test]
fn transact_rejects_invalid_shape_without_mutating() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    let settlement = setup_spl_settlement(&mut rig, fixture("shield").public_spl_asset_id);
    let mut data = transact_data(&fixture("shield"));
    while data.output_utxo_hashes.len() <= 8 {
        data.output_utxo_hashes
            .push([data.output_utxo_hashes.len() as u8; 32]);
    }

    let err = submit_data(&mut rig, &tree, data, Some(&settlement))
        .expect_err("oversized output shape must fail");
    assert_error_contains(err, "Custom(10)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before
    );
    assert_eq!(token_amount(&rig, &settlement.user_token), 1_000_000);
    assert_eq!(token_amount(&rig, &settlement.vault), 0);
}
