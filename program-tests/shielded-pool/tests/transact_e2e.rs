use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use light_program_test::{PoolTestRig, RigError};
use light_prover_client::proof::{compress_proof, proof_from_json_struct, GnarkProofJson};
use light_sparse_merkle_tree::SparseMerkleTree;
use light_verifier::CompressedProof;
use serde::Deserialize;
use shielded_pool_program::instructions::create_pool_tree::init::{
    address_sub_tree_slice_mut, pool_tree_account_size, state_next_index_offset, state_root_offset,
    STATE_HEIGHT,
};
use shielded_pool_program::instructions::transact::verifying_key;
use solana_account::Account as SolanaAccount;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use spl_token::state::{Account as TokenAccount, Mint};
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateSplInterfaceData, TransactData},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPL_ASSET_REGISTRY_ACCOUNT_LEN,
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
    let (a, b, c) = proof_from_json_struct(proof);
    let (a, b, c) = compress_proof(&a, &b, &c);

    let mut out = [0u8; 192];
    out[..32].copy_from_slice(&a);
    out[32..96].copy_from_slice(&b);
    out[96..128].copy_from_slice(&c);
    out
}

fn compressed_proof_from_bytes(proof: &[u8; 192]) -> CompressedProof {
    let mut a = [0u8; 32];
    a.copy_from_slice(&proof[..32]);
    let mut b = [0u8; 64];
    b.copy_from_slice(&proof[32..96]);
    let mut c = [0u8; 32];
    c.copy_from_slice(&proof[96..128]);
    CompressedProof { a, b, c }
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
        public_spl_asset_id: fixture.public_spl_asset_id,
        encrypted_utxos: bytes_from_hex(&fixture.encrypted_utxos),
    }
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

fn setup_spl_settlement(rig: &mut PoolTestRig, asset_id: u64) -> SplSettlement {
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

    let payer = rig.payer.insecure_clone();
    let mint = Keypair::new_from_array([0x24; 32]);
    let user_token = Keypair::new_from_array([0x22; 32]);
    let vault = Keypair::new_from_array([0x23; 32]);
    let token_program = spl_token::id();
    let mint_len = Mint::LEN;
    let token_len = TokenAccount::LEN;
    let payer_pubkey = payer.pubkey();
    let shield_fixture = fixture("shield");
    assert_eq!(shield_fixture.public_spl_asset_id, asset_id);
    assert_eq!(
        shield_fixture.user_spl_token_account,
        hex::encode(user_token.pubkey().to_bytes())
    );
    assert_eq!(
        shield_fixture.spl_token_interface,
        hex::encode(vault.pubkey().to_bytes())
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
        system_instruction::create_account(
            &payer_pubkey,
            &vault.pubkey(),
            rig.svm.minimum_balance_for_rent_exemption(token_len),
            token_len as u64,
            &token_program,
        ),
        spl_token::instruction::initialize_account3(
            &token_program,
            &vault.pubkey(),
            &mint.pubkey(),
            &cpi_authority,
        )
        .expect("initialize vault token"),
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
    rig.send_instructions(&ixs, &[&payer, &mint, &user_token, &vault])
        .expect("create token settlement accounts");

    let registry = rig
        .create_program_owned_account(SPL_ASSET_REGISTRY_ACCOUNT_LEN as u64)
        .expect("create asset registry");
    let create_registry_ix = Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(payer_pubkey, true),
            AccountMeta::new(registry.pubkey(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
        ],
        data: encode_instruction(
            tag::CREATE_SPL_INTERFACE,
            &CreateSplInterfaceData { asset_id },
        ),
    };
    rig.send_instructions(&[create_registry_ix], &[&payer])
        .expect("initialize asset registry");

    SplSettlement {
        cpi_authority,
        user_token: user_token.pubkey(),
        vault: vault.pubkey(),
        registry: registry.pubkey(),
    }
}

fn token_amount(rig: &PoolTestRig, token_account: &Pubkey) -> u64 {
    let account = rig.svm.get_account(token_account).expect("token account");
    TokenAccount::unpack(&account.data)
        .expect("valid token account")
        .amount
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

fn submit_fixture(
    rig: &mut PoolTestRig,
    tree: &Keypair,
    fixture: &Fixture,
    settlement: Option<&SplSettlement>,
) -> Result<(), RigError> {
    submit_data(rig, tree, transact_data(fixture), settlement)
}

#[test]
fn fixture_proofs_verify_against_committed_verifying_key() {
    for fixture in fixtures().fixtures {
        let data = transact_data(&fixture);
        let public_input_hash = field_from_hex(&fixture.public_input_hash);
        let compressed_proof = compressed_proof_from_bytes(&data.proof);
        light_verifier::verify::<1>(
            &[public_input_hash],
            &compressed_proof,
            &verifying_key::VERIFYINGKEY,
        )
        .unwrap_or_else(|err| panic!("fixture {} proof does not verify: {err:?}", fixture.name));
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
fn transact_rejects_nonzero_proof_trailing_bytes_without_mutating() {
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
    data.proof[128] = 1;

    let err = rig
        .transact_with_extra_accounts(&tree, data, settlement.metas())
        .expect_err("non-zero proof padding must fail");
    assert_error_contains(err, "Custom(11)");
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
    data.output_utxo_hashes.push([1u8; 32]);
    data.output_utxo_hashes.push([2u8; 32]);

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
