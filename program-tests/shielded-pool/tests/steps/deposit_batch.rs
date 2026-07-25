//! Batched `deposit` steps: one instruction appending several outputs, across
//! one or more assets, settling each asset with a single transfer.

use cucumber::{then, when};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::DepositWithdraw;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        tag, AssetDeposit, DepositAsset, DepositAssetKind, DepositEntry, DepositIxData,
        DepositSplAccounts,
    },
    pda,
};
use zolana_program_test::ZolanaProgramTest;

use crate::{common::assert_pool_error, ShieldedPoolWorld};

fn interface_lamports(world: &mut ShieldedPoolWorld, sol_interface: &Pubkey) -> u64 {
    world
        .rpc()
        .svm
        .get_account(sol_interface)
        .map(|account| account.lamports)
        .unwrap_or_default()
}

/// The batch append writes one root for the whole batch; the indexer replays the
/// same leaves one at a time into its reference tree. Equal roots prove the batch
/// append and the leaf-by-leaf append agree.
#[track_caller]
fn assert_batch_root_matches_reference(world: &mut ShieldedPoolWorld, tree: &Pubkey) {
    let onchain = world.rpc().state_root(tree).expect("state root");
    assert_eq!(
        world.rpc().indexer().root(),
        onchain,
        "batch append root must match the leaf-by-leaf reference tree"
    );
}

fn sol_entry(amount: u64, seed: u8) -> AssetDeposit {
    ZolanaProgramTest::sol_shield_data(amount, [seed; 32], [seed; 31])
}

fn spl_entry(world: &ShieldedPoolWorld, amount: u64, seed: u8) -> AssetDeposit {
    ZolanaProgramTest::spl_shield_data(
        amount,
        [seed; 32],
        [seed; 31],
        &world.mint(),
        &world.user_token(),
    )
}

/// Send hand-built batch instruction data against a valid account layout, so a
/// test can violate an instruction-data invariant the builder never produces.
fn send_raw_batch(
    world: &mut ShieldedPoolWorld,
    assets: Vec<DepositAssetKind>,
    deposits: Vec<DepositEntry>,
    accounts: Vec<AccountMeta>,
) {
    let depositor = world.depositor().insecure_clone();
    let program_id = world.rpc().program_id;
    let mut data = vec![tag::DEPOSIT];
    data.extend_from_slice(
        &DepositIxData { assets, deposits }
            .serialize()
            .expect("proofless ix data serialization is infallible"),
    );
    let result = world
        .rpc()
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id,
                accounts,
                data,
            }],
            &[&depositor],
        )
        .map(|_| ());
    world.last_error = result.err();
}

fn sol_group_accounts() -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(pda::sol_interface(), false),
    ]
}

fn spl_group_accounts(world: &ShieldedPoolWorld) -> Vec<AccountMeta> {
    let mint = world.mint();
    vec![
        AccountMeta::new_readonly(ZolanaProgramTest::token_program_id(), false),
        AccountMeta::new(world.user_token(), false),
        AccountMeta::new(pda::spl_asset_vault(&mint), false),
        AccountMeta::new_readonly(pda::spl_asset_registry(&mint), false),
    ]
}

fn batch_accounts(world: &ShieldedPoolWorld, groups: Vec<Vec<AccountMeta>>) -> Vec<AccountMeta> {
    let mut accounts = vec![
        AccountMeta::new(world.tree().pubkey(), false),
        AccountMeta::new(world.depositor().pubkey(), true),
    ];
    for group in groups {
        accounts.extend(group);
    }
    accounts.push(AccountMeta::new_readonly(world.rpc_ref().program_id, false));
    accounts
}

// === success ===

#[when(expr = "the depositor batch-shields {int} SOL outputs of {int} lamports")]
fn batch_shield_sol(world: &mut ShieldedPoolWorld, count: u64, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let sol_interface = pda::sol_interface();
    let interface_before = interface_lamports(world, &sol_interface);
    let deposits: Vec<AssetDeposit> = (0..count)
        .map(|index| sol_entry(amount, u8::try_from(index).expect("small batch") + 1))
        .collect();

    let batch = world
        .rpc()
        .deposit_batch(&tree, &depositor, deposits)
        .expect("batch deposit");
    let outputs = batch.outputs;

    assert_eq!(outputs.len(), usize::try_from(count).expect("small batch"));
    assert_eq!(
        batch.deposit_withdraws,
        vec![DepositWithdraw {
            is_deposit: true,
            amount: amount * count,
            asset: None,
        }],
        "one settlement record carrying the summed SOL amount"
    );
    let mut leaf_indices: Vec<u64> = outputs.iter().map(|output| output.leaf_index).collect();
    leaf_indices.dedup();
    assert_eq!(
        leaf_indices.len(),
        outputs.len(),
        "each batch entry must append its own leaf"
    );
    for output in &outputs {
        assert_eq!(output.output.amount, amount, "per-entry amount");
        assert_eq!(output.output.asset, [0u8; 32], "SOL asset");
    }

    let interface_after = interface_lamports(world, &sol_interface);
    assert_eq!(
        interface_after - interface_before,
        amount * count,
        "the batch must settle the summed amount"
    );
    assert_batch_root_matches_reference(world, &tree);
    world.batch_outputs = outputs;
}

#[when(expr = "the depositor batch-shields {int} lamports and {int} tokens together")]
fn batch_shield_multi_asset(world: &mut ShieldedPoolWorld, lamports: u64, tokens: u64) {
    let tree = world.tree().pubkey();
    let mint = world.mint();
    let depositor = world.depositor().insecure_clone();
    let vault = pda::spl_asset_vault(&mint);
    let sol_interface = pda::sol_interface();
    let interface_before = interface_lamports(world, &sol_interface);
    let vault_before = world.rpc().token_balance(&vault).expect("vault balance");

    let deposits = vec![
        sol_entry(lamports, 1),
        spl_entry(world, tokens, 2),
        sol_entry(lamports, 3),
    ];
    let batch = world
        .rpc()
        .deposit_batch(&tree, &depositor, deposits)
        .expect("batch deposit");
    let outputs = batch.outputs;

    assert_eq!(outputs.len(), 3, "three outputs across two assets");
    assert_eq!(
        batch.deposit_withdraws,
        vec![
            DepositWithdraw {
                is_deposit: true,
                amount: lamports * 2,
                asset: None,
            },
            DepositWithdraw {
                is_deposit: true,
                amount: tokens,
                asset: Some(mint.to_bytes()),
            },
        ],
        "one settlement record per asset, each carrying that asset's total"
    );
    let assets: Vec<[u8; 32]> = outputs.iter().map(|output| output.output.asset).collect();
    assert_eq!(
        assets,
        vec![[0u8; 32], mint.to_bytes(), [0u8; 32]],
        "each output records its own asset"
    );

    let interface_after = interface_lamports(world, &sol_interface);
    assert_eq!(
        interface_after - interface_before,
        lamports * 2,
        "both SOL entries settle in one transfer"
    );
    assert_eq!(
        world.rpc().token_balance(&vault).expect("vault balance") - vault_before,
        tokens,
        "the SPL entry settles into the vault"
    );
    assert_batch_root_matches_reference(world, &tree);
    world.batch_outputs = outputs;
}

#[then(expr = "the batch appends {int} distinct leaves")]
fn batch_appended(world: &mut ShieldedPoolWorld, count: usize) {
    assert_eq!(world.batch_outputs.len(), count);
    let mut hashes: Vec<[u8; 32]> = world
        .batch_outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(hashes.len(), count, "batch leaves must be distinct");
}

// === instruction-data violations ===

#[when(expr = "the depositor sends a batch with no entries")]
fn batch_empty(world: &mut ShieldedPoolWorld) {
    let accounts = batch_accounts(world, vec![sol_group_accounts()]);
    send_raw_batch(world, vec![DepositAssetKind::Sol], Vec::new(), accounts);
}

#[when(expr = "the depositor sends a batch entry naming an out-of-range asset")]
fn batch_bad_asset_index(world: &mut ShieldedPoolWorld) {
    let accounts = batch_accounts(world, vec![sol_group_accounts()]);
    let mut entry = raw_entry(1_000);
    entry.asset_index = 1;
    send_raw_batch(world, vec![DepositAssetKind::Sol], vec![entry], accounts);
}

#[when(expr = "the depositor sends a batch leaving a declared asset unfunded")]
fn batch_unreferenced_asset(world: &mut ShieldedPoolWorld) {
    let accounts = batch_accounts(world, vec![sol_group_accounts(), spl_group_accounts(world)]);
    send_raw_batch(
        world,
        vec![DepositAssetKind::Sol, DepositAssetKind::Spl],
        vec![raw_entry(1_000)],
        accounts,
    );
}

#[when(expr = "the depositor sends a batch declaring the same mint twice")]
fn batch_duplicate_asset(world: &mut ShieldedPoolWorld) {
    let accounts = batch_accounts(
        world,
        vec![spl_group_accounts(world), spl_group_accounts(world)],
    );
    let mut second = raw_entry(1_000);
    second.asset_index = 1;
    send_raw_batch(
        world,
        vec![DepositAssetKind::Spl, DepositAssetKind::Spl],
        vec![raw_entry(1_000), second],
        accounts,
    );
}

#[when(expr = "the depositor sends a batch whose amounts overflow")]
fn batch_overflow(world: &mut ShieldedPoolWorld) {
    let accounts = batch_accounts(world, vec![sol_group_accounts()]);
    send_raw_batch(
        world,
        vec![DepositAssetKind::Sol],
        vec![raw_entry(u64::MAX), raw_entry(1)],
        accounts,
    );
}

fn raw_entry(amount: u64) -> DepositEntry {
    DepositEntry {
        asset_index: 0,
        view_tag: [9u8; 32],
        owner: [9u8; 32],
        blinding: [9u8; 31],
        amount,
        utxo_data: None,
        memo: None,
    }
}

#[then(expr = "the batch is rejected as an empty deposit batch")]
fn rejected_empty(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::EmptyDepositBatch);
}

#[then(expr = "the batch is rejected as an invalid deposit asset index")]
fn rejected_bad_index(world: &mut ShieldedPoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidDepositAssetIndex,
    );
}

#[then(expr = "the batch is rejected as an unreferenced deposit asset")]
fn rejected_unreferenced(world: &mut ShieldedPoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::UnreferencedDepositAsset,
    );
}

#[then(expr = "the batch is rejected as a duplicate deposit asset")]
fn rejected_duplicate(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::DuplicateDepositAsset);
}

#[then(expr = "the batch is rejected as a deposit amount overflow")]
fn rejected_overflow(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::DepositAmountOverflow);
}

/// The builder cannot express a bad `asset_index`: it derives every index from
/// the asset each entry names.
#[then(expr = "the builder assigns each entry the index of its own asset")]
fn builder_assigns_indices(world: &mut ShieldedPoolWorld) {
    let mint = world.mint();
    let user_token = world.user_token();
    let ix = zolana_interface::instruction::Deposit {
        tree: world.tree().pubkey(),
        depositor: world.depositor().pubkey(),
        deposits: vec![
            spl_entry(world, 10, 1),
            sol_entry(20, 2),
            AssetDeposit {
                asset: DepositAsset::Spl(DepositSplAccounts { mint, user_token }),
                ..spl_entry(world, 30, 3)
            },
        ],
    }
    .instruction();
    let parsed = DepositIxData::deserialize(
        ix.data
            .get(1..)
            .expect("instruction data carries a tag and body"),
    )
    .expect("builder emits parseable instruction data");

    // SOL is declared first, so the two same-mint SPL entries share index 1.
    assert_eq!(
        parsed.assets,
        vec![DepositAssetKind::Sol, DepositAssetKind::Spl]
    );
    let indices: Vec<u8> = parsed
        .deposits
        .iter()
        .map(|deposit| deposit.asset_index)
        .collect();
    assert_eq!(indices, vec![1, 0, 1]);
}
