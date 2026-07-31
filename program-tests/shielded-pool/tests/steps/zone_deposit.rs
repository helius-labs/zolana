//! Policy-zone proofless deposit steps.

use cucumber::{then, when};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::SplTransfer;
use zolana_interface::{
    instruction::{DepositAsset, DepositSplAccounts, UtxoData, ZoneAssetDeposit, ZoneDeposit},
    pda,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{test_blinding, ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::litesvm_asserts::litesvm_assert_zone_deposit;
use zolana_transaction::{
    owner_utxo_hash, Address, AssetRegistry, LocalWalletAuthority, Wallet, ZoneDepositPlaintext,
};

use crate::ShieldedPoolWorld;

fn prepare_zone(world: &mut ShieldedPoolWorld) {
    world
        .rpc()
        .load_zone_test_program()
        .expect("zone_test_program.so must be built");
    let zone_authority = world.authority().insecure_clone();
    world
        .rpc()
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");
}

fn interface_lamports(world: &mut ShieldedPoolWorld) -> u64 {
    world
        .rpc()
        .svm
        .get_account(&pda::sol_interface())
        .map(|account| account.lamports)
        .unwrap_or_default()
}

fn zone_entry(
    asset: DepositAsset,
    amount: u64,
    seed: u8,
    utxo_data: Option<UtxoData>,
    memo: Option<Vec<u8>>,
) -> ZoneAssetDeposit {
    let recipient = ShieldedKeypair::new().expect("zone recipient keypair");
    let owner = recipient.owner_hash().expect("zone recipient owner hash");
    let blinding = test_blinding(seed);
    let data_hash = utxo_data.as_ref().map(|data| data.data_hash);
    let zone_data = vec![seed, seed.wrapping_add(1)];
    let encrypted = ZoneDepositPlaintext {
        blinding,
        utxo_data: utxo_data.map(|data| data.data),
        memo,
        zone_data,
    }
    .encrypt(&recipient.viewing_pubkey())
    .expect("encrypt zone deposit");

    ZoneAssetDeposit {
        asset,
        view_tag: [seed; 32],
        owner_utxo_hash: owner_utxo_hash(&owner, &blinding).expect("owner UTXO hash"),
        amount,
        data_hash,
        zone_data_hash: [seed; 32],
        encrypted,
    }
}

#[when(expr = "the depositor zone-shields {int} lamports to a fresh recipient")]
fn zone_shield(world: &mut ShieldedPoolWorld, amount: u64) {
    prepare_zone(world);

    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let keypair = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");

    let seed = test_blinding(5);
    let mut data =
        ZolanaProgramTest::wallet_zone_sol_shield_data(amount, &recipient.identity, &seed, 0)
            .expect("wallet zone deposit data");
    data.zone_data_hash = [5u8; 32];

    let root_before = world.rpc().state_root(&tree).expect("root");
    let event = world
        .rpc()
        .zone_deposit(&tree, &depositor, &data)
        .expect("zone deposit");

    litesvm_assert_zone_deposit(
        world.rpc(),
        &tree,
        &event,
        &data,
        amount,
        [0u8; 32],
        ZONE_TEST_PROGRAM_ID,
        root_before,
        &LocalWalletAuthority::new(Address::default(), &keypair),
        &mut recipient,
    );
    world.depositor = Some(depositor);
    world.last_zone_deposit_view = Some(event);
    world.recipient = Some(recipient);
}

#[when(expr = "the SPL depositor zone-shields {int} tokens to a fresh recipient")]
fn zone_spl_shield(world: &mut ShieldedPoolWorld, amount: u64) {
    prepare_zone(world);

    let tree = world.tree().pubkey();
    let mint = world.mint();
    let user_token = world.user_token();
    let vault = pda::spl_interface(&mint);
    let depositor = world.depositor().insecure_clone();
    let keypair = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        keypair.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");

    let seed = test_blinding(9);
    let mut data = ZolanaProgramTest::wallet_zone_spl_shield_data(
        amount,
        mint,
        user_token,
        &recipient.identity,
        &seed,
        0,
    )
    .expect("wallet zone SPL deposit data");
    data.zone_data_hash = [9u8; 32];

    let vault_before = world.rpc().token_balance(&vault).expect("vault balance");
    let user_token_before = world
        .rpc()
        .token_balance(&user_token)
        .expect("user token balance");
    let root_before = world.rpc().state_root(&tree).expect("root");
    let event = world
        .rpc()
        .zone_deposit(&tree, &depositor, &data)
        .expect("zone SPL deposit");

    assert_eq!(
        world.rpc().token_balance(&vault),
        Some(vault_before + amount),
        "vault grows by the deposit"
    );
    assert_eq!(
        world.rpc().token_balance(&user_token),
        Some(user_token_before - amount),
        "user token account shrinks by the deposit"
    );
    litesvm_assert_zone_deposit(
        world.rpc(),
        &tree,
        &event,
        &data,
        amount,
        mint.to_bytes(),
        ZONE_TEST_PROGRAM_ID,
        root_before,
        &LocalWalletAuthority::new(Address::default(), &keypair),
        &mut recipient,
    );
    world.depositor = Some(depositor);
    world.last_zone_deposit_view = Some(event);
    world.recipient = Some(recipient);
}

#[then(expr = "an encrypted zone deposit event is emitted")]
fn encrypted_zone_event_emitted(world: &mut ShieldedPoolWorld) {
    assert!(world.last_zone_deposit_view.is_some());
}

#[when(expr = "the depositor zone-batch-shields {int} SOL outputs of {int} lamports")]
fn zone_batch_shield_sol(world: &mut ShieldedPoolWorld, count: u64, amount: u64) {
    prepare_zone(world);
    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let interface_before = interface_lamports(world);

    let deposits = (0..count)
        .map(|index| {
            let seed = u8::try_from(index + 1).expect("small batch");
            zone_entry(
                DepositAsset::Sol,
                amount,
                seed.wrapping_add(10),
                Some(UtxoData {
                    data_hash: [seed.wrapping_add(20); 32],
                    data: vec![seed; 2],
                }),
                Some(vec![seed.wrapping_add(30)]),
            )
        })
        .collect::<Vec<_>>();
    let expected = deposits.clone();

    let batch = world
        .rpc()
        .zone_deposit_batch(&tree, &depositor, deposits)
        .expect("zone batch deposit");
    assert_eq!(
        batch.spl_transfers,
        vec![SplTransfer {
            is_deposit: true,
            amount: amount * count,
            asset: None,
        }]
    );
    assert_eq!(
        interface_lamports(world) - interface_before,
        amount * count,
        "SOL settles once for the summed amount"
    );
    assert_eq!(batch.outputs.len(), expected.len());
    for (output, entry) in batch.outputs.iter().zip(&expected) {
        assert_eq!(output.view_tag, entry.view_tag);
        assert_eq!(output.output.owner_utxo_hash, entry.owner_utxo_hash);
        assert_eq!(output.output.zone_data_hash, entry.zone_data_hash);
        assert_eq!(output.output.data_hash, entry.data_hash);
        assert_eq!(output.output.zone_program_id, ZONE_TEST_PROGRAM_ID);
        assert_eq!(
            output.output.encrypted.tx_viewing_pk,
            entry.encrypted.tx_viewing_pk
        );
        assert_eq!(output.output.encrypted.salt, entry.encrypted.salt);
        assert_eq!(
            output.output.encrypted.ciphertext,
            entry.encrypted.ciphertext
        );
    }
    world.zone_batch_outputs = batch.outputs;
    world.depositor = Some(depositor);
}

#[when(expr = "the SPL depositor zone-batch-shields {int} lamports and {int} tokens")]
fn zone_batch_shield_mixed(world: &mut ShieldedPoolWorld, lamports: u64, tokens: u64) {
    prepare_zone(world);
    let tree = world.tree().pubkey();
    let depositor = world.depositor().insecure_clone();
    let mint = world.mint();
    let user_token = world.user_token();
    let vault = pda::spl_interface(&mint);
    let interface_before = interface_lamports(world);
    let vault_before = world.rpc().token_balance(&vault).expect("vault balance");

    let deposits = vec![
        zone_entry(DepositAsset::Sol, lamports, 11, None, None),
        zone_entry(
            DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: ZolanaProgramTest::token_program_id(),
            }),
            tokens,
            12,
            None,
            None,
        ),
        zone_entry(DepositAsset::Sol, lamports, 13, None, None),
    ];
    let batch = world
        .rpc()
        .zone_deposit_batch(&tree, &depositor, deposits)
        .expect("mixed zone batch");

    assert_eq!(
        batch.spl_transfers,
        vec![
            SplTransfer {
                is_deposit: true,
                amount: lamports * 2,
                asset: None,
            },
            SplTransfer {
                is_deposit: true,
                amount: tokens,
                asset: Some(mint.to_bytes()),
            },
        ]
    );
    assert_eq!(interface_lamports(world) - interface_before, lamports * 2);
    assert_eq!(
        world.rpc().token_balance(&vault).expect("vault balance") - vault_before,
        tokens
    );
    assert_eq!(
        batch
            .outputs
            .iter()
            .map(|output| output.output.asset)
            .collect::<Vec<_>>(),
        vec![[0; 32], mint.to_bytes(), [0; 32]]
    );
    world.zone_batch_outputs = batch.outputs;
}

#[then(expr = "the zone batch appends {int} distinct leaves")]
fn zone_batch_appended(world: &mut ShieldedPoolWorld, count: usize) {
    assert_eq!(world.zone_batch_outputs.len(), count);
    let mut hashes = world
        .zone_batch_outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(hashes.len(), count);
}

#[when(expr = "a zone proofless deposit is sent straight to the pool with the wrong signer")]
fn zone_shield_wrong_signer(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");

    let data = world
        .rpc()
        .zone_sol_shield_data(1_000_000, [3u8; 32], test_blinding(4));
    let mut ix = ZoneDeposit {
        tree,
        depositor: depositor.pubkey(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("valid zone deposit");
    if let Some(meta) = ix.accounts.get_mut(2) {
        meta.pubkey = depositor.pubkey();
    }
    let err = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    world.last_error = Some(err);
}
