//! SPL asset registration and public SPL-deposit settlement coverage.

mod common;

use common::{assert_custom, assert_pool_error, rig_with_tree};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    SPL_ASSET_REGISTRY_ASSET_ID_OFFSET, SPL_ASSET_REGISTRY_MAGIC, SPL_ASSET_REGISTRY_MAGIC_END,
    SPL_ASSET_REGISTRY_MAGIC_OFFSET, SPL_ASSET_REGISTRY_MINT_END, SPL_ASSET_REGISTRY_MINT_OFFSET,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{proofless_event_for_wallet, PoolTestRig};
use zolana_transaction::Wallet;

const TOKEN_INSUFFICIENT_FUNDS: u32 = 1;
const TOKEN_ACCOUNT_MINT_OFFSET: usize = 0;
const TOKEN_ACCOUNT_OWNER_OFFSET: usize = 32;
const TOKEN_ACCOUNT_OWNER_END: usize = 64;

fn read_le_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn registry_mint(data: &[u8]) -> &[u8] {
    &data[SPL_ASSET_REGISTRY_MINT_OFFSET..SPL_ASSET_REGISTRY_MINT_END]
}

fn registry_asset_id(data: &[u8]) -> u64 {
    read_le_u64(data, SPL_ASSET_REGISTRY_ASSET_ID_OFFSET)
}

fn spl_setup(balance: u64) -> Option<(PoolTestRig, Keypair, Pubkey, Keypair, Pubkey)> {
    let (mut rig, authority, tree) = rig_with_tree()?;
    let mint = rig.create_mint().expect("create_mint");
    rig.create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund");
    let user_token = rig
        .create_token_account(&mint, &depositor.pubkey())
        .expect("token account");
    rig.mint_to(&mint, &user_token, balance).expect("mint_to");
    Some((rig, tree, mint, depositor, user_token))
}

#[test]
fn create_spl_interface_initializes_registry_and_vault() {
    let Some((mut rig, authority, _tree)) = rig_with_tree() else {
        return;
    };
    let mint = rig.create_mint().expect("create_mint");

    let (registry, vault) = rig
        .create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    let registry_data = rig.account_data(&registry).expect("registry exists");
    assert_eq!(
        &registry_data[SPL_ASSET_REGISTRY_MAGIC_OFFSET..SPL_ASSET_REGISTRY_MAGIC_END],
        SPL_ASSET_REGISTRY_MAGIC.as_slice()
    );
    assert_eq!(registry_mint(&registry_data), mint.as_ref());
    assert_eq!(registry_asset_id(&registry_data), 2, "first SPL asset id");
    let counter_data = rig
        .account_data(&rig.spl_asset_counter_pda())
        .expect("counter exists");
    assert_eq!(read_le_u64(&counter_data, 0), 3, "next SPL asset id");
    let vault_data = rig.account_data(&vault).expect("vault exists");
    assert_eq!(
        &vault_data[TOKEN_ACCOUNT_MINT_OFFSET..TOKEN_ACCOUNT_OWNER_OFFSET],
        mint.as_ref(),
        "vault mint"
    );
    assert_eq!(
        &vault_data[TOKEN_ACCOUNT_OWNER_OFFSET..TOKEN_ACCOUNT_OWNER_END],
        rig.cpi_authority().as_ref(),
        "vault owner is the cpi authority"
    );
    assert_eq!(rig.token_balance(&vault), Some(0));

    // Fresh blockhash so the byte-identical transaction is not deduped as
    // already processed.
    rig.svm.expire_blockhash();
    let err = rig.create_spl_interface(&authority, &mint).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSplAssetRegistry);

    let mint_b = rig.create_mint().expect("create_mint");
    let (registry_b, _vault_b) = rig
        .create_spl_interface(&authority, &mint_b)
        .expect("create_spl_interface mint B");
    let registry_b_data = rig.account_data(&registry_b).expect("registry B exists");
    assert_eq!(
        registry_asset_id(&registry_b_data),
        3,
        "second SPL asset id"
    );
    let counter_data = rig
        .account_data(&rig.spl_asset_counter_pda())
        .expect("counter exists");
    assert_eq!(read_le_u64(&counter_data, 0), 4, "next SPL asset id");
}

#[test]
fn create_spl_interface_rejects_non_authority() {
    let Some((mut rig, _authority, _tree)) = rig_with_tree() else {
        return;
    };
    let mint = rig.create_mint().expect("create_mint");

    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig.create_spl_interface(&impostor, &mint).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn spl_deposit_succeeds_and_event_is_faithful() {
    let Some((mut rig, tree, mint, depositor, user_token)) = spl_setup(1_000_000) else {
        return;
    };
    let vault = rig.spl_asset_vault_pda(&mint);
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [7u8; BLINDING_LEN];
    let (data, blinding) = PoolTestRig::wallet_spl_shield_data(400_000, &recipient, &seed, 0)
        .expect("wallet deposit data");

    let root_before = rig.state_root(&tree.pubkey()).expect("root");
    let event = rig
        .proofless_shield_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("deposit");

    assert_eq!(event.amount, 400_000);
    assert_eq!(event.asset, mint.to_bytes());
    assert_eq!(event.owner_utxo_hash, data.owner_utxo_hash);
    assert_eq!(event.view_tag, data.view_tag);
    assert_eq!(rig.token_balance(&vault), Some(400_000));
    assert_eq!(rig.token_balance(&user_token), Some(600_000));
    assert_ne!(
        rig.state_root(&tree.pubkey()).expect("root"),
        root_before,
        "leaf must be appended"
    );

    assert_eq!(
        rig.indexer().root(),
        rig.state_root(&tree.pubkey()).expect("root")
    );
    assert!(
        recipient
            .sync_proofless_deposit(&proofless_event_for_wallet(&event), blinding)
            .expect("wallet discovery"),
        "recipient wallet must discover the SPL deposit"
    );
    assert_eq!(recipient.utxos[0].hash, event.utxo_hash);
    assert_eq!(recipient.utxos[0].utxo.asset.to_bytes(), mint.to_bytes());
}

fn spl_accounts(
    rig: &PoolTestRig,
    tree: &Pubkey,
    depositor: &Pubkey,
    user_token: &Pubkey,
    mint: &Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*tree, false),
        AccountMeta::new(*depositor, true),
        AccountMeta::new_readonly(rig.cpi_authority(), false),
        AccountMeta::new(*user_token, false),
        AccountMeta::new(rig.spl_asset_vault_pda(mint), false),
        AccountMeta::new_readonly(rig.spl_asset_registry_pda(mint), false),
        AccountMeta::new_readonly(PoolTestRig::token_program_id(), false),
        AccountMeta::new_readonly(rig.program_id, false),
    ]
}

#[test]
fn rejects_deposit_from_foreign_token_account() {
    let Some((mut rig, tree, mint, depositor, _user_token)) = spl_setup(1_000_000) else {
        return;
    };

    let other = Keypair::new();
    let other_token = rig
        .create_token_account(&mint, &other.pubkey())
        .expect("token account");
    rig.mint_to(&mint, &other_token, 1_000_000)
        .expect("mint_to");
    let accounts = spl_accounts(
        &rig,
        &tree.pubkey(),
        &depositor.pubkey(),
        &other_token,
        &mint,
    );
    let err = rig
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &PoolTestRig::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_non_canonical_vault() {
    let Some((mut rig, tree, mint, depositor, user_token)) = spl_setup(1_000_000) else {
        return;
    };

    let decoy_vault = rig
        .create_token_account(&mint, &rig.cpi_authority())
        .expect("decoy vault");
    let mut accounts = spl_accounts(
        &rig,
        &tree.pubkey(),
        &depositor.pubkey(),
        &user_token,
        &mint,
    );
    accounts[4] = AccountMeta::new(decoy_vault, false);
    let err = rig
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &PoolTestRig::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_mint_mismatch() {
    let Some((mut rig, tree, mint_a, depositor, _user_token)) = spl_setup(1_000_000) else {
        return;
    };

    let mint_b = rig.create_mint().expect("mint B");
    let token_b = rig
        .create_token_account(&mint_b, &depositor.pubkey())
        .expect("token account");
    rig.mint_to(&mint_b, &token_b, 1_000_000).expect("mint_to");
    let accounts = spl_accounts(&rig, &tree.pubkey(), &depositor.pubkey(), &token_b, &mint_a);
    let err = rig
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &PoolTestRig::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_unaffordable_spl_deposit() {
    let Some((mut rig, tree, mint, depositor, user_token)) = spl_setup(1_000) else {
        return;
    };

    let err = rig
        .proofless_shield_spl(
            &tree,
            &depositor,
            &user_token,
            &mint,
            &PoolTestRig::spl_shield_data(5_000, [3u8; 32]),
        )
        .unwrap_err();
    assert_custom(err, TOKEN_INSUFFICIENT_FUNDS);
}
