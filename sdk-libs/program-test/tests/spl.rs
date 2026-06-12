//! SPL matrix: create_spl_interface (spec tag 4) and the SPL settlement leg
//! of proofless_shield.
//!
//! Cases:
//!  1. create_spl_interface succeeds: registry carries magic + mint, the
//!     vault is a token account for the mint owned by the cpi authority.
//!  2. create_spl_interface by a non-authority signer — reject.
//!  3. create_spl_interface twice for the same mint — reject (registry
//!     already written).
//!  4. SPL deposit succeeds: vault credited, depositor debited, the event
//!     carries the mint, and the indexer recomputation/root parity hold.
//!  5. Deposit from a token account the signer does not own — reject.
//!  6. Vault swapped for a non-canonical token account of the same mint and
//!     vault owner — reject (vault pinned to its PDA).
//!  7. Registry/vault of mint A with a user token account of mint B — reject.
//!  8. Deposit exceeding the depositor's token balance fails inside the
//!     token program.

mod common;

use common::{assert_custom, rig_with_tree};
use light_program_test::{PoolIndexer, PoolTestRig};
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

// Stable on-chain error codes (programs/shielded-pool/src/error.rs).
const UNAUTHORIZED_CALLER: u32 = 5;
const INVALID_SETTLEMENT_ACCOUNTS: u32 = 13;
const INVALID_SPL_ASSET_REGISTRY: u32 = 15;

/// Boot a rig with a tree, a registered mint, and a depositor holding
/// `balance` tokens. Returns (rig, tree, mint, depositor, user_token).
fn spl_setup(balance: u64) -> Option<(PoolTestRig, Keypair, Pubkey, Keypair, Pubkey)> {
    let (mut rig, authority, tree) = rig_with_tree()?;
    let mint = rig.create_mint().expect("create_mint");
    rig.create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 1_000_000_000).expect("fund");
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

    // 1: registry magic + mint; vault is a token account for the mint owned
    // (token-level) by the cpi authority.
    let (registry, vault) = rig
        .create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    let registry_data = rig.account_data(&registry).expect("registry exists");
    assert_eq!(&registry_data[0..8], b"SPASSET1");
    assert_eq!(&registry_data[8..40], mint.as_ref());
    let vault_data = rig.account_data(&vault).expect("vault exists");
    assert_eq!(&vault_data[0..32], mint.as_ref(), "vault mint");
    assert_eq!(
        &vault_data[32..64],
        rig.cpi_authority().as_ref(),
        "vault owner is the cpi authority"
    );
    assert_eq!(rig.token_balance(&vault), Some(0));

    // 3: a second create for the same mint must fail — the registry is
    // already written. (Fresh blockhash so the byte-identical transaction is
    // not deduped as already processed.)
    rig.svm.expire_blockhash();
    let err = rig.create_spl_interface(&authority, &mint).unwrap_err();
    assert_custom(err, INVALID_SPL_ASSET_REGISTRY);
}

#[test]
fn create_spl_interface_rejects_non_authority() {
    let Some((mut rig, _authority, _tree)) = rig_with_tree() else {
        return;
    };
    let mint = rig.create_mint().expect("create_mint");

    // 2: an impostor signs.
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000).expect("fund");
    let err = rig.create_spl_interface(&impostor, &mint).unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
}

#[test]
fn spl_deposit_succeeds_and_event_is_faithful() {
    let Some((mut rig, tree, mint, depositor, user_token)) = spl_setup(1_000_000) else {
        return;
    };
    let vault = rig.spl_asset_vault_pda(&mint);
    let mut data = PoolTestRig::spl_shield_data(400_000, [7u8; 32]);
    data.view_tag = [9u8; 32];
    data.salt = [3u8; 16];

    // 4: balances move, the event names the mint, the indexer's independent
    // utxo_hash recomputation passes, and root parity holds.
    let root_before = rig.state_root(&tree.pubkey()).expect("root");
    let event = rig
        .proofless_shield_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("deposit");

    assert_eq!(event.amount, 400_000);
    assert_eq!(event.asset, mint.to_bytes());
    assert_eq!(event.owner_utxo_hash, [7u8; 32]);
    assert_eq!(rig.token_balance(&vault), Some(400_000));
    assert_eq!(rig.token_balance(&user_token), Some(600_000));
    assert_ne!(
        rig.state_root(&tree.pubkey()).expect("root"),
        root_before,
        "leaf must be appended"
    );

    let mut indexer = PoolIndexer::new();
    indexer.record_proofless_shield(&event);
    assert_eq!(indexer.root(), rig.state_root(&tree.pubkey()).expect("root"));
}

/// The standard SPL-deposit account list (proofless_shield_spl) so shape
/// cases can mutate it. [tree, signer, cpi_authority, user_token, vault,
/// registry, token_program, program].
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

    // 5: the token account belongs to someone else; the signer cannot pay
    // from it.
    let other = Keypair::new();
    let other_token = rig
        .create_token_account(&mint, &other.pubkey())
        .expect("token account");
    rig.mint_to(&mint, &other_token, 1_000_000).expect("mint_to");
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
    assert_custom(err, INVALID_SETTLEMENT_ACCOUNTS);
}

#[test]
fn rejects_non_canonical_vault() {
    let Some((mut rig, tree, mint, depositor, user_token)) = spl_setup(1_000_000) else {
        return;
    };

    // 6: a token account with the right mint and the cpi authority as owner,
    // but not at the canonical vault PDA.
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
    assert_custom(err, INVALID_SETTLEMENT_ACCOUNTS);
}

#[test]
fn rejects_mint_mismatch() {
    let Some((mut rig, tree, mint_a, depositor, _user_token)) = spl_setup(1_000_000) else {
        return;
    };

    // 7: registry and vault are mint A's, the user token account holds mint B.
    let mint_b = rig.create_mint().expect("mint B");
    let token_b = rig
        .create_token_account(&mint_b, &depositor.pubkey())
        .expect("token account");
    rig.mint_to(&mint_b, &token_b, 1_000_000).expect("mint_to");
    let accounts = spl_accounts(
        &rig,
        &tree.pubkey(),
        &depositor.pubkey(),
        &token_b,
        &mint_a,
    );
    let err = rig
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &PoolTestRig::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_custom(err, INVALID_SETTLEMENT_ACCOUNTS);
}

#[test]
fn rejects_unaffordable_spl_deposit() {
    let Some((mut rig, tree, mint, depositor, user_token)) = spl_setup(1_000) else {
        return;
    };

    // 8: the depositor holds 1_000 tokens; a 5_000 deposit fails inside the
    // token-program transfer CPI, and that inner error aborts the
    // instruction directly.
    let err = rig
        .proofless_shield_spl(
            &tree,
            &depositor,
            &user_token,
            &mint,
            &PoolTestRig::spl_shield_data(5_000, [3u8; 32]),
        )
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("Custom(1)"),
        "expected the token transfer to fail with insufficient funds, got: {msg}"
    );
}
