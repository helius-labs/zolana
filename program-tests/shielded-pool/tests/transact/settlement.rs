//! Settlement-guard negatives for the withdrawal rail. All of them fire in
//! account validation, before proof verification, so no real proof is needed.
//!
//! - C-01 regression: a both-amounts `transact` used to mint an unbacked UTXO,
//!   because the parser settles one asset (SPL when `public_spl_amount` is set)
//!   while the proven SOL leg never moved. The fix rejects both-present up
//!   front with `BothPublicAmountsSet` (7023) and moves no tokens.
//! - Payer/settlement negatives: an unsigned payer meta (20009), a
//!   non-canonical `sol_interface` PDA, and a wrong `cpi_authority` on the SPL
//!   withdrawal leg (both 7009).
//! - SPL vault negatives (7009): a non-canonical vault address, a vault/user
//!   mint mismatch, and a vault whose token owner is not the CPI authority.
//! - SPL token-account shape negatives (7009): a settlement account not owned
//!   by the SPL Token program, a wrong `data_len`, and an uninitialized state
//!   byte.

use shielded_pool_tests::support::fixtures::Pool;

use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{TransactIxData, TransactProof},
        Transact, TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal,
    },
    pda, SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_ACCOUNT_STATE_OFFSET,
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::{eddsa_input_utxo, fe, inline_output};

#[test]
fn both_public_amounts_are_rejected() {
    let Pool {
        mut rpc,
        authority,
        tree,
    } = Pool::initialized();

    let attacker = rpc.payer.insecure_clone();

    // Valid SPL accounts, so the tx reaches the guard, not an earlier account error.
    let mint = rpc.create_mint().expect("create mint");
    rpc.ensure_asset_counter(&authority).expect("asset counter");
    let (_registry, vault) = rpc
        .create_spl_interface(&authority, &mint)
        .expect("create spl interface");
    let attacker_ata = rpc
        .create_token_account(&mint, &attacker.pubkey())
        .expect("attacker ata");
    rpc.mint_to(&mint, &attacker_ata, 1_000).expect("mint dust");

    // Both amounts set: +1 SOL and +1000 SPL.
    let ix_data = TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        p256_signing_pk_x: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![eddsa_input_utxo(fe(101), 0), eddsa_input_utxo(fe(102), 0)],
        public_sol_amount: Some(1_000_000_000),
        public_spl_amount: Some(1_000),
        data_hash: None,
        zone_data_hash: None,
        outputs: vec![
            inline_output([1u8; 32], [1u8; 32]),
            inline_output([2u8; 32], [2u8; 32]),
            inline_output([3u8; 32], [3u8; 32]),
        ],
        messages: Vec::new(),
    };

    let ix = Transact {
        payer: attacker.pubkey(),
        tree: tree.pubkey(),
        withdrawal: Some(TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: None,
            spl_token_interface: vault,
            recipient: attacker.pubkey(),
            user_token_account: attacker_ata,
            token_program: ZolanaProgramTest::token_program_id(),
        })),
        data: ix_data,
    }
    .instruction();

    let ata_before = rpc.token_balance(&attacker_ata).unwrap_or(0);
    let vault_before = rpc.token_balance(&vault).unwrap_or(0);
    let sol_vault_before = rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0);

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("both-amounts transact must be rejected");
    Rejection::pool(ShieldedPoolError::BothPublicAmountsSet).assert_litesvm(error);

    // The guard fires before settlement, so nothing moved.
    assert_eq!(
        rpc.token_balance(&attacker_ata).unwrap_or(0),
        ata_before,
        "no SPL debited"
    );
    assert_eq!(
        rpc.token_balance(&vault).unwrap_or(0),
        vault_before,
        "no SPL credited"
    );
    assert_eq!(
        rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0),
        sol_vault_before,
        "no SOL moved"
    );
}

/// SOL-withdrawal-shaped (negative public amount) transact data with a zeroed
/// proof: the payer/settlement account checks under test fire during account
/// validation, before proof verification.
fn sol_withdrawal_ix_data() -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        p256_signing_pk_x: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![eddsa_input_utxo(fe(201), 0), eddsa_input_utxo(fe(202), 0)],
        public_sol_amount: Some(-1_000_000_000),
        public_spl_amount: None,
        data_hash: None,
        zone_data_hash: None,
        outputs: vec![
            inline_output([4u8; 32], [4u8; 32]),
            inline_output([5u8; 32], [5u8; 32]),
            inline_output([6u8; 32], [6u8; 32]),
        ],
        messages: Vec::new(),
    }
}

fn withdrawal_env() -> (ZolanaProgramTest, Keypair) {
    let Pool { rpc, tree, .. } = Pool::initialized();
    (rpc, tree)
}

#[test]
fn sol_withdrawal_rejects_an_unsigned_payer_meta() {
    let (mut rpc, tree) = withdrawal_env();
    let fee_payer = rpc.payer.pubkey();
    let spp_payer = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let sol_vault_before = rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0);

    // Bind the input owners to the signed fee payer inserted at index 5, so
    // the input-signer checks pass and the unsigned SPP payer meta itself is
    // what `validate_and_parse` rejects.
    let mut ix_data = sol_withdrawal_ix_data();
    for input in &mut ix_data.inputs {
        input.eddsa_signer_index = 5;
    }
    let mut ix = Transact {
        payer: spp_payer,
        tree: tree.pubkey(),
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient })),
        data: ix_data,
    }
    .instruction();
    ix.accounts.get_mut(0).expect("payer meta").is_signer = false;
    ix.accounts
        .insert(5, AccountMeta::new_readonly(fee_payer, true));

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned withdrawal payer must be rejected");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("unsigned payer transaction trace")
        .assert_rolled_back_except(&[fee_payer]);
    assert_eq!(
        rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0),
        sol_vault_before,
        "no SOL moved"
    );
}

#[test]
fn sol_withdrawal_rejects_a_non_canonical_sol_interface() {
    let (mut rpc, tree) = withdrawal_env();
    let payer = rpc.payer.pubkey();
    let recipient = Pubkey::new_unique();
    let sol_vault_before = rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0);

    let mut ix = Transact {
        payer,
        tree: tree.pubkey(),
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient })),
        data: sol_withdrawal_ix_data(),
    }
    .instruction();
    // Swap the canonical SOL-custody PDA (index 2) for an attacker account.
    ix.accounts.get_mut(2).expect("sol_interface meta").pubkey = Pubkey::new_unique();

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("non-canonical sol_interface must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("wrong sol_interface transaction trace")
        .assert_rolled_back_except(&[payer]);
    assert_eq!(
        rpc.svm.get_balance(&pda::sol_interface()).unwrap_or(0),
        sol_vault_before,
        "no SOL moved"
    );
}

#[test]
fn spl_withdrawal_rejects_a_wrong_cpi_authority() {
    let Pool {
        mut rpc,
        authority,
        tree,
    } = Pool::initialized();
    let attacker = rpc.payer.insecure_clone();

    // Valid SPL settlement accounts throughout, so the wrong `cpi_authority`
    // is the only defect the instruction carries.
    let mint = rpc.create_mint().expect("create mint");
    rpc.ensure_asset_counter(&authority).expect("asset counter");
    let (_registry, vault) = rpc
        .create_spl_interface(&authority, &mint)
        .expect("create spl interface");
    let attacker_ata = rpc
        .create_token_account(&mint, &attacker.pubkey())
        .expect("attacker ata");
    rpc.mint_to(&mint, &attacker_ata, 1_000).expect("mint dust");

    let mut ix_data = sol_withdrawal_ix_data();
    ix_data.public_sol_amount = None;
    ix_data.public_spl_amount = Some(-1_000);

    let ix = Transact {
        payer: attacker.pubkey(),
        tree: tree.pubkey(),
        withdrawal: Some(TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: Some(Pubkey::new_unique()),
            spl_token_interface: vault,
            recipient: attacker.pubkey(),
            user_token_account: attacker_ata,
            token_program: ZolanaProgramTest::token_program_id(),
        })),
        data: ix_data,
    }
    .instruction();

    let ata_before = rpc.token_balance(&attacker_ata).unwrap_or(0);
    let vault_before = rpc.token_balance(&vault).unwrap_or(0);

    let error = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("wrong cpi_authority must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(error);
    rpc.last_transaction_trace()
        .expect("wrong cpi_authority transaction trace")
        .assert_rolled_back_except(&[attacker.pubkey()]);
    assert_eq!(
        rpc.token_balance(&attacker_ata).unwrap_or(0),
        ata_before,
        "no SPL credited"
    );
    assert_eq!(
        rpc.token_balance(&vault).unwrap_or(0),
        vault_before,
        "no SPL debited"
    );
}

/// A fully valid SPL-withdrawal environment: canonical vault, canonical CPI
/// authority, funded attacker ATA. Each test swaps in exactly one settlement
/// defect, so the asserted rejection isolates that check.
struct SplWithdrawalEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
    attacker: Keypair,
    mint: Pubkey,
    vault: Pubkey,
    attacker_ata: Pubkey,
}

impl SplWithdrawalEnv {
    fn boot() -> Self {
        let Pool {
            mut rpc,
            authority,
            tree,
        } = Pool::initialized();
        let attacker = rpc.payer.insecure_clone();
        let mint = rpc.create_mint().expect("create mint");
        rpc.ensure_asset_counter(&authority).expect("asset counter");
        let (_registry, vault) = rpc
            .create_spl_interface(&authority, &mint)
            .expect("create spl interface");
        let attacker_ata = rpc
            .create_token_account(&mint, &attacker.pubkey())
            .expect("attacker ata");
        rpc.mint_to(&mint, &attacker_ata, 1_000).expect("mint dust");
        Self {
            rpc,
            tree,
            attacker,
            mint,
            vault,
            attacker_ata,
        }
    }

    /// SPL withdrawal accounts that would pass every settlement check.
    fn valid_withdrawal(&self) -> TransactSplWithdrawal {
        TransactSplWithdrawal {
            cpi_authority: Some(pda::shielded_pool_cpi_authority()),
            spl_token_interface: self.vault,
            recipient: self.attacker.pubkey(),
            user_token_account: self.attacker_ata,
            token_program: ZolanaProgramTest::token_program_id(),
        }
    }

    /// Materialize a token-account-shaped account directly in LiteSVM at a
    /// fresh address, owned by `owner_program`.
    fn write_token_account(&mut self, owner_program: Pubkey, data: Vec<u8>) -> Pubkey {
        let address = Pubkey::new_unique();
        self.rpc
            .svm
            .set_account(
                address,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner: owner_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("write fabricated token account");
        address
    }

    /// Send an SPL withdrawal carrying `spl` and assert the exact
    /// `InvalidSettlementAccounts` rejection with full rollback: the guards
    /// fire during account validation, before proof verification and any
    /// token movement.
    #[track_caller]
    fn expect_settlement_rejection(&mut self, spl: TransactSplWithdrawal) {
        let mut ix_data = sol_withdrawal_ix_data();
        ix_data.public_sol_amount = None;
        ix_data.public_spl_amount = Some(-1_000);
        let ix = Transact {
            payer: self.attacker.pubkey(),
            tree: self.tree.pubkey(),
            withdrawal: Some(TransactWithdrawal::Spl(spl)),
            data: ix_data,
        }
        .instruction();

        let ata_before = self.rpc.token_balance(&self.attacker_ata).unwrap_or(0);
        let vault_before = self.rpc.token_balance(&self.vault).unwrap_or(0);
        let error = self
            .rpc
            .create_and_send_default_payer_transaction(&[ix], &[])
            .expect_err("invalid settlement accounts must be rejected");
        Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(error);
        self.rpc
            .last_transaction_trace()
            .expect("settlement rejection trace")
            .assert_rolled_back_except(&[self.attacker.pubkey()]);
        assert_eq!(
            self.rpc.token_balance(&self.attacker_ata).unwrap_or(0),
            ata_before,
            "no SPL credited"
        );
        assert_eq!(
            self.rpc.token_balance(&self.vault).unwrap_or(0),
            vault_before,
            "no SPL debited"
        );
    }
}

/// Token-account bytes with the mint, token-owner, and state fields set; the
/// remaining fields are zeroed (irrelevant to `read_token_account`).
fn token_account_bytes(mint: &Pubkey, owner: &Pubkey, state: u8, len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    if let Some(slice) = data.get_mut(..32) {
        slice.copy_from_slice(mint.as_ref());
    }
    if let Some(slice) = data.get_mut(32..64) {
        slice.copy_from_slice(owner.as_ref());
    }
    if let Some(byte) = data.get_mut(SPL_TOKEN_ACCOUNT_STATE_OFFSET) {
        *byte = state;
    }
    data
}

#[test]
fn spl_withdrawal_rejects_a_non_canonical_vault() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-15: a real token account of the right mint whose token
    // owner IS the CPI authority, but which is not at the canonical
    // [b"spl_asset_vault", mint] PDA, must be rejected: liquidity cannot be
    // routed through a look-alike vault.
    let mint = env.mint;
    let decoy_vault = env
        .rpc
        .create_token_account(&mint, &pda::shielded_pool_cpi_authority())
        .expect("decoy vault");
    let mut spl = env.valid_withdrawal();
    spl.spl_token_interface = decoy_vault;
    env.expect_settlement_rejection(spl);
}

#[test]
fn spl_withdrawal_rejects_a_vault_user_mint_mismatch() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-15: the canonical vault (mint A) and a valid user token
    // account of mint B must not settle against each other.
    let other_mint = env.rpc.create_mint().expect("second mint");
    let attacker = env.attacker.pubkey();
    let other_ata = env
        .rpc
        .create_token_account(&other_mint, &attacker)
        .expect("other-mint ata");
    let mut spl = env.valid_withdrawal();
    spl.user_token_account = other_ata;
    env.expect_settlement_rejection(spl);
}

#[test]
fn spl_withdrawal_rejects_a_vault_not_owned_by_the_cpi_authority() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-15: rewrite the token-owner field (bytes 32..64) of the
    // otherwise canonical vault, so the CPI-authority ownership check is the
    // only defect the instruction carries.
    let mut account = env.rpc.svm.get_account(&env.vault).expect("vault account");
    account
        .data
        .get_mut(32..64)
        .expect("vault owner field")
        .copy_from_slice(env.attacker.pubkey().as_ref());
    env.rpc
        .svm
        .set_account(env.vault, account)
        .expect("rewrite vault owner");
    let spl = env.valid_withdrawal();
    env.expect_settlement_rejection(spl);
}

#[test]
fn spl_withdrawal_rejects_a_user_token_account_not_owned_by_the_token_program() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-16: perfectly token-account-shaped bytes under a foreign
    // owner program must be rejected.
    let bytes = token_account_bytes(
        &env.mint,
        &env.attacker.pubkey(),
        SPL_TOKEN_ACCOUNT_INITIALIZED,
        SPL_TOKEN_ACCOUNT_LEN,
    );
    let fake = env.write_token_account(Pubkey::new_unique(), bytes);
    let mut spl = env.valid_withdrawal();
    spl.user_token_account = fake;
    env.expect_settlement_rejection(spl);
}

#[test]
fn spl_withdrawal_rejects_a_user_token_account_with_a_wrong_length() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-16: `data_len` must be exactly 165; one byte short is
    // rejected even under the real SPL Token program owner.
    let bytes = token_account_bytes(
        &env.mint,
        &env.attacker.pubkey(),
        SPL_TOKEN_ACCOUNT_INITIALIZED,
        SPL_TOKEN_ACCOUNT_LEN - 1,
    );
    let fake = env.write_token_account(ZolanaProgramTest::token_program_id(), bytes);
    let mut spl = env.valid_withdrawal();
    spl.user_token_account = fake;
    env.expect_settlement_rejection(spl);
}

#[test]
fn spl_withdrawal_rejects_an_uninitialized_user_token_account() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-16: right owner, right length, matching mint, but the
    // state byte is Uninitialized (0) instead of Initialized (1).
    let bytes = token_account_bytes(&env.mint, &env.attacker.pubkey(), 0, SPL_TOKEN_ACCOUNT_LEN);
    let fake = env.write_token_account(ZolanaProgramTest::token_program_id(), bytes);
    let mut spl = env.valid_withdrawal();
    spl.user_token_account = fake;
    env.expect_settlement_rejection(spl);
}
