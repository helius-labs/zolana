//! Settlement-guard negatives for the withdrawal rail. All of them fire in
//! account validation, before proof verification, so no real proof is needed.
//!
//! - Payer/settlement negatives: an unsigned payer meta (20009) and a
//!   non-canonical `sol_interface` PDA (7009).
//! - SPL vault negatives (7009): a non-canonical vault address, a vault/user
//!   mint mismatch, and a vault whose token owner is not the CPI authority.
//! - SPL token-account shape negatives (7009): a settlement account not owned
//!   by the SPL Token program, a wrong `data_len`, and an uninitialized state
//!   byte.
//!
//! Removed with the old public-amount fields: the C-01 both-amounts case
//! (multiple interface-transfer legs are now legal and settle independently).
//! The `cpi_authority` instruction-data FIELD was removed too, but the
//! cpi_authority ACCOUNT slot is still validated against the canonical PDA —
//! its negative lives in `spl_withdrawal_rejects_a_wrong_cpi_authority_account`
//! (INV-TRANSACT-14).

use shielded_pool_tests::support::fixtures::Pool;

use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, InterfaceTransfer, TransactIxData, TransactProof},
        Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplWithdrawalAccounts,
    },
    pda, N_PUBLIC_SLOTS, SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_ACCOUNT_LEN,
    SPL_TOKEN_ACCOUNT_STATE_OFFSET,
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::{eddsa_input_utxo, fe, inline_output};

/// SOL-withdrawal-shaped (negative public amount) transact data with a zeroed
/// proof: the payer/settlement account checks under test fire during account
/// validation, before proof verification.
fn sol_withdrawal_ix_data() -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(2, 3, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        inputs: vec![eddsa_input_utxo(fe(201), 0), eddsa_input_utxo(fe(202), 0)],
        interface_transfers: vec![InterfaceTransfer::SolWithdrawal {
            amount: 1_000_000_000,
        }],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![
            inline_output([4u8; 32], [4u8; 32]),
            inline_output([5u8; 32], [5u8; 32]),
            inline_output([6u8; 32], [6u8; 32]),
        ],
        messages: Vec::new(),
    }
}

/// Swap the SOL leg for an SPL one of `amount`.
fn spl_withdrawal_leg(mut ix_data: TransactIxData, amount: u64, mint: &Pubkey) -> TransactIxData {
    ix_data.interface_transfers = vec![InterfaceTransfer::SplWithdrawal {
        amount,
        spl_interface_bump: pda::spl_interface_with_bump(mint).1,
    }];
    ix_data
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

    // Bind the input owners to the signed fee payer passed as an owner signer
    // (the builder appends it after the system program, at index 5), so the
    // input-signer checks pass and the unsigned SPP payer meta itself is what
    // `validate_and_parse` rejects.
    let ix_data = sol_withdrawal_ix_data();
    let mut ix = Transact {
        payer: spp_payer,
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        owner_signers: vec![fee_payer],
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        data: ix_data,
    }
    .instruction();
    ix.accounts.get_mut(0).expect("payer meta").is_signer = false;

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
        input_tree: tree.pubkey(),
        output_tree: tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        data: sol_withdrawal_ix_data(),
    }
    .instruction();
    // Swap the canonical SOL-custody PDA (first group account, index 5) for an
    // attacker account.
    ix.accounts.get_mut(5).expect("sol_interface meta").pubkey = Pubkey::new_unique();

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
    fn valid_withdrawal(&self) -> TransactSplWithdrawalAccounts {
        TransactSplWithdrawalAccounts {
            mint: self.mint,
            spl_interface: self.vault,
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
    fn expect_settlement_rejection(&mut self, spl: TransactSplWithdrawalAccounts) {
        let ix_data = spl_withdrawal_leg(sol_withdrawal_ix_data(), 1_000, &self.mint);
        let ix = Transact {
            payer: self.attacker.pubkey(),
            input_tree: self.tree.pubkey(),
            output_tree: self.tree.pubkey(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
                spl,
            )],
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
fn spl_withdrawal_rejects_a_wrong_cpi_authority_account() {
    let mut env = SplWithdrawalEnv::boot();
    // INV-TRANSACT-14: substitute a non-canonical account at the cpi_authority
    // slot (the first account of the SPL-withdrawal group, hardcoded by the
    // builder); the slot is validated against `SHIELDED_POOL_CPI_AUTHORITY`
    // before any vault check runs.
    let ix_data = spl_withdrawal_leg(sol_withdrawal_ix_data(), 1_000, &env.mint);
    let mut ix = Transact {
        payer: env.attacker.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            env.valid_withdrawal(),
        )],
        data: ix_data,
    }
    .instruction();
    // The withdrawal group's cpi_authority is the first group account (index 5).
    ix.accounts.get_mut(5).expect("cpi_authority meta").pubkey = Pubkey::new_unique();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("a non-canonical cpi_authority account must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("cpi_authority rejection trace")
        .assert_rolled_back_except(&[env.attacker.pubkey()]);
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
    spl.spl_interface = decoy_vault;
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
