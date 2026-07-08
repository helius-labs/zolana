//! Squads zone withdrawal steps routed through the backend.
//!
//! Sync: the suite reads the vault's spendable UTXO via the backend `get_balances`,
//! builds a `PrivateTransactionIntent`, and calls `request_transact` on the
//! smart-account rail (`sender_owner_pubkey = None`) with a `Withdraw` type. The
//! backend re-derives the sender secrets via the auditor key, proves the `(1, 1)`
//! spend, and returns the `transact` instruction with the relayer (zone co-signer)
//! as payer + co-signer; the suite sends it as a v0+ALT transaction. The assert
//! verifies the public fund movement OUT of the pool plus the shielded change via
//! the backend.
//!
//! Async (SOL only): `create_proposal` is client-built (real blinding, encrypted to
//! the sender's shared viewing key); the autonomous background crank settles it.
//! The scenario waits for settlement, then asserts the change balance through the
//! backend. SPL withdrawal has no proposal-bound token destination, so the crank
//! cannot settle it and the SPL async scenario is not modelled.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::pda;
use zolana_squads_client::{
    PrivateTransactionIntent, RequestTransactRequest, RequestTransactResponse, TransactionType,
    SOL_ASSET_ID,
};
use zolana_squads_interface::types::Address as SquadsAddress;
use zolana_squads_sdk::proposal::proposal_hash;
use zolana_test_utils::{spl::create_token_account, test_validator_asserts::to_address};
use zolana_transaction::{Address, SOL_MINT};

use crate::{
    fixture::PROPOSAL_WITHDRAWN,
    steps::transfer::placeholder_encrypted_utxos,
    world::{SquadsLifecycleWorld, WithdrawalRecord},
};

/// A far-future expiry so scenarios never expire against the cluster clock.
const EXPIRY: i64 = i64::MAX;

/// The SPL asset id the suite registers (mirrors `world::FIRST_SPL_ASSET_ID`).
const SPL_ASSET_ID: u64 = 2;

/// Read an SPL token account's `amount` field (`mint(32) || owner(32) || amount(8)`).
fn token_amount(account: &solana_account::Account) -> Result<u64> {
    let bytes: [u8; 8] = account
        .data
        .get(64..72)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| anyhow!("not an SPL token account"))?;
    Ok(u64::from_le_bytes(bytes))
}

impl SquadsLifecycleWorld {
    /// Sync `transact` withdrawal of SOL from the vault's deposited zone UTXO to a
    /// fresh external account through the backend.
    pub(crate) fn withdraw_sol(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let inputs = self.wait_for_utxos(name, SOL_ASSET_ID, 1)?;
        let input = inputs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("{name} has no spendable SOL UTXO"))?;
        let recipient = Keypair::new().pubkey();
        let sol_interface = pda::sol_interface();
        let recipient_before = self.lamports(&recipient)?;
        let pool_before = self.lamports(&sol_interface)?;

        let intent = PrivateTransactionIntent {
            sender_viewing_key_account: self.viewing_key_account_address(name),
            inputs: vec![input],
            outputs: vec![],
            encrypted_utxos: placeholder_encrypted_utxos(),
            expiry: EXPIRY,
        };
        let instruction = self.request_withdrawal(intent, withdrawn, recipient)?;
        self.send_execute_v0_alt(instruction)?;

        self.withdrawals.insert(
            name.to_string(),
            WithdrawalRecord {
                withdrawn,
                recipient,
                recipient_before,
                pool: sol_interface,
                pool_before,
                is_spl: false,
            },
        );
        Ok(())
    }

    /// Sync `transact` withdrawal of the scenario SPL asset from the vault's UTXO to
    /// a fresh recipient token account through the backend.
    pub(crate) fn withdraw_spl(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let spl = self.spl_asset()?;
        let inputs = self.wait_for_utxos(name, SPL_ASSET_ID, 1)?;
        let input = inputs
            .into_iter()
            .find(|utxo| utxo.asset_id == SPL_ASSET_ID)
            .ok_or_else(|| anyhow!("{name} has no spendable SPL UTXO"))?;

        let vault = pda::spl_asset_vault(&spl.mint);
        let recipient_owner = Keypair::new();
        let payer = self.payer.insecure_clone();
        let recipient_token =
            create_token_account(&self.rpc, &payer, &spl.mint, &recipient_owner.pubkey())
                .map_err(|e| anyhow!("create recipient token account: {e}"))?;
        let recipient_before = self.token_balance(&recipient_token)?;
        let pool_before = self.token_balance(&vault)?;

        let intent = PrivateTransactionIntent {
            sender_viewing_key_account: self.viewing_key_account_address(name),
            inputs: vec![input],
            outputs: vec![],
            encrypted_utxos: placeholder_encrypted_utxos(),
            expiry: EXPIRY,
        };
        let instruction = self.request_withdrawal(intent, withdrawn, recipient_token)?;
        self.send_execute_v0_alt(instruction)?;

        self.withdrawals.insert(
            name.to_string(),
            WithdrawalRecord {
                withdrawn,
                recipient: recipient_token,
                recipient_before,
                pool: vault,
                pool_before,
                is_spl: true,
            },
        );
        Ok(())
    }

    /// Build the backend `Withdraw` request and unwrap the returned instruction.
    fn request_withdrawal(
        &self,
        intent: PrivateTransactionIntent,
        withdrawn: u64,
        recipient_account: Pubkey,
    ) -> Result<solana_instruction::Instruction> {
        let response = self
            .backend
            .request_transact(RequestTransactRequest {
                transaction_type: TransactionType::Withdraw {
                    public_amount: withdrawn,
                    recipient_account: Address::new_from_array(recipient_account.to_bytes()),
                },
                intent,
                sender_owner_pubkey: None,
                sender_vault: Some(Address::new_from_array(self.proposer_vault.to_bytes())),
                owner_signature: None,
            })
            .map_err(|e| anyhow!("backend request_transact withdraw: {e}"))?;
        match response {
            RequestTransactResponse::Instruction(ix) => Ok(ix),
            RequestTransactResponse::Signature(_) => {
                Err(anyhow!("smart-account withdrawal returned a signature"))
            }
        }
    }

    /// Create the async SOL withdrawal proposal (owned by the vault) via
    /// `create_proposal` wrapped in `executeTransactionSyncV2`; the background crank
    /// settles it. The `(amount, blinding)` is encrypted to the sender's shared
    /// viewing key so the crank recovers them.
    pub(crate) fn create_withdrawal_proposal(&mut self, name: &str) -> Result<()> {
        // The crank spends via get_balances, so the deposit must be indexed first.
        self.wait_for_utxos(name, SOL_ASSET_ID, 1)?;
        let withdrawn = PROPOSAL_WITHDRAWN;

        let sender_vka = self.viewing_key_account_address(name);
        let sender_account = self
            .backend
            .load_viewing_key_account(sender_vka)
            .map_err(|e| anyhow!("load sender viewing key account: {e}"))?;
        let cipher_recipient =
            zolana_keypair::P256Pubkey::from_bytes(sender_account.shared_viewing_key)
                .map_err(|e| anyhow!("sender shared key: {e:?}"))?;

        let blinding = crate::deposit_action::random_blinding();
        let hash = proposal_hash(0, &[0u8; 32], &blinding, withdrawn)
            .map_err(|e| anyhow!("withdrawal proposal hash: {e}"))?;

        let proposal_address = self.queue_proposal(
            hash,
            SquadsAddress::default(),
            SquadsAddress::new_from_array(SOL_MINT.to_bytes()),
            &cipher_recipient,
            withdrawn,
            &blinding,
        )?;

        self.pending_proposal = Some(proposal_address);
        Ok(())
    }

    /// Assert the recorded sync withdrawal for `name` moved `withdrawn` OUT of the
    /// pool to the public destination and drained the pool settlement account by the
    /// same amount.
    pub(crate) fn assert_withdrew(&self, name: &str, withdrawn: u64) -> Result<()> {
        let record = self
            .withdrawals
            .get(name)
            .ok_or_else(|| anyhow!("{name} has no recorded withdrawal"))?;
        if record.withdrawn != withdrawn {
            return Err(anyhow!(
                "recorded withdrawal amount {} does not match asserted {withdrawn}",
                record.withdrawn
            ));
        }

        let (recipient_after, pool_after) = if record.is_spl {
            (
                self.token_balance(&record.recipient)?,
                self.token_balance(&record.pool)?,
            )
        } else {
            (
                self.lamports(&record.recipient)?,
                self.lamports(&record.pool)?,
            )
        };
        let recipient_delta = recipient_after.saturating_sub(record.recipient_before);
        if recipient_delta != withdrawn {
            return Err(anyhow!(
                "recipient received {recipient_delta}, expected {withdrawn}"
            ));
        }
        let pool_delta = record.pool_before.saturating_sub(pool_after);
        if pool_delta != withdrawn {
            return Err(anyhow!("pool released {pool_delta}, expected {withdrawn}"));
        }
        Ok(())
    }

    /// An account's lamports, defaulting to zero when the account does not exist.
    fn lamports(&self, key: &Pubkey) -> Result<u64> {
        Ok(self
            .rpc
            .get_account(to_address(key))
            .map_err(|e| anyhow!("{e}"))?
            .map(|account| account.lamports)
            .unwrap_or(0))
    }

    /// An SPL token account's `amount`, defaulting to zero when it does not exist.
    fn token_balance(&self, key: &Pubkey) -> Result<u64> {
        match self
            .rpc
            .get_account(to_address(key))
            .map_err(|e| anyhow!("{e}"))?
        {
            Some(account) => token_amount(&account),
            None => Ok(0),
        }
    }
}

#[when(expr = "{word} withdraws {int} lamports of SOL")]
fn withdraws_sol(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .withdraw_sol(&name, amount as u64)
        .expect("withdraw SOL");
}

#[then(expr = "{word} received {int} lamports of SOL from the pool")]
fn received_sol(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .assert_withdrew(&name, amount as u64)
        .expect("assert SOL withdrawal");
}

#[when(expr = "{word} withdraws {int} tokens")]
fn withdraws_tokens(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .withdraw_spl(&name, amount as u64)
        .expect("withdraw tokens");
}

#[then(expr = "{word} received {int} tokens from the pool")]
fn received_tokens(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .assert_withdrew(&name, amount as u64)
        .expect("assert token withdrawal");
}

#[when(expr = "{word} creates a SOL withdrawal proposal")]
fn creates_sol_proposal(world: &mut SquadsLifecycleWorld, name: String) {
    world
        .create_withdrawal_proposal(&name)
        .expect("create SOL withdrawal proposal");
}

#[when(expr = "the crank settles the withdrawal proposal")]
fn crank_settles_withdrawal(world: &mut SquadsLifecycleWorld) {
    let address = world
        .pending_proposal
        .expect("no pending withdrawal proposal");
    world
        .wait_for_proposal_settled(address)
        .expect("crank settle withdrawal proposal");
}
