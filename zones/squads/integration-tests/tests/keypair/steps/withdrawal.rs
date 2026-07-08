//! Squads zone withdrawal steps driven through the backend's P256 keypair rail.
//!
//! A withdrawal is a `(1, 1)` spend that settles a public amount OUT of the pool.
//! The client no longer builds the proof: it reads the spendable input from the
//! backend's `getBalances`, asks the backend to probe the transaction (returning
//! the shared `private_tx_hash`), signs `sha256(private_tx_hash)` with the sender's
//! client-held P256 owner key, and asks the backend to finalize
//! (`requestTransact`) which returns the assembled `transact` instruction. The
//! backend is the relayer (fee payer + co-signer). The assert checks the on-chain
//! fund movement out of the pool; the sender's remaining balance is checked via
//! `getBalances`.

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::pda;
use zolana_squads_client::{
    DecryptedUtxo, GetBalancesRequest, PrivateTransactionIntent, RequestTransactRequest,
    RequestTransactResponse, TransactionType,
};
use zolana_squads_interface::{
    constants::SENDER_CIPHERTEXT_LEN, instruction::instruction_data::EncryptedUtxos,
};
use zolana_test_utils::{
    spl::create_token_account,
    test_validator_asserts::{fetch_account, to_address},
};

use crate::{
    fixture::{owner_keypair, viewing_key_account_address},
    localnet::{create_address_lookup_table, send_v0_transaction},
    world::{SquadsLifecycleWorld, WithdrawalRecord, WithdrawalSettlement},
};

/// A far-future expiry so scenarios never expire against the cluster clock.
const EXPIRY: i64 = i64::MAX;

/// The SPL token account `amount` field offset (`mint(32) || owner(32) || amount`).
const SPL_TOKEN_AMOUNT_OFFSET: usize = 64;

/// The zone SOL asset id (mirrors `zolana_squads_client::SOL_ASSET_ID`).
const SOL_ASSET_ID: u64 = 1;
/// The SPL asset id the suite registers.
const SPL_ASSET_ID: u64 = 2;

/// An empty output-ciphertext blob: the backend rebuilds the real ciphertexts from
/// the recovered secrets during proving, so the intent carries a placeholder.
fn empty_encrypted_utxos() -> EncryptedUtxos {
    EncryptedUtxos {
        tx_viewing_pk: [0u8; 33],
        sender_ciphertext: [0u8; SENDER_CIPHERTEXT_LEN],
        recipient_ciphertexts: Vec::new(),
    }
}

/// Read an SPL token account's `amount` (little-endian at offset 64).
fn token_amount(account: &Account) -> Result<u64> {
    let bytes = account
        .data
        .get(SPL_TOKEN_AMOUNT_OFFSET..SPL_TOKEN_AMOUNT_OFFSET + 8)
        .ok_or_else(|| anyhow!("token account too short"))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

impl SquadsLifecycleWorld {
    /// All spendable UTXOs the backend decrypts for `name` under `asset_id`.
    pub(crate) fn sender_inputs(&self, name: &str, asset_id: u64) -> Result<Vec<DecryptedUtxo>> {
        let viewing_key_account =
            Address::new_from_array(viewing_key_account_address(name).to_bytes());
        let response = self
            .backend
            .get_balances(GetBalancesRequest {
                viewing_key_account,
                skip_utxos: false,
                signature: [0u8; 64],
            })
            .map_err(|e| anyhow!("backend get_balances: {e}"))?;
        Ok(response
            .balances
            .into_iter()
            .find(|balance| balance.asset_id == asset_id)
            .map(|balance| balance.utxos)
            .unwrap_or_default())
    }

    /// Poll `getBalances` until `name` has at least `expected` spendable UTXOs of
    /// `asset_id` (Photon indexes a fresh deposit's output leaf and nullifier
    /// non-inclusion a few slots after the deposit confirms).
    pub(crate) fn wait_for_sender_inputs(
        &self,
        name: &str,
        asset_id: u64,
        expected: usize,
    ) -> Result<Vec<DecryptedUtxo>> {
        let started = Instant::now();
        loop {
            let inputs = self.sender_inputs(name, asset_id)?;
            if inputs.len() >= expected {
                return Ok(inputs);
            }
            if started.elapsed() > Duration::from_secs(30) {
                return Err(anyhow!(
                    "{name} has {} spendable {asset_id} UTXOs, expected {expected}",
                    inputs.len()
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The single spendable input for `name` under `asset_id` (a `(1, 1)` spend).
    fn sender_input(&self, name: &str, asset_id: u64) -> Result<DecryptedUtxo> {
        self.wait_for_sender_inputs(name, asset_id, 1)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("{name} has no spendable {asset_id} UTXO"))
    }

    /// Drive the backend's P256 keypair rail: probe for the shared
    /// `private_tx_hash`, sign `sha256(private_tx_hash)` with `signer_name`'s owner
    /// key, and finalize. Returns the assembled `transact` instruction.
    pub(crate) fn p256_transact(
        &self,
        signer_name: &str,
        mut request: RequestTransactRequest,
    ) -> Result<Instruction> {
        let private_tx_hash = self
            .backend
            .request_transact_probe(&request)
            .map_err(|e| anyhow!("request_transact probe: {e}"))?;
        let signature = owner_keypair(signer_name)
            .signing_key()
            .sign(&zolana_keypair::hash::sha256(&private_tx_hash));
        request.owner_signature = Some(signature);
        match self
            .backend
            .request_transact(request)
            .map_err(|e| anyhow!("request_transact finalize: {e}"))?
        {
            RequestTransactResponse::Instruction(ix) => Ok(ix),
            RequestTransactResponse::Signature(_) => Err(anyhow!(
                "backend unexpectedly sent the transact transaction"
            )),
        }
    }

    /// Send a backend-built `transact` instruction as a v0 transaction backed by an
    /// address lookup table. The instruction's fee payer and co-signer are both the
    /// backend relayer (the zone co-signer), so it is the only static signer.
    pub(crate) fn send_backend_v0_alt(&mut self, ix: Instruction) -> Result<Signature> {
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let relayer = self.co_signer.insecure_clone();
        let ixs = [budget, ix];

        let signer_keys: HashSet<Pubkey> = [relayer.pubkey()].into_iter().collect();
        let program_ids: HashSet<Pubkey> = ixs.iter().map(|i| i.program_id).collect();
        let mut seen: HashSet<Pubkey> = HashSet::new();
        let mut alt_addresses: Vec<Pubkey> = Vec::new();
        for instruction in &ixs {
            for meta in &instruction.accounts {
                if !signer_keys.contains(&meta.pubkey)
                    && !program_ids.contains(&meta.pubkey)
                    && seen.insert(meta.pubkey)
                {
                    alt_addresses.push(meta.pubkey);
                }
            }
        }

        let alt_account = create_address_lookup_table(&mut self.rpc, &relayer, &alt_addresses)?;
        send_v0_transaction(&mut self.rpc, &ixs, &relayer, &[&relayer], &[alt_account])
    }

    fn fetch_or_default(&self, key: &Pubkey) -> Result<Account> {
        Ok(self
            .rpc
            .get_account(to_address(key))
            .map_err(|e| anyhow!("{e}"))?
            .unwrap_or_default())
    }

    /// Withdraw `withdrawn` lamports of SOL from `name`'s deposited zone UTXO to a
    /// fresh external account, via the backend's P256 rail.
    pub(crate) fn withdraw_sol(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let input = self.sender_input(name, SOL_ASSET_ID)?;
        let recipient = Keypair::new().pubkey();
        let sol_interface = pda::sol_interface();

        let sol_interface_before = self.fetch_or_default(&sol_interface)?;
        let recipient_before = self.fetch_or_default(&recipient)?;

        let request = RequestTransactRequest {
            transaction_type: TransactionType::Withdraw {
                public_amount: withdrawn,
                recipient_account: Address::new_from_array(recipient.to_bytes()),
            },
            intent: self.withdrawal_intent(name, input),
            sender_owner_pubkey: Some(owner_keypair(name).owner_pubkey_bytes()),
            sender_vault: None,
            owner_signature: None,
        };
        let ix = self.p256_transact(name, request)?;
        self.send_backend_v0_alt(ix)?;

        self.withdrawals.insert(
            name.to_string(),
            WithdrawalRecord {
                withdrawn,
                settlement: WithdrawalSettlement::Sol {
                    sol_interface,
                    sol_interface_before,
                    recipient,
                    recipient_before,
                },
            },
        );
        Ok(())
    }

    /// Withdraw `withdrawn` tokens of the scenario SPL asset from `name`'s deposited
    /// zone UTXO to a fresh recipient token account, via the backend's P256 rail.
    pub(crate) fn withdraw_spl(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let spl = self.spl_asset()?;
        let input = self.sender_input(name, SPL_ASSET_ID)?;
        let vault = pda::spl_asset_vault(&spl.mint);
        let recipient_owner = Keypair::new();
        let payer = self.payer.insecure_clone();
        let recipient_token =
            create_token_account(&self.rpc, &payer, &spl.mint, &recipient_owner.pubkey())
                .map_err(|e| anyhow!("create recipient token account: {e}"))?;

        let vault_before = fetch_account(&self.rpc, &vault)?;
        let recipient_token_before = fetch_account(&self.rpc, &recipient_token)?;

        let request = RequestTransactRequest {
            transaction_type: TransactionType::Withdraw {
                public_amount: withdrawn,
                recipient_account: Address::new_from_array(recipient_token.to_bytes()),
            },
            intent: self.withdrawal_intent(name, input),
            sender_owner_pubkey: Some(owner_keypair(name).owner_pubkey_bytes()),
            sender_vault: None,
            owner_signature: None,
        };
        let ix = self.p256_transact(name, request)?;
        self.send_backend_v0_alt(ix)?;

        self.withdrawals.insert(
            name.to_string(),
            WithdrawalRecord {
                withdrawn,
                settlement: WithdrawalSettlement::Spl {
                    vault,
                    vault_before,
                    recipient_token,
                    recipient_token_before,
                },
            },
        );
        Ok(())
    }

    /// The shielded intent for a `(1, 1)` withdrawal: one input, no client-built
    /// outputs (the backend derives the change), and a placeholder ciphertext blob.
    fn withdrawal_intent(&self, name: &str, input: DecryptedUtxo) -> PrivateTransactionIntent {
        PrivateTransactionIntent {
            sender_viewing_key_account: Address::new_from_array(
                viewing_key_account_address(name).to_bytes(),
            ),
            inputs: vec![input],
            outputs: Vec::new(),
            encrypted_utxos: empty_encrypted_utxos(),
            expiry: EXPIRY,
        }
    }

    /// Assert the recorded withdrawal for `name` moved `withdrawn` real funds OUT of
    /// the pool: the pool interface / vault fell by `withdrawn` and the recipient
    /// account rose by it.
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

        match &record.settlement {
            WithdrawalSettlement::Sol {
                sol_interface,
                sol_interface_before,
                recipient,
                recipient_before,
            } => {
                let pool_after = fetch_account(&self.rpc, sol_interface)?;
                let recipient_after = fetch_account(&self.rpc, recipient)?;
                let pool_delta = sol_interface_before
                    .lamports
                    .checked_sub(pool_after.lamports)
                    .ok_or_else(|| anyhow!("pool balance rose on a withdrawal"))?;
                if pool_delta != withdrawn {
                    return Err(anyhow!("pool fell by {pool_delta}, expected {withdrawn}"));
                }
                let recipient_delta = recipient_after
                    .lamports
                    .saturating_sub(recipient_before.lamports);
                if recipient_delta != withdrawn {
                    return Err(anyhow!(
                        "recipient rose by {recipient_delta}, expected {withdrawn}"
                    ));
                }
            }
            WithdrawalSettlement::Spl {
                vault,
                vault_before,
                recipient_token,
                recipient_token_before,
            } => {
                let vault_after = fetch_account(&self.rpc, vault)?;
                let recipient_after = fetch_account(&self.rpc, recipient_token)?;
                let vault_delta = token_amount(vault_before)?
                    .checked_sub(token_amount(&vault_after)?)
                    .ok_or_else(|| anyhow!("vault balance rose on a withdrawal"))?;
                if vault_delta != withdrawn {
                    return Err(anyhow!("vault fell by {vault_delta}, expected {withdrawn}"));
                }
                let recipient_delta = token_amount(&recipient_after)?
                    .saturating_sub(token_amount(recipient_token_before)?);
                if recipient_delta != withdrawn {
                    return Err(anyhow!(
                        "recipient rose by {recipient_delta}, expected {withdrawn}"
                    ));
                }
            }
        }
        Ok(())
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
