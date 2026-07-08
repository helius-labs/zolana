//! Squads zone transfer steps driven through the backend's P256 keypair rail.
//!
//! A transfer is a `(2, 2)` spend that keeps every lamport in the pool, routing one
//! output to a recipient and a change output back to the sender. The client funds
//! two of the sender's zone UTXOs, reads them from the backend's `getBalances`,
//! describes the recipient output, then probes / signs / finalizes through the
//! backend exactly as a withdrawal does (see `steps/withdrawal.rs`). The backend
//! builds both proofs and the recipient ciphertext internally. The assert confirms
//! the recipient's and sender's decrypted balances via `getBalances` and that no
//! funds left the pool.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use zolana_client::Rpc;
use zolana_interface::pda;
use zolana_squads_client::{
    OutputUtxo, PrivateTransactionIntent, RequestTransactRequest, TransactionType,
};
use zolana_squads_interface::{
    constants::SENDER_CIPHERTEXT_LEN, instruction::instruction_data::EncryptedUtxos,
};
use zolana_test_utils::test_validator_asserts::{fetch_account, to_address};

use crate::{
    deposit_action::random_blinding,
    fixture::{owner_keypair, viewing_key_account_address},
    world::{SquadsLifecycleWorld, TransferRecord},
};

/// A far-future expiry so scenarios never expire against the cluster clock.
const EXPIRY: i64 = i64::MAX;

/// The zone SOL asset id (mirrors `zolana_squads_client::SOL_ASSET_ID`).
const SOL_ASSET_ID: u64 = 1;

/// An empty output-ciphertext blob: the backend rebuilds the real transfer
/// ciphertexts from the recovered secrets during proving, so the intent carries a
/// placeholder.
fn empty_encrypted_utxos() -> EncryptedUtxos {
    EncryptedUtxos {
        tx_viewing_pk: [0u8; 33],
        sender_ciphertext: [0u8; SENDER_CIPHERTEXT_LEN],
        recipient_ciphertexts: Vec::new(),
    }
}

impl SquadsLifecycleWorld {
    /// Transfer `transferred` lamports of SOL from `sender` to `recipient`, funding
    /// two of the sender's zone UTXOs (`amount_a`, `amount_b`). Funds stay in the
    /// pool; the change returns to the sender.
    pub(crate) fn transfer_sol(
        &mut self,
        sender: &str,
        transferred: u64,
        recipient: &str,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        self.ensure_viewing_key_account(sender)?;
        self.ensure_viewing_key_account(recipient)?;

        // Fund two spendable deposits for the sender (on-chain side effect). The
        // always-on crank auto-merges the two into one spendable UTXO of the summed
        // amount; the P256 transfer then spends that single merged UTXO (padded with
        // one dummy so the circuit shape stays (2, 2)).
        self.deposit_sol_input(sender, amount_a)?;
        self.deposit_sol_input(sender, amount_b)?;

        let merged = self.wait_for_consolidated(sender, SOL_ASSET_ID, amount_a + amount_b)?;
        let inputs = vec![merged];

        let sol_interface = pda::sol_interface();
        let pool_before = self
            .rpc
            .get_account(to_address(&sol_interface))?
            .unwrap_or_default();

        let recipient_output = OutputUtxo {
            owner: Address::new_from_array(owner_keypair(recipient).owner_field()),
            asset_id: SOL_ASSET_ID,
            amount: transferred,
            blinding: random_blinding(),
        };
        let request = RequestTransactRequest {
            transaction_type: TransactionType::Transfer {
                recipient_viewing_key_account: Address::new_from_array(
                    viewing_key_account_address(recipient).to_bytes(),
                ),
            },
            intent: PrivateTransactionIntent {
                sender_viewing_key_account: Address::new_from_array(
                    viewing_key_account_address(sender).to_bytes(),
                ),
                inputs,
                outputs: vec![recipient_output],
                encrypted_utxos: empty_encrypted_utxos(),
                expiry: EXPIRY,
            },
            sender_owner_pubkey: Some(owner_keypair(sender).owner_pubkey_bytes()),
            sender_vault: None,
            owner_signature: None,
        };

        let ix = self.p256_transact(sender, request)?;
        self.send_backend_v0_alt(ix)?;

        self.transfers.insert(
            recipient.to_string(),
            TransferRecord {
                sender: sender.to_string(),
                transferred,
                change_amount: amount_a + amount_b - transferred,
                pool_before,
                pool_account: sol_interface,
            },
        );
        Ok(())
    }

    /// Assert the recipient of the transfer holds the routed zone UTXO: the backend
    /// (auditor) decrypts the recipient's SOL balance as `transferred`.
    pub(crate) fn assert_transfer_recipient(
        &self,
        recipient: &str,
        transferred: u64,
    ) -> Result<()> {
        let record = self
            .transfers
            .get(recipient)
            .ok_or_else(|| anyhow!("{recipient} has no recorded incoming transfer"))?;
        if record.transferred != transferred {
            return Err(anyhow!(
                "recorded transfer amount {} does not match asserted {transferred}",
                record.transferred
            ));
        }
        self.assert_backend_balance(recipient, SOL_ASSET_ID, transferred)
    }

    /// Assert the sender of the transfer holds the reconstructed change balance
    /// (via `getBalances`) and that no funds left the pool.
    pub(crate) fn assert_transfer_change(&self, sender: &str, change_amount: u64) -> Result<()> {
        let record = self
            .transfers
            .values()
            .find(|record| record.sender == sender)
            .ok_or_else(|| anyhow!("{sender} has no recorded outgoing transfer"))?;
        if record.change_amount != change_amount {
            return Err(anyhow!(
                "recorded change amount {} does not match asserted {change_amount}",
                record.change_amount
            ));
        }
        self.assert_backend_balance(sender, SOL_ASSET_ID, change_amount)?;

        // A transfer settles nothing, so the pool balance must be unchanged.
        let pool_after = fetch_account(&self.rpc, &record.pool_account)?;
        if pool_after.lamports != record.pool_before.lamports {
            return Err(anyhow!(
                "pool balance changed on a transfer: {} -> {}",
                record.pool_before.lamports,
                pool_after.lamports
            ));
        }
        Ok(())
    }
}

#[when(expr = "{word} transfers {int} lamports of SOL to {word} funded by {int} and {int}")]
fn transfers_sol(
    world: &mut SquadsLifecycleWorld,
    sender: String,
    transferred: i64,
    recipient: String,
    amount_a: i64,
    amount_b: i64,
) {
    world
        .transfer_sol(
            &sender,
            transferred as u64,
            &recipient,
            amount_a as u64,
            amount_b as u64,
        )
        .expect("transfer SOL");
}

#[then(expr = "{word} holds a {int} lamport SOL zone UTXO from the transfer")]
fn recipient_holds_transfer(world: &mut SquadsLifecycleWorld, recipient: String, amount: i64) {
    world
        .assert_transfer_recipient(&recipient, amount as u64)
        .expect("assert transfer recipient");
}

#[then(expr = "{word} holds a {int} lamport SOL change UTXO")]
fn sender_holds_change(world: &mut SquadsLifecycleWorld, sender: String, amount: i64) {
    world
        .assert_transfer_change(&sender, amount as u64)
        .expect("assert transfer change");
}
