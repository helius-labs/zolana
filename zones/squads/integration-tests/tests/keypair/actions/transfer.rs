//! A transfer is a `(2, 2)` spend that keeps every lamport in the pool, one
//! output to the recipient and a change output back to the sender. The
//! backend builds both proofs and the recipient ciphertext internally.

use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_client::Rpc;
use zolana_interface::pda;
use zolana_squads_client::{
    OutputUtxo, PrivateTransactionIntent, RequestTransactRequest, TransactionType, SOL_ASSET_ID,
};
use zolana_squads_interface::{
    constants::SENDER_CIPHERTEXT_LEN, instruction::instruction_data::EncryptedUtxos,
};
use zolana_test_utils::test_validator_asserts::{fetch_account, to_address};

use crate::{
    fixture::{owner_keypair, viewing_key_account_address},
    harness::{SquadsKeypairHarness, TransferRecord},
};

/// A fresh 31-byte blinding, the form the client's decrypted UTXO carries.
fn random_blinding_31() -> [u8; 31] {
    let mut blinding = [0u8; 31];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut blinding);
    blinding
}

/// A far-future expiry so scenarios never expire against the cluster clock.
const EXPIRY: i64 = i64::MAX;

/// The backend rebuilds the real transfer ciphertexts from the recovered
/// secrets during proving, so the intent carries a placeholder.
fn empty_encrypted_utxos() -> EncryptedUtxos {
    EncryptedUtxos {
        tx_viewing_pk: [0u8; 33],
        sender_ciphertext: [0u8; SENDER_CIPHERTEXT_LEN],
        recipient_ciphertexts: Vec::new(),
    }
}

impl SquadsKeypairHarness {
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

        // The always-on crank auto-merges the two deposits into one spendable UTXO
        // of the summed amount. The transfer then spends the single merged UTXO,
        // padded with one dummy so the circuit shape stays (2, 2).
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
            blinding: random_blinding_31(),
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
