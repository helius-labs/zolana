//! Squads ring transfers on the Ed25519 keypair rail. The sender funds two
//! deposits, the crank merges them, and the transfer spends the merged UTXO
//! (padded to the `(2, 2)` shape by the backend) into a recipient output and
//! the sender's change. Nothing leaves the pool.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use squads_ring_tests::localnet::SOL_ASSET_ID;
use zolana_interface::pda;
use zolana_squads_client::{
    OutputUtxo, PrivateTransactionIntent, RequestTransactRequest, TransactionType,
};
use zolana_test_utils::test_validator_asserts::fetch_account;

use crate::{
    fixture::{owner_keypair, viewing_key_account_address},
    steps::withdrawal::EXPIRY,
    world::{SquadsLifecycleWorld, TransferRecord},
};

impl SquadsLifecycleWorld {
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
        self.deposit_sol_input(sender, amount_a)?;
        self.deposit_sol_input(sender, amount_b)?;
        let funded = amount_a + amount_b;
        let merged = self.net.wait_for_consolidated(
            viewing_key_account_address(sender),
            SOL_ASSET_ID,
            funded,
        )?;
        let change_amount = funded
            .checked_sub(transferred)
            .ok_or_else(|| anyhow!("transfer of {transferred} exceeds the funded {funded}"))?;

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
                inputs: vec![merged],
                outputs: vec![OutputUtxo {
                    owner: Address::new_from_array(owner_keypair(recipient).owner_identity()),
                    asset_id: SOL_ASSET_ID,
                    amount: transferred,
                }],
                expiry: EXPIRY,
            },
            sender_owner_pubkey: Some(owner_keypair(sender).owner_pubkey_bytes()),
            owner_signature: None,
        };
        let ix = self.ed25519_transact(sender, request)?;

        let pool_account = pda::sol_interface();
        let pool_before = fetch_account(&self.net.base.rpc, &pool_account)?;
        self.net.send_backend_instruction(ix)?;
        self.transfers.insert(
            recipient.to_string(),
            TransferRecord {
                sender: sender.to_string(),
                transferred,
                change_amount,
                pool_before,
                pool_account,
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
                "recorded transfer of {} does not match asserted {transferred}",
                record.transferred
            ));
        }
        self.net.wait_for_consolidated(
            viewing_key_account_address(recipient),
            SOL_ASSET_ID,
            transferred,
        )?;
        Ok(())
    }

    pub(crate) fn assert_transfer_change(&self, sender: &str, change_amount: u64) -> Result<()> {
        let record = self
            .transfers
            .values()
            .find(|record| record.sender == sender)
            .ok_or_else(|| anyhow!("{sender} has no recorded outgoing transfer"))?;
        if record.change_amount != change_amount {
            return Err(anyhow!(
                "recorded change of {} does not match asserted {change_amount}",
                record.change_amount
            ));
        }
        self.net.wait_for_consolidated(
            viewing_key_account_address(sender),
            SOL_ASSET_ID,
            change_amount,
        )?;
        let pool_after = fetch_account(&self.net.base.rpc, &record.pool_account)?;
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
    transferred: u64,
    recipient: String,
    amount_a: u64,
    amount_b: u64,
) {
    world
        .transfer_sol(&sender, transferred, &recipient, amount_a, amount_b)
        .expect("transfer SOL");
}

#[then(expr = "{word} holds a {int} lamport SOL ring UTXO from the transfer")]
fn recipient_holds_transfer(world: &mut SquadsLifecycleWorld, recipient: String, amount: u64) {
    world
        .assert_transfer_recipient(&recipient, amount)
        .expect("assert transfer recipient");
}

#[then(expr = "{word} holds a {int} lamport SOL change UTXO")]
fn sender_holds_change(world: &mut SquadsLifecycleWorld, sender: String, amount: u64) {
    world
        .assert_transfer_change(&sender, amount)
        .expect("assert transfer change");
}
