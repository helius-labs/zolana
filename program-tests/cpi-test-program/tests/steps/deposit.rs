//! `deposit` (proofless shield) steps for SOL and the World operation. Shields SOL
//! to a sender actor so the program-governed transact has a spendable input.

use anyhow::{anyhow, Result};
use cucumber::{given, then};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_program_test::deposit_output_from_event;
use zolana_test_utils::test_validator_asserts::{assert_deposit, fetch_account, DepositAssertArgs};
use zolana_transaction::{Wallet, SOL_MINT};

use crate::{actor::DepositRecord, deposit_action::Deposit, CpiLifecycleWorld};

impl CpiLifecycleWorld {
    /// Deposit SOL to an actor through the client SDK's `Deposit` action. Records
    /// the returned UTXO as spendable and the deposit details for the assert step.
    /// The eddsa actor pays and signs its own deposit, so the deposited note becomes
    /// spendable over the eddsa rail.
    pub(crate) fn deposit_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_actor(name)?;
        let signer = self
            .actor(name)
            .solana_signer
            .as_ref()
            .map(|k| k.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let recipient_address = self.actor(name).keypair.shielded_address()?;
        let tree_before = fetch_account(&self.rpc, &tree)?;

        let result = Deposit {
            tree,
            recipient: &recipient_address,
            sender: signer.pubkey(),
            amount,
        }
        .execute(&self.rpc, &payer, &signer)?;

        let actor = self.actor_mut(name);
        actor.spendable.push(result.utxo);
        actor.last_deposit = Some(DepositRecord {
            signature: result.signature,
            data: result.data,
            tree_before,
        });
        Ok(())
    }

    /// Assert the most recent SOL deposit: the indexed event matches the sent data,
    /// the account movement on Solana, that Photon's root tracks the tree, and that a
    /// fresh wallet discovers the deposit by `sync`.
    pub(crate) fn assert_deposited(&self, name: &str, amount: u64) -> Result<()> {
        let actor = self.actor(name);
        let record = actor
            .last_deposit
            .clone()
            .ok_or_else(|| anyhow!("{name} has no recorded deposit"))?;
        let keypair = actor.keypair.clone();

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let groups = self
            .rpc
            .fetch_confirmed_instruction_groups(&record.signature)?;
        let events = indexed_events_from_instruction_groups(program_id, &groups.groups);
        let indexed = events
            .first()
            .ok_or_else(|| anyhow!("deposit emitted no event"))?;
        let event = deposit_output_from_event(indexed)
            .map_err(|e| anyhow!("proofless output decode failed: {e:?}"))?;

        let mut wallet = Wallet::new(keypair)?;
        assert_deposit(
            &self.rpc,
            &self.indexer,
            DepositAssertArgs {
                tree: &self.tree,
                event: &event,
                data: &record.data,
                expected_amount: amount,
                expected_asset: SOL_MINT,
                signature: record.signature,
                tree_before: &record.tree_before,
            },
            &mut wallet,
        )?;
        Ok(())
    }
}

#[given(expr = "{word} deposits {int} lamports of SOL")]
fn deposits(world: &mut CpiLifecycleWorld, name: String, amount: i64) {
    world.deposit_sol(&name, amount as u64).expect("deposit");
}

#[then(expr = "{word} holds a {int} lamport SOL UTXO")]
fn holds_utxo(world: &mut CpiLifecycleWorld, name: String, amount: i64) {
    world
        .assert_deposited(&name, amount as u64)
        .expect("assert deposited");
}
