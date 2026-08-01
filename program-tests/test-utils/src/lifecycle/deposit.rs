//! `deposit` (proofless shield) operations for SOL and SPL, and
//! the shared assert that dispatches on the deposit's asset.

use anyhow::{anyhow, Result};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_program_test::deposit_output_from_event;
use zolana_transaction::{Address, LocalWalletAuthority, Wallet, SOL_MINT};

use super::{Deposit, DepositRecord, LifecycleHarness, SplDepositAccounts};
use crate::{
    spl::mint_to,
    test_validator_asserts::{
        assert_deposit, assert_spl_deposit, fetch_account, DepositAssertArgs, SplDepositAssertArgs,
    },
};

impl LifecycleHarness {
    /// Deposit SOL to an actor through the client SDK's `Deposit` action. Records
    /// the returned UTXO as spendable and the deposit details for the assert helper.
    pub fn deposit_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_fresh_actor(name)?;
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let recipient_address = self.actor(name).keypair.shielded_address()?;
        let tree_before = fetch_account(&self.rpc, &tree)?;

        let result = Deposit {
            tree,
            recipient: &recipient_address,
            sender: payer.pubkey(),
            amount,
        }
        .execute(&self.rpc, &payer, &payer)?;

        let actor = self.actor_mut(name);
        actor.spendable.push(result.utxo);
        actor.last_deposit = Some(DepositRecord {
            signature: result.signature,
            data: result.data,
            tree_before,
            spl: None,
        });
        Ok(())
    }

    /// Deposit the first registered SPL asset to an actor.
    pub fn deposit_spl(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_spl_asset()?;
        self.deposit_spl_at(name, 0, amount)
    }

    /// Deposit the registered SPL asset at `asset_index` to an actor. Funds the shared
    /// token account, snapshots the vault + token account, deposits via the action
    /// (which detects SPL from the token-account `sender`), and records the SPL assert
    /// inputs. The asset must already be registered (see `ensure_spl_assets`).
    pub fn deposit_spl_at(&mut self, name: &str, asset_index: usize, amount: u64) -> Result<()> {
        self.ensure_fresh_actor(name)?;
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let recipient_address = self.actor(name).keypair.shielded_address()?;
        let spl = *self
            .spls
            .get(asset_index)
            .ok_or_else(|| anyhow!("SPL asset {asset_index} not registered"))?;
        let (mint, vault, user_token) = (spl.mint, spl.vault, spl.user_token);

        // Fund the shared token account, then snapshot it and the vault right before
        // the deposit so the assert sees exactly the deposit's movement.
        mint_to(&self.rpc, &payer, &mint, &user_token, amount)?;
        let tree_before = fetch_account(&self.rpc, &tree)?;
        let vault_before = fetch_account(&self.rpc, &vault)?;
        let user_token_before = fetch_account(&self.rpc, &user_token)?;

        let result = Deposit {
            tree,
            recipient: &recipient_address,
            sender: user_token,
            amount,
        }
        .execute(&self.rpc, &payer, &payer)?;

        let actor = self.actor_mut(name);
        actor.spendable.push(result.utxo);
        actor.last_deposit = Some(DepositRecord {
            signature: result.signature,
            data: result.data,
            tree_before,
            spl: Some(SplDepositAccounts {
                mint,
                vault,
                user_token,
                vault_before,
                user_token_before,
            }),
        });
        Ok(())
    }

    /// Assert the most recent deposit via the shared assert (SOL or SPL): it checks
    /// the indexed event against the sent data, the account movement on Solana, that
    /// Photon's root tracks the tree, and that a fresh wallet discovers the deposit
    /// by `sync`.
    pub fn assert_deposited(&self, name: &str, amount: u64) -> Result<()> {
        let actor = self.actor(name);
        let record = actor
            .last_deposit
            .clone()
            .ok_or_else(|| anyhow!("{name} has no recorded deposit"))?;
        let keypair = actor.keypair.clone();

        // Decode the deposit transaction into the proofless deposit the program recorded.
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

        let mut wallet = Wallet::new(keypair.shielded_address()?, self.assets.clone())?;
        let authority = LocalWalletAuthority::new(Address::default(), &keypair);
        match &record.spl {
            None => assert_deposit(
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
                &authority,
                &mut wallet,
            )?,
            Some(spl) => assert_spl_deposit(
                &self.rpc,
                &self.indexer,
                SplDepositAssertArgs {
                    tree: &self.tree,
                    mint: &spl.mint,
                    vault: &spl.vault,
                    user_token: &spl.user_token,
                    event: &event,
                    data: &record.data,
                    expected_amount: amount,
                    signature: record.signature,
                    tree_before: &record.tree_before,
                    vault_before: &spl.vault_before,
                    user_token_before: &spl.user_token_before,
                },
                &authority,
                &mut wallet,
            )?,
        }
        Ok(())
    }
}
