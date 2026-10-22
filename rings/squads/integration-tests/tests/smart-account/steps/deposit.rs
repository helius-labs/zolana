//! Squads ring `deposit` steps executed by the proposer vault through
//! `executeTransactionSyncV2`, crediting the vault's viewing key account.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_pubkey::Pubkey;
use squads_ring_tests::asserts::{
    assert_squads_deposit, SquadsDepositAssertArgs, SquadsDepositSettlement,
};
use zolana_event_parser::indexed_events_from_instruction_groups;
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::random_blinding;
use zolana_program::instruction::{DepositAsset, DepositSplAccounts};
use zolana_program_test::ring_deposit_output_from_event;
use zolana_squads_client::tags::account_view_tag;
use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;
use zolana_test_utils::{
    smart_account::execute_sync_ix,
    spl::{create_token_account, mint_to},
    test_validator_asserts::{fetch_account, fetch_optional_account},
};
use zolana_transaction::{Address, SOL_MINT};

use crate::{
    fixture::{viewing_key_account_address, VAULT_SENDER},
    world::{DepositRecord, SettlementSnapshot, SquadsLifecycleWorld},
};

impl SquadsLifecycleWorld {
    fn vault_view_tag(&self) -> Result<[u8; 32]> {
        Ok(account_view_tag(
            &self.load_viewing_key_account(VAULT_SENDER)?,
        ))
    }

    fn execute_as_vault(
        &self,
        ix: solana_instruction::Instruction,
    ) -> solana_instruction::Instruction {
        execute_sync_ix(
            &self.proposer_settings,
            0,
            &self.proposer_member_pubkeys(),
            &[ix],
        )
    }

    pub(crate) fn deposit_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        let record = self.deposit_sol_input(amount)?;
        self.deposits.insert(name.to_string(), record);
        Ok(())
    }

    pub(crate) fn deposit_sol_input(&mut self, amount: u64) -> Result<DepositRecord> {
        self.ensure_viewing_key_account(VAULT_SENDER)?;
        self.net
            .base
            .rpc
            .airdrop(&self.proposer_vault, amount + 1_000_000_000)?;
        let blinding = random_blinding();
        let view_tag = self.vault_view_tag()?;
        let deposit = self.net.deposit_instruction(
            self.proposer_vault,
            viewing_key_account_address(VAULT_SENDER),
            view_tag,
            blinding,
            amount,
            DepositAsset::Sol,
        )?;
        let ix = self.execute_as_vault(deposit);

        let sol_interface = pda::sol_interface();
        let tree_before = fetch_account(&self.net.base.rpc, &self.net.base.tree)?;
        let sol_interface_before =
            fetch_optional_account(&self.net.base.rpc, &sol_interface)?.unwrap_or_default();
        let signature = self.send_as_proposer(&[ix])?;
        Ok(DepositRecord {
            signature,
            view_tag,
            blinding,
            asset: SOL_MINT,
            tree_before,
            settlement: SettlementSnapshot::Sol {
                sol_interface,
                sol_interface_before,
            },
        })
    }

    pub(crate) fn deposit_spl(&mut self, name: &str, amount: u64) -> Result<()> {
        let spl = self.net.ensure_spl_asset()?;
        self.ensure_viewing_key_account(VAULT_SENDER)?;
        let payer = self.net.payer();
        let vault_token =
            create_token_account(&self.net.base.rpc, &payer, &spl.mint, &self.proposer_vault)?;
        mint_to(&self.net.base.rpc, &payer, &spl.mint, &vault_token, amount)?;

        let blinding = random_blinding();
        let view_tag = self.vault_view_tag()?;
        let deposit = self.net.deposit_instruction(
            self.proposer_vault,
            viewing_key_account_address(VAULT_SENDER),
            view_tag,
            blinding,
            amount,
            DepositAsset::Spl(DepositSplAccounts {
                mint: spl.mint,
                user_token: vault_token,
                token_program: pda::spl_token_program_id(),
            }),
        )?;
        let ix = self.execute_as_vault(deposit);

        let tree_before = fetch_account(&self.net.base.rpc, &self.net.base.tree)?;
        let vault_before = fetch_account(&self.net.base.rpc, &spl.vault)?;
        let user_token_before = fetch_account(&self.net.base.rpc, &vault_token)?;
        let signature = self.send_as_proposer(&[ix])?;
        self.deposits.insert(
            name.to_string(),
            DepositRecord {
                signature,
                view_tag,
                blinding,
                asset: Address::new_from_array(spl.mint.to_bytes()),
                tree_before,
                settlement: SettlementSnapshot::Spl {
                    vault: spl.vault,
                    user_token: vault_token,
                    vault_before,
                    user_token_before,
                },
            },
        );
        Ok(())
    }

    pub(crate) fn assert_deposited(&self, name: &str, amount: u64) -> Result<()> {
        let record = self
            .deposits
            .get(name)
            .ok_or_else(|| anyhow!("{name} has no recorded deposit"))?;
        let account = self.load_viewing_key_account(VAULT_SENDER)?;

        let groups = self
            .net
            .base
            .rpc
            .fetch_confirmed_instruction_groups(&record.signature)?;
        let events = indexed_events_from_instruction_groups(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            &groups.groups,
        );
        let [indexed] = events.as_slice() else {
            return Err(anyhow!(
                "deposit emitted {} events, expected one",
                events.len()
            ));
        };
        let event = ring_deposit_output_from_event(indexed)
            .map_err(|e| anyhow!("decode ring deposit output: {e:?}"))?;

        let settlement = match &record.settlement {
            SettlementSnapshot::Sol {
                sol_interface,
                sol_interface_before,
            } => SquadsDepositSettlement::Sol {
                sol_interface,
                sol_interface_before,
            },
            SettlementSnapshot::Spl {
                vault,
                user_token,
                vault_before,
                user_token_before,
            } => SquadsDepositSettlement::Spl {
                vault,
                user_token,
                vault_before,
                user_token_before,
            },
        };
        assert_squads_deposit(
            &self.net.base.rpc,
            &self.net.base.indexer,
            SquadsDepositAssertArgs {
                tree: &self.net.base.tree,
                event: &event,
                view_tag: record.view_tag,
                blinding: record.blinding,
                vka_owner: account.owner.to_bytes(),
                vka_nullifier_pubkey: account.nullifier_pubkey,
                expected_amount: amount,
                expected_asset: record.asset,
                expected_ring_program_id: SQUADS_RING_PROGRAM_ID,
                signature: record.signature,
                tree_before: &record.tree_before,
                settlement,
            },
        )?;
        Ok(())
    }
}

#[when(expr = "{word} deposits {int} lamports of SOL")]
fn deposits_sol(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world.deposit_sol(&name, amount).expect("deposit SOL");
}

#[then(expr = "{word} holds a {int} lamport SOL ring UTXO")]
fn holds_sol_ring_utxo(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .assert_deposited(&name, amount)
        .expect("assert SOL deposit");
}

#[when(expr = "{word} deposits {int} tokens")]
fn deposits_tokens(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world.deposit_spl(&name, amount).expect("deposit tokens");
}

#[then(expr = "{word} holds a {int} token ring UTXO")]
fn holds_token_ring_utxo(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .assert_deposited(&name, amount)
        .expect("assert token deposit");
}
