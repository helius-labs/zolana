//! Squads zone `deposit` steps for SOL and SPL driven by the smart-account vault.
//!
//! The depositor is the vault: each `deposit` instruction is wrapped in the
//! smart-account `executeTransactionSyncV2` (the vault signs the inner deposit as
//! its CPI signer), and the deposited UTXO is credited to the vault-owned
//! smart-account sender VKA. The deposit itself is proofless.
//!
//! The VKA is created at runtime (random secrets, recoverable via the auditor), so
//! the deposit reads the account's on-chain `shared_viewing_key` for the deposit
//! view tag and its `owner` / `nullifier_pubkey` for the assert. The deposit
//! blinding is plain random: the derived change blinding is masked to 31 bytes,
//! so any deposited UTXO is spendable.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_program_test::deposit_output_from_event;
use zolana_squads_client::tags::view_tag_from_shared_viewing_key;
use zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID;
use zolana_test_utils::{
    smart_account::execute_sync_ix,
    spl::{create_token_account, mint_to},
    test_validator_asserts::{
        assert_squads_deposit, fetch_account, to_address, SquadsDepositAssertArgs,
        SquadsDepositSettlement,
    },
};
use zolana_transaction::SOL_MINT;

use crate::{
    deposit_action::{random_blinding, ZoneDeposit},
    fixture::VAULT_SENDER,
    localnet::send_transaction,
    world::{DepositRecord, SettlementSnapshot, SquadsLifecycleWorld},
};

impl SquadsLifecycleWorld {
    /// The vault sender's viewing key account address (all vault-sender names share
    /// this account).
    fn vault_vka(&self) -> Address {
        self.viewing_key_account_address(VAULT_SENDER)
    }

    /// The vault VKA's deposit view tag: the X coordinate of its on-chain shared
    /// viewing key.
    fn vault_view_tag(&self) -> Result<[u8; 32]> {
        let vka = self
            .backend
            .load_viewing_key_account(self.vault_vka())
            .map_err(|e| anyhow!("load vault viewing key account: {e}"))?;
        Ok(view_tag_from_shared_viewing_key(&vka.shared_viewing_key))
    }

    /// Zone-deposit SOL to the vault sender VKA through the wrapped `deposit`.
    pub(crate) fn deposit_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        let record = self.deposit_sol_input(amount)?;
        self.deposits.insert(name.to_string(), record);
        Ok(())
    }

    /// Zone-deposit SOL and RETURN the record instead of storing it under a name.
    /// Lets a `(2, 2)` transfer fund two spendable inputs for one vault sender.
    pub(crate) fn deposit_sol_input(&mut self, amount: u64) -> Result<DepositRecord> {
        // Fund the vault so it can settle the deposit as the depositor.
        self.rpc
            .airdrop(&self.proposer_vault, amount + 1_000_000_000)?;

        let blinding = random_blinding();
        let view_tag = self.vault_view_tag()?;
        let recipient_vka = Pubkey::new_from_array(self.vault_vka().to_bytes());
        let (deposit_ix, sol_interface) = ZoneDeposit {
            depositor: self.proposer_vault,
            recipient_vka,
            zone_auth: self.zone_auth,
            tree: self.tree,
            view_tag,
            blinding,
            amount,
        }
        .sol_ix();
        let ix = execute_sync_ix(
            &self.proposer_settings,
            0,
            &self.proposer_member_pubkeys(),
            &[deposit_ix],
        );

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let sol_interface_before = self
            .rpc
            .get_account(to_address(&sol_interface))?
            .unwrap_or_default();

        let payer = self.payer.insecure_clone();
        let member = self.proposer_member.insecure_clone();
        let member_b = self.proposer_member_b.insecure_clone();
        let signature = send_transaction(
            &mut self.rpc,
            &[ix],
            &payer.pubkey(),
            &[&payer, &member, &member_b],
        )?;

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

    /// Zone-deposit the scenario's SPL asset to the vault sender VKA. A fresh
    /// vault-owned funding token account is created and minted to, then the vault
    /// settles the deposit from it.
    pub(crate) fn deposit_spl(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_spl_asset()?;
        let spl = self.spl_asset()?;
        let payer = self.payer.insecure_clone();
        let member = self.proposer_member.insecure_clone();
        let member_b = self.proposer_member_b.insecure_clone();

        // A vault-owned funding token account; the vault signs the SPL transfer as
        // its CPI signer inside the wrapped deposit.
        let vault_token = create_token_account(&self.rpc, &payer, &spl.mint, &self.proposer_vault)?;
        mint_to(&self.rpc, &payer, &spl.mint, &vault_token, amount)?;

        let asset = Address::new_from_array(spl.mint.to_bytes());
        let blinding = random_blinding();
        let view_tag = self.vault_view_tag()?;
        let recipient_vka = Pubkey::new_from_array(self.vault_vka().to_bytes());
        let (deposit_ix, vault) = ZoneDeposit {
            depositor: self.proposer_vault,
            recipient_vka,
            zone_auth: self.zone_auth,
            tree: self.tree,
            view_tag,
            blinding,
            amount,
        }
        .spl_ix(spl.mint, vault_token);
        let ix = execute_sync_ix(
            &self.proposer_settings,
            0,
            &self.proposer_member_pubkeys(),
            &[deposit_ix],
        );

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let vault_before = fetch_account(&self.rpc, &vault)?;
        let user_token_before = fetch_account(&self.rpc, &vault_token)?;

        let signature = send_transaction(
            &mut self.rpc,
            &[ix],
            &payer.pubkey(),
            &[&payer, &member, &member_b],
        )?;

        self.deposits.insert(
            name.to_string(),
            DepositRecord {
                signature,
                view_tag,
                blinding,
                asset,
                tree_before,
                settlement: SettlementSnapshot::Spl {
                    vault,
                    user_token: vault_token,
                    vault_before,
                    user_token_before,
                },
            },
        );
        Ok(())
    }

    /// Assert the recorded deposit for `name` moved real funds through SPP. The
    /// leaf reconstruction reads the VKA `owner` / `nullifier_pubkey` on-chain.
    pub(crate) fn assert_deposited(&self, name: &str, amount: u64) -> Result<()> {
        let record = self
            .deposits
            .get(name)
            .ok_or_else(|| anyhow!("{name} has no recorded deposit"))?;
        let vka = self
            .backend
            .load_viewing_key_account(self.vault_vka())
            .map_err(|e| anyhow!("load vault viewing key account: {e}"))?;

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
            &self.rpc,
            &self.indexer,
            SquadsDepositAssertArgs {
                tree: &self.tree,
                event: &event,
                view_tag: record.view_tag,
                blinding: record.blinding,
                vka_owner: vka.owner.to_bytes(),
                vka_nullifier_pubkey: vka.nullifier_pubkey,
                expected_amount: amount,
                expected_asset: record.asset,
                expected_zone_program_id: SQUADS_ZONE_PROGRAM_ID,
                signature: record.signature,
                tree_before: &record.tree_before,
                settlement,
            },
        )?;
        Ok(())
    }
}

#[when(expr = "{word} deposits {int} lamports of SOL")]
fn deposits_sol(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .deposit_sol(&name, amount as u64)
        .expect("deposit SOL");
}

#[then(expr = "{word} holds a {int} lamport SOL zone UTXO")]
fn holds_sol_zone_utxo(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .assert_deposited(&name, amount as u64)
        .expect("assert SOL deposit");
}

#[when(expr = "{word} deposits {int} tokens")]
fn deposits_tokens(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .deposit_spl(&name, amount as u64)
        .expect("deposit tokens");
}

#[then(expr = "{word} holds a {int} token zone UTXO")]
fn holds_token_zone_utxo(world: &mut SquadsLifecycleWorld, name: String, amount: i64) {
    world
        .assert_deposited(&name, amount as u64)
        .expect("assert token deposit");
}
