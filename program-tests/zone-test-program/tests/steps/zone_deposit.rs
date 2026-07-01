//! `zone_proofless_shield` (zone deposit) steps for SOL and SPL, the World
//! operations, and the shared assert that dispatches on the deposit's asset. A
//! zone deposit routes through the zone-test fixture program, which CPIs into SPP
//! signing the zone's `zone_auth` PDA.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::{
    instruction::{DepositSplAccounts, ZoneDeposit, ZoneDepositIxData},
    pda, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::random_blinding;
use zolana_program_test::{deposit_output_from_event, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::{
    spl::mint_to,
    test_validator_asserts::{assert_zone_deposit, fetch_account, ZoneDepositAssertArgs},
};
use zolana_transaction::{Data, Utxo, Wallet, SOL_MINT};

use crate::{
    actor::{SplZoneDepositAccounts, ZoneDepositRecord},
    localnet::send_transaction,
    ZoneLifecycleWorld,
};

/// `ShieldedPoolError::InvalidZoneConfig` (the wrong-signer zone config is not the
/// canonical `zone_auth` PDA the loader requires).
const INVALID_ZONE_CONFIG: u32 = 7014;

impl ZoneLifecycleWorld {
    /// Build the recipient-hidden, wallet-discoverable zone deposit data for `name`:
    /// owner = recipient owner-hash, fresh blinding, the recipient bootstrap view
    /// tag, and the public amount. No zone/program data.
    fn zone_deposit_data(&self, name: &str, amount: u64) -> Result<ZoneDepositIxData> {
        let keypair = &self.actor(name).keypair;
        Ok(ZoneDepositIxData {
            view_tag: keypair.recipient_bootstrap_view_tag(),
            owner: keypair.owner_hash()?,
            blinding: random_blinding(),
            public_amount: Some(amount),
            zone_data_hash: [0u8; 32],
            zone_data: Vec::new(),
            utxo_data: None,
            memo: None,
        })
    }

    /// Zone-shield SOL to a fresh recipient `name` through the fixture program.
    /// Requires a zone config to exist (creates an enabled one if absent).
    pub(crate) fn zone_shield_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        if self.zone_config.is_none() {
            self.create_enabled_zone_config()?;
        }
        self.ensure_actor(name)?;
        let tree = self.tree;
        let depositor = Keypair::new();
        self.rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?;

        let data = self.zone_deposit_data(name, amount)?;
        let tree_before = fetch_account(&self.rpc, &tree)?;

        let ix = ZoneDeposit {
            tree,
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            zone_program_id: self.zone_program_id,
            zone_data_hash: data.zone_data_hash,
            zone_data: data.zone_data.clone(),
            utxo_data: data.utxo_data.clone(),
            memo: None,
        }
        .instruction();
        let signature = send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor])?;

        // Make the zone-owned note spendable for `name` so later zone_transact /
        // merge_zone steps can consume it (its zone_program_id is the zone the
        // ZoneConfig binds).
        let owner = self.actor(name).keypair.signing_pubkey();
        let zone = Address::new_from_array(self.zone_program_id.to_bytes());
        let utxo = Utxo {
            owner,
            asset: SOL_MINT,
            amount,
            blinding: data.blinding,
            zone_program_id: Some(zone),
            data: Data::default(),
        };
        let actor = self.actor_mut(name);
        actor.spendable.push(utxo);
        actor.last_zone_deposit = Some(ZoneDepositRecord {
            signature,
            data,
            tree_before,
            spl: None,
        });
        Ok(())
    }

    /// Zone-shield the scenario's first SPL asset to a fresh recipient `name`.
    /// Registers an SPL asset and a zone config if needed, funds the shared token
    /// account, snapshots the vault + token account, and records the SPL assert
    /// inputs.
    pub(crate) fn zone_shield_spl(&mut self, name: &str, amount: u64) -> Result<()> {
        if self.zone_config.is_none() {
            self.create_enabled_zone_config()?;
        }
        self.ensure_spl_asset()?;
        self.ensure_actor(name)?;
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let spl = *self.spl_asset()?;
        let (mint, vault, user_token) = (spl.mint, spl.vault, spl.user_token);

        // Fund the shared token account, then snapshot it and the vault right before
        // the deposit so the assert sees exactly the deposit's movement.
        mint_to(&self.rpc, &payer, &mint, &user_token, amount)?;
        let tree_before = fetch_account(&self.rpc, &tree)?;
        let vault_before = fetch_account(&self.rpc, &vault)?;
        let user_token_before = fetch_account(&self.rpc, &user_token)?;

        let data = self.zone_deposit_data(name, amount)?;
        let ix = ZoneDeposit {
            tree,
            depositor: payer.pubkey(),
            spl: Some(DepositSplAccounts {
                user_token,
                vault,
                registry: pda::spl_asset_registry(&mint),
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            }),
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            zone_program_id: self.zone_program_id,
            zone_data_hash: data.zone_data_hash,
            zone_data: data.zone_data.clone(),
            utxo_data: data.utxo_data.clone(),
            memo: None,
        }
        .instruction();
        let signature = send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer])?;

        self.actor_mut(name).last_zone_deposit = Some(ZoneDepositRecord {
            signature,
            data,
            tree_before,
            spl: Some(SplZoneDepositAccounts {
                mint,
                vault,
                user_token,
                vault_before,
                user_token_before,
            }),
        });
        Ok(())
    }

    /// Assert the most recent zone deposit (SOL or SPL): the indexed event matches
    /// the sent data, the leaf was appended, Photon's root tracks the tree, and a
    /// fresh recipient wallet discovers the zone-owned UTXO.
    pub(crate) fn assert_zone_deposited(&self, name: &str, amount: u64) -> Result<()> {
        let actor = self.actor(name);
        let record = actor
            .last_zone_deposit
            .clone()
            .ok_or_else(|| anyhow!("{name} has no recorded zone deposit"))?;
        let keypair = actor.keypair.clone();

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let groups = self
            .rpc
            .fetch_confirmed_instruction_groups(&record.signature)?;
        let events = indexed_events_from_instruction_groups(program_id, &groups.groups);
        let indexed = events
            .first()
            .ok_or_else(|| anyhow!("zone deposit emitted no event"))?;
        let event = deposit_output_from_event(indexed)
            .map_err(|e| anyhow!("proofless output decode failed: {e:?}"))?;

        let mut wallet = Wallet::new(keypair)?;
        let expected_asset = match &record.spl {
            None => SOL_MINT,
            Some(spl) => Address::new_from_array(spl.mint.to_bytes()),
        };
        assert_zone_deposit(
            &self.rpc,
            &self.indexer,
            ZoneDepositAssertArgs {
                tree: &self.tree,
                event: &event,
                data: &record.data,
                expected_amount: amount,
                expected_asset,
                expected_zone_program_id: ZONE_TEST_PROGRAM_ID,
                signature: record.signature,
                tree_before: &record.tree_before,
            },
            &mut wallet,
        )?;
        Ok(())
    }

    /// Attempt a zone proofless deposit sent straight to SPP with a non-PDA signer in
    /// the zone-config slot; SPP must reject it (the zone-auth signature can only come
    /// from the zone program's `invoke_signed`).
    fn zone_shield_wrong_signer_rejected(&mut self) -> Result<()> {
        let tree = self.tree;
        let depositor = Keypair::new();
        self.rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?;

        let mut ix = ZoneDeposit {
            tree,
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: [0u8; 32],
            owner: [3u8; 32],
            blinding: [4u8; 31],
            public_amount: Some(1_000_000),
            zone_program_id: self.zone_program_id,
            zone_data_hash: [0u8; 32],
            zone_data: Vec::new(),
            utxo_data: None,
            memo: None,
        }
        .cpi_instruction();
        // Swap the zone config account (index 2) for a non-PDA signer.
        let meta = ix
            .accounts
            .get_mut(2)
            .ok_or_else(|| anyhow!("missing zone config account meta"))?;
        meta.pubkey = depositor.pubkey();
        match send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor]) {
            Ok(_) => Err(anyhow!("wrong-signer zone deposit unexpectedly succeeded")),
            Err(error) => {
                assert_rpc_custom_error(&error, INVALID_ZONE_CONFIG);
                Ok(())
            }
        }
    }
}

/// Assert a transaction failed with the given custom program error, by code or its
/// hex form, as the validator surfaces it.
#[track_caller]
fn assert_rpc_custom_error(error: &anyhow::Error, code: u32) {
    let message = error.to_string().to_lowercase();
    let hex = format!("0x{code:x}");
    assert!(
        message.contains(&code.to_string()) || message.contains(&hex),
        "expected custom program error {code} ({hex}), got: {message}"
    );
}

#[when(expr = "{word} zone-shields {int} lamports of SOL")]
fn zone_shields_sol(world: &mut ZoneLifecycleWorld, name: String, amount: i64) {
    world
        .zone_shield_sol(&name, amount as u64)
        .expect("zone shield SOL");
}

#[then(expr = "{word} holds a {int} lamport SOL zone UTXO")]
fn holds_sol_zone_utxo(world: &mut ZoneLifecycleWorld, name: String, amount: i64) {
    world
        .assert_zone_deposited(&name, amount as u64)
        .expect("assert zone deposited");
}

#[when(expr = "{word} zone-shields {int} tokens")]
fn zone_shields_spl(world: &mut ZoneLifecycleWorld, name: String, amount: i64) {
    world
        .zone_shield_spl(&name, amount as u64)
        .expect("zone shield SPL");
}

#[then(expr = "{word} holds a {int} token zone UTXO")]
fn holds_token_zone_utxo(world: &mut ZoneLifecycleWorld, name: String, amount: i64) {
    world
        .assert_zone_deposited(&name, amount as u64)
        .expect("assert zone token deposited");
}

#[then(expr = "a zone proofless deposit with the wrong signer is rejected")]
fn wrong_signer_rejected(world: &mut ZoneLifecycleWorld) {
    world
        .zone_shield_wrong_signer_rejected()
        .expect("wrong-signer zone deposit rejected");
}
