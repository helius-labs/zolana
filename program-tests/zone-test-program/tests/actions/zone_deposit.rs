//! SOL and SPL zone deposits and their assertions.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::{
    instruction::{DepositAsset, DepositSplAccounts, ZoneAssetDeposit, ZoneDeposit},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::random_blinding;
use zolana_program_test::{test_blinding, zone_deposit_output_from_event, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::{
    spl::mint_to,
    test_validator_asserts::{
        assert_account_unchanged, assert_custom_program_error, assert_zone_deposit, fetch_account,
        token_amount, ZoneDepositAssertArgs,
    },
};
use zolana_transaction::{
    owner_utxo_hash, Data, LocalWalletAuthority, Utxo, Wallet, ZoneDepositPlaintext, SOL_MINT,
};

use crate::{
    actor::{SplZoneDepositAccounts, ZoneDepositRecord},
    localnet::send_transaction,
    ZoneHarness,
};

/// `ShieldedPoolError::InvalidZoneConfig` (the wrong-signer zone config is not the
/// canonical `zone_auth` PDA the loader requires).
const INVALID_ZONE_CONFIG: u32 = 7014;

impl ZoneHarness {
    /// Build the recipient-hidden, wallet-discoverable zone deposit data for `name`:
    /// owner = recipient owner-hash, fresh blinding, the recipient bootstrap view
    /// tag, and the public amount. No zone/program data.
    fn zone_deposit_data(
        &self,
        name: &str,
        amount: u64,
        asset: DepositAsset,
    ) -> Result<(ZoneAssetDeposit, [u8; 32])> {
        let keypair = &self.actor(name).keypair;
        let owner = keypair.owner_hash()?;
        let blinding = random_blinding();
        Ok((
            ZoneAssetDeposit {
                asset,
                view_tag: keypair.recipient_bootstrap_view_tag(),
                owner_utxo_hash: owner_utxo_hash(&owner, &blinding)?,
                amount,
                data_hash: None,
                zone_data_hash: [0u8; 32],
                encrypted: ZoneDepositPlaintext {
                    blinding,
                    utxo_data: None,
                    memo: None,
                    zone_data: Vec::new(),
                }
                .encrypt(&keypair.viewing_pubkey())?,
            },
            blinding,
        ))
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

        let (data, blinding) = self.zone_deposit_data(name, amount, DepositAsset::Sol)?;
        let tree_before = fetch_account(&self.rpc, &tree)?;

        let ix = ZoneDeposit {
            tree,
            depositor: depositor.pubkey(),
            zone_program_id: self.zone_program_id,
            deposits: vec![data.clone()],
        }
        .instruction()?;
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
            blinding,
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

    /// Zone-shield the first registered SPL asset to a fresh recipient `name`.
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

        let (data, _) = self.zone_deposit_data(
            name,
            amount,
            DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: zolana_interface::pda::spl_token_program_id(),
            }),
        )?;
        let ix = ZoneDeposit {
            tree,
            depositor: payer.pubkey(),
            zone_program_id: self.zone_program_id,
            deposits: vec![data.clone()],
        }
        .instruction()?;
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
        let event = zone_deposit_output_from_event(indexed)
            .map_err(|e| anyhow!("encrypted zone output decode failed: {e:?}"))?;

        let mut wallet = Wallet::new(keypair.shielded_address()?, self.assets.clone())?;
        let authority = LocalWalletAuthority::new(Address::default(), &keypair);
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
            &authority,
            &mut wallet,
        )?;
        if let Some(spl) = record.spl {
            assert_eq!(
                token_amount(&fetch_account(&self.rpc, &spl.vault)?),
                token_amount(&spl.vault_before) + amount,
                "zone SPL vault balance"
            );
            assert_eq!(
                token_amount(&fetch_account(&self.rpc, &spl.user_token)?),
                token_amount(&spl.user_token_before) - amount,
                "zone SPL depositor balance"
            );
        }
        Ok(())
    }

    /// Attempt a zone proofless deposit sent straight to SPP with a non-PDA signer in
    /// the zone-config slot; SPP must reject it (the zone-auth signature can only come
    /// from the zone program's `invoke_signed`).
    pub(crate) fn zone_shield_wrong_signer_rejected(&mut self) -> Result<()> {
        let tree = self.tree;
        let tree_before = fetch_account(&self.rpc, &tree)?;
        let depositor = Keypair::new();
        self.rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?;

        let mut ix = ZoneDeposit {
            tree,
            depositor: depositor.pubkey(),
            zone_program_id: self.zone_program_id,
            deposits: vec![ZoneAssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: [0u8; 32],
                owner_utxo_hash: [3u8; 32],
                amount: 1_000_000,
                data_hash: None,
                zone_data_hash: [0u8; 32],
                encrypted: ZoneDepositPlaintext {
                    blinding: test_blinding(4),
                    utxo_data: None,
                    memo: None,
                    zone_data: Vec::new(),
                }
                .encrypt(&zolana_keypair::ShieldedKeypair::new()?.viewing_pubkey())?,
            }],
        }
        .cpi_instruction()?;
        // Swap the zone config account (index 2) for a non-PDA signer.
        let meta = ix
            .accounts
            .get_mut(2)
            .ok_or_else(|| anyhow!("missing zone config account meta"))?;
        meta.pubkey = depositor.pubkey();
        match send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor]) {
            Ok(_) => Err(anyhow!("wrong-signer zone deposit unexpectedly succeeded")),
            Err(error) => {
                assert_eq!(assert_custom_program_error(&error, INVALID_ZONE_CONFIG), 0);
                assert_account_unchanged(&self.rpc, &tree, &tree_before)?;
                Ok(())
            }
        }
    }
}
