//! SOL and SPL ring deposits and their assertions.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        AssetDeposit, Deposit, DepositAsset, DepositSplAccounts, EncryptedRingDepositData,
        RingAssetDeposit, RingDeposit,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::random_blinding;
use zolana_program_test::{
    test_blinding, ring_deposit_output_from_event, Rejection, RING_TEST_PROGRAM_ID,
};
use zolana_transaction::{
    owner_utxo_hash, serialization::RingDepositPlaintext, Data, LocalWalletAuthority, Utxo, Wallet,
    SOL_MINT,
};

use super::{SplRingDepositAccounts, RingDepositRecord, RingHarness};
use crate::{
    localnet::send_transaction,
    spl::mint_to,
    test_validator_asserts::{
        assert_account_unchanged, assert_ring_deposit, fetch_account, token_amount,
        RingDepositAssertArgs,
    },
};

impl RingHarness {
    /// Build the recipient-visible, wallet-discoverable plain deposit data for
    /// `name`: owner = recipient owner-hash, fresh blinding, the recipient
    /// bootstrap view tag, and the public amount. No ring/program data.
    fn asset_deposit_data(
        &self,
        name: &str,
        amount: u64,
        asset: DepositAsset,
    ) -> Result<AssetDeposit> {
        let keypair = &self.actor(name).keypair;
        Ok(AssetDeposit {
            asset,
            view_tag: keypair.recipient_bootstrap_view_tag(),
            owner: keypair.owner_hash()?,
            blinding: random_blinding(),
            amount,
            utxo_data: None,
            memo: None,
        })
    }

    /// Build the owner-hidden, wallet-discoverable ring deposit data for `name`:
    /// the public face carries only the `owner_utxo_hash` commitment and the
    /// recipient bootstrap view tag; the blinding and preimages travel in the
    /// encrypted envelope. Returns the blinding so the caller can record the
    /// created UTXO as spendable.
    fn ring_deposit_data(
        &self,
        name: &str,
        amount: u64,
        asset: DepositAsset,
    ) -> Result<(RingAssetDeposit, [u8; 32])> {
        let keypair = &self.actor(name).keypair;
        let owner = keypair.owner_hash()?;
        let blinding = random_blinding();
        let data = RingAssetDeposit {
            asset,
            view_tag: keypair.recipient_bootstrap_view_tag(),
            owner_utxo_hash: owner_utxo_hash(&owner, &blinding)?,
            amount,
            data_hash: None,
            ring_data_hash: [0u8; 32],
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&keypair.viewing_pubkey())?,
        };
        Ok((data, blinding))
    }

    pub fn shield_default_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_fresh_actor(name)?;
        let depositor = Keypair::new();
        self.rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?;
        let data = self.asset_deposit_data(name, amount, DepositAsset::Sol)?;
        let ix = Deposit {
            tree: self.tree,
            depositor: depositor.pubkey(),
            deposits: vec![data.clone()],
        }
        .instruction()
        .expect("deposit instruction");
        send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor])?;
        let owner = self.actor(name).keypair.signing_pubkey();
        self.actor_mut(name).spendable.push(Utxo {
            owner,
            asset: SOL_MINT,
            amount,
            blinding: data.blinding,
            ring_program_id: None,
            data: Data::default(),
        });
        Ok(())
    }

    /// Ring-shield SOL to a fresh recipient `name` through the fixture program.
    /// Requires a ring config to exist (creates an enabled one if absent).
    pub fn ring_shield_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_fresh_actor(name)?;
        let tree = self.tree;
        let depositor = Keypair::new();
        self.rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?;

        let (data, blinding) = self.ring_deposit_data(name, amount, DepositAsset::Sol)?;
        let tree_before = fetch_account(&self.rpc, &tree)?;

        let ix = RingDeposit {
            tree,
            depositor: depositor.pubkey(),
            ring_program_id: self.ring_program_id,
            deposits: vec![data.clone()],
        }
        .instruction()?;
        let signature = send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor])?;

        // Make the ring-owned UTXO spendable for `name` so later ring_transact /
        // merge_ring operations can consume it (its ring_program_id is the ring the
        // RingConfig binds).
        let owner = self.actor(name).keypair.signing_pubkey();
        let ring = Address::new_from_array(self.ring_program_id.to_bytes());
        let utxo = Utxo {
            owner,
            asset: SOL_MINT,
            amount,
            blinding,
            ring_program_id: Some(ring),
            data: Data::default(),
        };
        let actor = self.actor_mut(name);
        actor.spendable.push(utxo);
        actor.last_deposit = Some(RingDepositRecord {
            signature,
            data,
            tree_before,
            spl: None,
        });
        Ok(())
    }

    /// Ring-shield the first registered SPL asset to a fresh recipient `name`.
    /// Registers an SPL asset and a ring config if needed, funds the shared token
    /// account, snapshots the vault + token account, and records the SPL assert
    /// inputs.
    pub fn ring_shield_spl(&mut self, name: &str, amount: u64) -> Result<()> {
        if self.ring_config.is_none() {
            self.create_enabled_ring_config()?;
        }
        self.ensure_spl_asset()?;
        self.ensure_fresh_actor(name)?;
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

        let (data, _blinding) = self.ring_deposit_data(
            name,
            amount,
            DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: zolana_interface::pda::spl_token_program_id(),
            }),
        )?;
        let ix = RingDeposit {
            tree,
            depositor: payer.pubkey(),
            ring_program_id: self.ring_program_id,
            deposits: vec![data.clone()],
        }
        .instruction()?;
        let signature = send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer])?;

        self.actor_mut(name).last_deposit = Some(RingDepositRecord {
            signature,
            data,
            tree_before,
            spl: Some(SplRingDepositAccounts {
                mint,
                vault,
                user_token,
                vault_before,
                user_token_before,
            }),
        });
        Ok(())
    }

    /// Assert the most recent ring deposit (SOL or SPL): the indexed event matches
    /// the sent data, the leaf was appended, Photon's root tracks the tree, and a
    /// fresh recipient wallet discovers the ring-owned UTXO.
    pub fn assert_ring_deposited(&self, name: &str, amount: u64) -> Result<()> {
        let actor = self.actor(name);
        let record = actor
            .last_deposit
            .clone()
            .ok_or_else(|| anyhow!("{name} has no recorded ring deposit"))?;
        let keypair = actor.keypair.clone();

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let groups = self
            .rpc
            .fetch_confirmed_instruction_groups(&record.signature)?;
        let events = indexed_events_from_instruction_groups(program_id, &groups.groups);
        let indexed = events
            .first()
            .ok_or_else(|| anyhow!("ring deposit emitted no event"))?;
        let event = ring_deposit_output_from_event(indexed)
            .map_err(|e| anyhow!("encrypted ring deposit output decode failed: {e:?}"))?;

        let mut wallet = Wallet::new(keypair.shielded_address()?, self.assets.clone())?;
        let authority = LocalWalletAuthority::new(Address::default(), &keypair);
        let expected_asset = match &record.spl {
            None => SOL_MINT,
            Some(spl) => Address::new_from_array(spl.mint.to_bytes()),
        };
        assert_ring_deposit(
            &self.rpc,
            &self.indexer,
            RingDepositAssertArgs {
                tree: &self.tree,
                event: &event,
                data: &record.data,
                expected_amount: amount,
                expected_asset,
                expected_ring_program_id: RING_TEST_PROGRAM_ID,
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
                "ring SPL vault balance"
            );
            assert_eq!(
                token_amount(&fetch_account(&self.rpc, &spl.user_token)?),
                token_amount(&spl.user_token_before) - amount,
                "ring SPL depositor balance"
            );
        }
        Ok(())
    }

    /// Attempt a ring proofless deposit sent straight to SPP with a non-PDA signer in
    /// the ring-config slot; SPP must reject it (the ring-auth signature can only come
    /// from the ring program's `invoke_signed`).
    pub fn ring_shield_wrong_signer_rejected(&mut self) -> Result<()> {
        let tree = self.tree;
        let tree_before = fetch_account(&self.rpc, &tree)?;
        let depositor = Keypair::new();
        self.rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?;

        let mut ix = RingDeposit {
            tree,
            depositor: depositor.pubkey(),
            ring_program_id: self.ring_program_id,
            deposits: vec![RingAssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: [0u8; 32],
                owner_utxo_hash: owner_utxo_hash(&[3u8; 32], &test_blinding(4))?,
                amount: 1_000_000,
                data_hash: None,
                ring_data_hash: [0u8; 32],
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: [0u8; 33],
                    salt: [0u8; 16],
                    ciphertext: Vec::new(),
                },
            }],
        }
        .cpi_instruction()?;
        // Swap the ring config account (index 2) for a non-PDA signer.
        let meta = ix
            .accounts
            .get_mut(2)
            .ok_or_else(|| anyhow!("missing ring config account meta"))?;
        meta.pubkey = depositor.pubkey();
        match send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor]) {
            Ok(_) => Err(anyhow!("wrong-signer ring deposit unexpectedly succeeded")),
            Err(error) => {
                Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_client(&error);
                assert_account_unchanged(&self.rpc, &tree, &tree_before)?;
                Ok(())
            }
        }
    }
}
