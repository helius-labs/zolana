//! The recipient viewing key account is created at runtime by the backend,
//! so the deposit `view_tag` and `nullifier_pubkey` are read from on-chain
//! VKA data rather than a fixture. The deposit is proofless and client-built
//! with a plain random blinding. The derived change blinding is masked to
//! 31 bytes, so any deposited UTXO stays spendable.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_event::indexed_events_from_instruction_groups;
use zolana_interface::instruction::DepositAssetKind;
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_program_test::deposit_output_from_event;
use zolana_squads_interface::{
    state::viewing_key_account::ViewingKeyAccount, SQUADS_ZONE_PROGRAM_ID,
};
use zolana_test_utils::{
    spl::mint_to,
    test_validator_asserts::{
        assert_squads_deposit, fetch_account, to_address, SquadsDepositAssertArgs,
        SquadsDepositSettlement,
    },
};
use zolana_transaction::SOL_MINT;

use crate::{
    deposit_action::{random_blinding, ZoneDeposit},
    fixture::{owner_keypair, viewing_key_account_address},
    harness::{DepositRecord, SettlementSnapshot, SquadsKeypairHarness},
    localnet::send_transaction,
};

impl SquadsKeypairHarness {
    fn load_viewing_key_account(&self, name: &str) -> Result<ViewingKeyAccount> {
        let address = viewing_key_account_address(name);
        let account = self
            .rpc
            .get_account(to_address(&address))?
            .ok_or_else(|| anyhow!("viewing key account missing for {name}"))?;
        ViewingKeyAccount::deserialize(&account.data)
            .map_err(|e| anyhow!("decode viewing key account for {name}: {e}"))
    }

    /// The deposit `view_tag` is the shared viewing key X coordinate
    /// (SEC1-compressed bytes `[1..33]`).
    fn view_tag(&self, name: &str) -> Result<[u8; 32]> {
        let account = self.load_viewing_key_account(name)?;
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&account.shared_viewing_key[1..33]);
        Ok(tag)
    }

    pub(crate) fn deposit_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        let record = self.deposit_sol_input(name, amount)?;
        self.deposits.insert(name.to_string(), record);
        Ok(())
    }

    /// Returns the record instead of storing it under `name`, so a `(2, 2)`
    /// transfer can fund two spendable inputs for one sender. The by-name
    /// `deposits` map holds one record per name.
    pub(crate) fn deposit_sol_input(&mut self, name: &str, amount: u64) -> Result<DepositRecord> {
        self.ensure_viewing_key_account(name)?;
        let recipient_vka = viewing_key_account_address(name);
        let depositor = Keypair::new();
        self.rpc
            .airdrop(&depositor.pubkey(), amount + 1_000_000_000)?;

        let blinding = random_blinding();
        let view_tag = self.view_tag(name)?;
        let (ix, sol_interface) = ZoneDeposit {
            asset: DepositAssetKind::Sol,
            depositor: depositor.pubkey(),
            recipient_vka,
            ring_auth: self.ring_auth,
            tree: self.tree,
            view_tag,
            blinding,
            amount,
        }
        .sol_ix();

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let sol_interface_before = self
            .rpc
            .get_account(to_address(&sol_interface))?
            .unwrap_or_default();

        let signature = send_transaction(&mut self.rpc, &[ix], &depositor.pubkey(), &[&depositor])?;

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

    /// The payer owns the shared funding token account, so it signs and funds.
    pub(crate) fn deposit_spl(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_spl_asset()?;
        self.ensure_viewing_key_account(name)?;
        let recipient_vka = viewing_key_account_address(name);
        let spl = self.spl_asset()?;
        let payer = self.payer.insecure_clone();

        mint_to(&self.rpc, &payer, &spl.mint, &spl.user_token, amount)?;

        let asset = Address::new_from_array(spl.mint.to_bytes());
        let blinding = random_blinding();
        let view_tag = self.view_tag(name)?;
        let (ix, vault) = ZoneDeposit {
            asset: DepositAssetKind::Spl {
                spl_interface_bump: zolana_interface::pda::spl_interface_bump(&spl.mint.to_bytes()),
            },
            depositor: payer.pubkey(),
            recipient_vka,
            ring_auth: self.ring_auth,
            tree: self.tree,
            view_tag,
            blinding,
            amount,
        }
        .spl_ix(spl.mint, spl.user_token);

        let tree_before = fetch_account(&self.rpc, &self.tree)?;
        let vault_before = fetch_account(&self.rpc, &vault)?;
        let user_token_before = fetch_account(&self.rpc, &spl.user_token)?;

        let signature = send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer])?;

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
                    user_token: spl.user_token,
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
        let account = self.load_viewing_key_account(name)?;
        let owner_field = owner_keypair(name).owner_field();
        if account.owner.to_bytes() != owner_field {
            return Err(anyhow!("on-chain VKA owner does not match {name}'s owner"));
        }

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
                vka_owner: owner_field,
                vka_nullifier_pubkey: account.nullifier_pubkey,
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
