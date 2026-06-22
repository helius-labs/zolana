//! Randomized mixed-asset workload: a long, internally consistent run that drives
//! deposits, withdrawals, and shielded transfers (SOL-only, SPL-only, single-input,
//! SOL+SPL mixed, and change-only consolidations) across many eddsa actors and
//! several SPL assets. Every actor is its own eddsa identity (it pays and signs its
//! own spends), so this exercises multiple distinct senders and recipients.
//!
//! Verification is maximal: each submitted transaction is followed by its strongest
//! existing full assert. A deposit runs the deposit assert; a transfer or
//! consolidation syncs and full-struct asserts each involved actor; a merge service
//! consolidation runs the merge assert (decrypt + reconstruct + inclusion); a
//! withdrawal checks the recipient credit inside `withdraw_sol` and asserts the
//! sender. After the run, every actor is synced and asserted again, and an on-chain
//! conservation invariant ties the pool's SOL custody and SPL vault balances to the
//! net deposited minus withdrawn amounts.
//!
//! Merge uses the eddsa owner rail: each actor registers under its own ed25519
//! signing key and the configured merge authority consolidates its SOL UTXOs into one
//! output. The merged output carries no view tag, so `Wallet::sync` cannot rediscover
//! it; the consumed inputs are marked spent directly so the wallet view stays
//! consistent, and the orphaned output value remains in pool custody (conservation
//! still holds).

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use cucumber::when;
use rand::{rngs::StdRng, Rng, SeedableRng};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::pda;
use zolana_test_utils::test_validator_asserts::{fetch_account, token_amount};
use zolana_transaction::{Utxo, SOL_MINT};

use crate::{actor::Actor, localnet::ZERO, LifecycleWorld};

/// Maximum real inputs the 8-in/1-out merge circuit consolidates at once.
const MAX_MERGE_INPUTS: usize = 8;

/// Extra lamports airdropped to the global payer to fund all SOL deposits in the run
/// (SPL deposits mint their own tokens, so they do not draw on this).
const PAYER_DEPOSIT_FUNDING: u64 = 2_000_000_000_000;
/// Lamports airdropped to each actor to pay the fees of the spends it authorizes.
const ACTOR_FEE_FUNDING: u64 = 1_000_000_000;
/// Base unit of a SOL deposit; the actual amount is a small multiple of this so 500
/// deposits stay within the payer's funded balance.
const SOL_DEPOSIT_UNIT: u64 = 50_000_000;
/// Base unit of an SPL deposit (token base units).
const SPL_DEPOSIT_UNIT: u64 = 1_000_000;

/// The randomized actions. Each carries no data; the asset, actor, amount, and
/// recipient are drawn separately. Every actor is eddsa; `Merge` uses the eddsa
/// owner rail.
#[derive(Clone, Copy)]
enum Action {
    DepositSol,
    DepositSpl,
    TransferAsset,
    TransferSingle,
    TransferMixed,
    Consolidate,
    WithdrawSol,
    Merge,
}

/// Relative selection weights for each action.
const ACTION_WEIGHTS: [(Action, u32); 8] = [
    (Action::DepositSol, 14),
    (Action::DepositSpl, 14),
    (Action::TransferAsset, 26),
    (Action::TransferSingle, 12),
    (Action::TransferMixed, 12),
    (Action::Consolidate, 8),
    (Action::WithdrawSol, 12),
    (Action::Merge, 8),
];

/// Configuration for a randomized run.
pub(crate) struct Workload {
    pub(crate) target_txs: usize,
    pub(crate) num_actors: usize,
    pub(crate) num_spl: usize,
}

/// Per-asset deposited totals (keyed by asset address bytes) and the SOL withdrawn
/// total, used for the end-of-run on-chain conservation check.
struct Totals {
    deposited: BTreeMap<[u8; 32], u64>,
    withdrawn_sol: u64,
}

impl Totals {
    fn new() -> Self {
        Self {
            deposited: BTreeMap::new(),
            withdrawn_sol: 0,
        }
    }

    fn record_deposit(&mut self, asset: Address, amount: u64) {
        *self.deposited.entry(asset.to_bytes()).or_default() += amount;
    }

    fn deposited_of(&self, asset: Address) -> u64 {
        self.deposited.get(&asset.to_bytes()).copied().unwrap_or(0)
    }
}

fn pick_action(rng: &mut StdRng) -> Action {
    let total: u32 = ACTION_WEIGHTS.iter().map(|(_, w)| *w).sum();
    let mut roll = rng.gen_range(0..total);
    for (action, weight) in ACTION_WEIGHTS {
        if roll < weight {
            return action;
        }
        roll -= weight;
    }
    Action::DepositSol
}

impl LifecycleWorld {
    /// Drive `cfg.target_txs` randomized state-changing transactions. Sets up the SPL
    /// assets and eddsa actors, then loops: pick a weighted action and actor, sync the
    /// actor so its change/received notes are spendable, and either execute the action
    /// (when its inputs are available) or fall back to a deposit that replenishes the
    /// missing asset. Each submitted transaction is fully asserted. Finishes with a
    /// per-actor sync+assert and an on-chain conservation check.
    pub(crate) fn run_random_workload(&mut self, seed: u64, cfg: Workload) -> Result<()> {
        println!("randomized workload seed: {seed}");
        if cfg.num_actors < 2 {
            return Err(anyhow!("randomized workload needs at least two actors"));
        }
        let mut rng = StdRng::seed_from_u64(seed);

        self.ensure_spl_assets(cfg.num_spl)?;
        self.rpc
            .airdrop(&self.payer.pubkey(), PAYER_DEPOSIT_FUNDING)?;

        let actor_names: Vec<String> = (0..cfg.num_actors).map(|i| format!("actor-{i}")).collect();
        for name in &actor_names {
            let signer = Keypair::new();
            self.rpc.airdrop(&signer.pubkey(), ACTOR_FEE_FUNDING)?;
            let actor = Actor::eddsa(signer)?;
            self.actors.insert(name.clone(), actor);
        }

        let sol_baseline = self.rpc.client().get_balance(&pda::sol_interface())?;
        let mut totals = Totals::new();

        let mut submitted = 0usize;
        while submitted < cfg.target_txs {
            let from_index = rng.gen_range(0..actor_names.len());
            let from = actor_names
                .get(from_index)
                .ok_or_else(|| anyhow!("actor index out of range"))?
                .clone();
            self.sync(&from)?;

            match pick_action(&mut rng) {
                Action::DepositSol => self.rand_deposit(&from, SOL_MINT, &mut rng, &mut totals)?,
                Action::DepositSpl => {
                    let asset = self.random_spl(&mut rng)?;
                    self.rand_deposit(&from, asset, &mut rng, &mut totals)?;
                }
                Action::TransferAsset => {
                    let asset = self.random_asset(&mut rng);
                    if let Some(sum) = self.first_spendable_sum(&from, asset, 2) {
                        let amount = rng.gen_range(1..=sum);
                        let to = self.other_actor(&mut rng, &actor_names, from_index)?;
                        self.transfer_asset(&from, &to, asset, amount)?;
                        self.assert_transfer(&from, Some(&to))?;
                    } else {
                        self.rand_deposit(&from, asset, &mut rng, &mut totals)?;
                    }
                }
                Action::TransferSingle => {
                    let asset = self.random_asset(&mut rng);
                    if let Some(amount_available) = self.first_spendable_sum(&from, asset, 1) {
                        let amount = rng.gen_range(1..=amount_available);
                        let to = self.other_actor(&mut rng, &actor_names, from_index)?;
                        self.transfer_single(&from, &to, asset, amount)?;
                        self.assert_transfer(&from, Some(&to))?;
                    } else {
                        self.rand_deposit(&from, asset, &mut rng, &mut totals)?;
                    }
                }
                Action::TransferMixed => {
                    let asset = self.random_spl(&mut rng)?;
                    let have_sol = self.spendable_count(&from, SOL_MINT) >= 1;
                    let have_spl = self.spendable_count(&from, asset) >= 1;
                    if have_sol && have_spl {
                        let spl_available = self
                            .first_spendable_sum(&from, asset, 1)
                            .ok_or_else(|| anyhow!("missing SPL input"))?;
                        let amount = rng.gen_range(1..=spl_available);
                        let to = self.other_actor(&mut rng, &actor_names, from_index)?;
                        self.transfer_mixed(&from, &to, asset, amount)?;
                        self.assert_transfer(&from, Some(&to))?;
                    } else {
                        let missing = if have_sol { asset } else { SOL_MINT };
                        self.rand_deposit(&from, missing, &mut rng, &mut totals)?;
                    }
                }
                Action::Consolidate => {
                    let asset = self.random_asset(&mut rng);
                    if self.spendable_count(&from, asset) >= 1 {
                        self.consolidate(&from, asset)?;
                        self.assert_transfer(&from, None)?;
                    } else {
                        self.rand_deposit(&from, asset, &mut rng, &mut totals)?;
                    }
                }
                Action::WithdrawSol => {
                    if let Some(sum) = self.first_spendable_sum(&from, SOL_MINT, 2) {
                        let amount = rng.gen_range(1..sum);
                        self.withdraw_sol(&from, amount)?;
                        self.sync(&from)?;
                        self.assert_utxos(&from)?;
                        totals.withdrawn_sol += amount;
                    } else {
                        self.rand_deposit(&from, SOL_MINT, &mut rng, &mut totals)?;
                    }
                }
                Action::Merge => {
                    if self.spendable_count(&from, SOL_MINT) >= 2 {
                        self.rand_merge(&from)?;
                    } else {
                        self.rand_deposit(&from, SOL_MINT, &mut rng, &mut totals)?;
                    }
                }
            }
            submitted += 1;
            if submitted == 1 || submitted % 25 == 0 || submitted == cfg.target_txs {
                println!(
                    "randomized workload progress: {submitted}/{} transactions",
                    cfg.target_txs
                );
            }
        }

        self.finalize(&actor_names, sol_baseline, &totals)
    }

    /// Deposit `asset` to `name` (SOL or SPL), assert the deposit, and record the
    /// amount. Used both as a chosen action and as the replenishing fallback.
    fn rand_deposit(
        &mut self,
        name: &str,
        asset: Address,
        rng: &mut StdRng,
        totals: &mut Totals,
    ) -> Result<()> {
        if asset == SOL_MINT {
            let amount = rng.gen_range(1..=4) * SOL_DEPOSIT_UNIT;
            self.deposit_sol(name, amount)?;
            self.assert_deposited(name, amount)?;
            totals.record_deposit(asset, amount);
        } else {
            let index = self.spl_index(asset)?;
            let amount = rng.gen_range(1..=4) * SPL_DEPOSIT_UNIT;
            self.deposit_spl_at(name, index, amount)?;
            self.assert_deposited(name, amount)?;
            totals.record_deposit(asset, amount);
        }
        Ok(())
    }

    /// Register `name` for the merge service on first use (under its own ed25519
    /// signing key, the eddsa owner rail) and consolidate up to `MAX_MERGE_INPUTS` of
    /// its SOL UTXOs into one output. The merged output is not rediscoverable by sync,
    /// so the consumed inputs are marked spent directly and the merge is verified by
    /// `assert_merged`.
    fn rand_merge(&mut self, name: &str) -> Result<()> {
        let count = self.spendable_count(name, SOL_MINT).min(MAX_MERGE_INPUTS);
        let consumed: Vec<Utxo> = self
            .actor(name)
            .spendable
            .iter()
            .filter(|utxo| utxo.asset == SOL_MINT)
            .take(count)
            .cloned()
            .collect();
        let owner = self.ensure_merge_registered(name)?;
        self.merge(name, &owner, SOL_MINT, count)?;
        self.mark_merge_inputs_spent(name, &consumed)?;
        self.assert_merged(name)
    }

    /// The registry signer for `name`'s merge service, registering it once.
    fn ensure_merge_registered(&mut self, name: &str) -> Result<Keypair> {
        if let Some(owner) = self.merge_owners.get(name) {
            return Ok(owner.insecure_clone());
        }
        let owner = self.register_merge_owner(name, true)?;
        self.merge_owners
            .insert(name.to_string(), owner.insecure_clone());
        Ok(owner)
    }

    /// Mark merge-consumed inputs spent in the actor's tracked sets. Deposited inputs
    /// are untracked (in `spendable` only) so they match nothing; transfer-derived
    /// inputs are flagged in both `wallet.utxos` and `expected`. `Wallet::sync` only
    /// ever sets `spent`, so the flag survives later syncs.
    fn mark_merge_inputs_spent(&mut self, name: &str, consumed: &[Utxo]) -> Result<()> {
        let nullifier_pk = self.actor(name).keypair.nullifier_key.pubkey()?;
        let mut consumed_hashes = Vec::with_capacity(consumed.len());
        for utxo in consumed {
            consumed_hashes.push(utxo.hash(&nullifier_pk, &ZERO, &ZERO)?);
        }
        let actor = self.actor_mut(name);
        for note in actor.expected.iter_mut() {
            if consumed_hashes.contains(&note.hash) {
                note.spent = true;
            }
        }
        for note in actor.wallet.utxos.iter_mut() {
            if consumed_hashes.contains(&note.hash) {
                note.spent = true;
            }
        }
        Ok(())
    }

    /// Sync and full-struct assert the sender, and the recipient when there is one.
    fn assert_transfer(&mut self, from: &str, to: Option<&str>) -> Result<()> {
        self.sync(from)?;
        self.assert_utxos(from)?;
        if let Some(to) = to {
            self.sync(to)?;
            self.assert_utxos(to)?;
        }
        Ok(())
    }

    /// Final per-actor sync+assert and the on-chain conservation check: the pool's SOL
    /// custody grew by exactly the net SOL deposited minus withdrawn, and each SPL
    /// vault holds exactly the SPL deposited for its mint (withdrawals are SOL-only).
    fn finalize(
        &mut self,
        actor_names: &[String],
        sol_baseline: u64,
        totals: &Totals,
    ) -> Result<()> {
        for name in actor_names {
            self.sync(name)?;
            self.assert_utxos(name)?;
        }

        let sol_after = self.rpc.client().get_balance(&pda::sol_interface())?;
        let sol_net = totals.deposited_of(SOL_MINT) - totals.withdrawn_sol;
        assert_eq!(
            sol_after - sol_baseline,
            sol_net,
            "SOL custody balance must equal net deposited minus withdrawn"
        );

        let vaults: Vec<(Pubkey, Address)> = self
            .spls
            .iter()
            .map(|spl| (spl.vault, Address::new_from_array(spl.mint.to_bytes())))
            .collect();
        for (vault, mint) in vaults {
            let vault_amount = token_amount(&fetch_account(&self.rpc, &vault)?);
            assert_eq!(
                vault_amount,
                totals.deposited_of(mint),
                "SPL vault balance must equal the deposited amount for {mint}"
            );
        }
        Ok(())
    }

    fn spendable_count(&self, name: &str, asset: Address) -> usize {
        self.actor(name)
            .spendable
            .iter()
            .filter(|utxo| utxo.asset == asset)
            .count()
    }

    /// Sum of the first `n` spendable UTXOs of `asset` (the ones the transfer/withdraw
    /// methods consume), or `None` if the actor has fewer than `n`.
    fn first_spendable_sum(&self, name: &str, asset: Address, n: usize) -> Option<u64> {
        let amounts: Vec<u64> = self
            .actor(name)
            .spendable
            .iter()
            .filter(|utxo| utxo.asset == asset)
            .take(n)
            .map(|utxo| utxo.amount)
            .collect();
        (amounts.len() == n).then(|| amounts.iter().sum())
    }

    /// A random asset: SOL or one of the registered SPL mints.
    fn random_asset(&self, rng: &mut StdRng) -> Address {
        let index = rng.gen_range(0..=self.spls.len());
        match index.checked_sub(1).and_then(|i| self.spls.get(i)) {
            Some(spl) => Address::new_from_array(spl.mint.to_bytes()),
            None => SOL_MINT,
        }
    }

    /// A random registered SPL mint as an asset address.
    fn random_spl(&self, rng: &mut StdRng) -> Result<Address> {
        if self.spls.is_empty() {
            return Err(anyhow!("no SPL assets registered"));
        }
        let index = rng.gen_range(0..self.spls.len());
        let spl = self
            .spls
            .get(index)
            .ok_or_else(|| anyhow!("SPL index out of range"))?;
        Ok(Address::new_from_array(spl.mint.to_bytes()))
    }

    /// Index into `self.spls` of the registered SPL mint matching `asset`.
    fn spl_index(&self, asset: Address) -> Result<usize> {
        self.spls
            .iter()
            .position(|spl| spl.mint.to_bytes() == asset.to_bytes())
            .ok_or_else(|| anyhow!("asset {asset} is not a registered SPL mint"))
    }

    /// A random actor name other than the one at `from_index`.
    fn other_actor(
        &self,
        rng: &mut StdRng,
        actor_names: &[String],
        from_index: usize,
    ) -> Result<String> {
        loop {
            let index = rng.gen_range(0..actor_names.len());
            if index != from_index {
                return actor_names
                    .get(index)
                    .cloned()
                    .ok_or_else(|| anyhow!("actor index out of range"));
            }
        }
    }
}

#[when(expr = "a randomized workload of {int} transactions runs")]
fn randomized_workload(world: &mut LifecycleWorld, target_txs: i64) {
    let seed = std::env::var("ZOLANA_RANDOM_SEED")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(rand::random);
    let cfg = Workload {
        target_txs: target_txs as usize,
        num_actors: 8,
        num_spl: 3,
    };
    world
        .run_random_workload(seed, cfg)
        .expect("randomized workload");
}
