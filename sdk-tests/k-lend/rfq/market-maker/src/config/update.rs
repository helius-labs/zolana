use std::{sync::PoisonError, time::Duration};

use solana_address::Address;
use tokio::sync::oneshot;

use super::{PairConfig, Settings, TargetRange};
use crate::{
    api::Inner,
    error::MakerError,
    inventory::balance::profile::InventoryProfile,
    inventory::balance::sync::registered_asset,
    transactions::coordinator::{Coordinator, Event, Operation},
};

#[derive(Clone, Debug, Default)]
pub struct ConfigUpdate {
    pub fee_bps: Option<u64>,
    pub quote_ttl: Option<Duration>,
    pub ranges: Vec<RangeUpdate>,
    pub utxo_profiles: Vec<(Address, InventoryProfile)>,
    pub add_pairs: Vec<PairConfig>,
    pub remove_pairs: Vec<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeUpdate {
    pub vault: Address,
    pub collateral: Option<TargetRange>,
    pub shares: Option<TargetRange>,
}

impl Settings {
    fn check(&self, update: &ConfigUpdate) -> Result<(), MakerError> {
        let known = |vault: &Address| {
            self.pair(vault)
                .is_some()
                .then_some(())
                .ok_or(MakerError::UnknownPair { vault: *vault })
        };
        for added in &update.add_pairs {
            if self.pair(&added.pair.vault).is_some() {
                return Err(MakerError::PairExists {
                    vault: added.pair.vault,
                });
            }
        }
        for range in &update.ranges {
            known(&range.vault)?;
        }
        for vault in &update.remove_pairs {
            known(vault)?;
        }
        let assets = self.assets();
        for (mint, _) in &update.utxo_profiles {
            let added = update
                .add_pairs
                .iter()
                .any(|config| config.token(mint).is_some());
            if !assets.contains(mint) && !added {
                return Err(MakerError::UnknownAsset { mint: *mint });
            }
        }
        Ok(())
    }

    pub fn apply(&mut self, update: ConfigUpdate) -> Result<(), MakerError> {
        self.check(&update)?;
        let ConfigUpdate {
            fee_bps,
            quote_ttl,
            ranges,
            utxo_profiles,
            add_pairs,
            remove_pairs,
        } = update;
        if let Some(fee_bps) = fee_bps {
            self.quotes.fee_bps = fee_bps;
        }
        if let Some(ttl) = quote_ttl {
            self.quotes.ttl = ttl;
        }
        self.pairs.extend(add_pairs);
        for range in ranges {
            if let Some(config) = self
                .pairs
                .iter_mut()
                .find(|config| config.pair.vault == range.vault)
            {
                config.collateral.range = range.collateral;
                config.shares.range = range.shares;
            }
        }
        for (mint, profile) in utxo_profiles {
            for config in &mut self.pairs {
                if config.pair.token_mint == mint {
                    config.collateral.profile = Some(profile.clone());
                }
                if config.pair.shares_mint == mint {
                    config.shares.profile = Some(profile.clone());
                }
            }
        }
        self.retiring.extend(remove_pairs);
        Ok(())
    }
}

impl Inner {
    pub async fn update_config(&self, update: ConfigUpdate) -> Result<(), MakerError> {
        let mut added = Vec::new();
        for config in &update.add_pairs {
            for mint in [config.pair.token_mint, config.pair.shares_mint] {
                added.push((
                    registered_asset(self.services.rpc.as_ref(), mint).await?,
                    mint,
                ));
            }
        }
        let (reply, applied) = oneshot::channel();
        self.runtime
            .events
            .send(Event::UpdateConfig { update, reply })
            .map_err(|_| MakerError::ShuttingDown)?;
        applied
            .await
            .map_err(|_| MakerError::CoordinatorStopped)??;
        if added.is_empty() {
            return Ok(());
        }
        {
            let mut registry = self
                .registry
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            for (asset_id, mint) in added {
                if registry.asset_id(&mint).is_err() {
                    registry.insert(asset_id, mint)?;
                }
            }
        }
        self.account.lock().await.rescan();
        self.sync().await
    }
}

impl Coordinator {
    pub async fn on_update_config(
        &mut self,
        update: ConfigUpdate,
        reply: oneshot::Sender<Result<(), MakerError>>,
    ) {
        let applied = self.config.apply(update);
        if applied.is_ok() {
            self.publish_config();
        }
        let _ = reply.send(applied);
        self.try_schedule().await;
    }

    pub fn drop_retired(&mut self) {
        let retired: Vec<Address> = self
            .config
            .retiring
            .iter()
            .copied()
            .filter(|vault| !self.pair_busy(vault))
            .collect();
        if retired.is_empty() {
            return;
        }
        self.config
            .pairs
            .retain(|config| !retired.contains(&config.pair.vault));
        self.config
            .retiring
            .retain(|vault| !retired.contains(vault));
        self.publish_config();
    }

    fn pair_busy(&self, vault: &Address) -> bool {
        let Some(config) = self.config.pair(vault) else {
            return false;
        };
        let assets = [config.pair.token_mint, config.pair.shares_mint];
        let stepping = self
            .steps
            .in_flight()
            .any(|step| step.asset.is_some_and(|asset| assets.contains(&asset)));
        let queued = self
            .queue
            .iter()
            .chain(self.scheduled.values())
            .any(|queued| match &queued.operation {
                Operation::Rebalance(order) => order.pair.vault == *vault,
                operation => assets.contains(&operation.asset()),
            });
        stepping || queued
    }

    fn publish_config(&self) {
        *self
            .shared_config
            .write()
            .unwrap_or_else(PoisonError::into_inner) = self.config.clone();
    }
}
