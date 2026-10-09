mod update;

use std::{collections::HashSet, time::Duration};

use solana_address::Address;
use zolana_keypair::ShieldedKeypair;

use k_lend_rfq_sdk::pair::Pair;

use crate::{error::MakerError, inventory::balance::profile::InventoryProfile};

pub use update::{ConfigUpdate, RangeUpdate};

const MIN_UTXO_VALUE: u64 = 1_000_000;

pub struct MarketMakerConfig {
    pub connection: ConnectionConfig,
    pub identity: IdentityConfig,
    pub pairs: Vec<PairConfig>,
    pub concurrency: ConcurrencyConfig,
    pub quotes: QuoteConfig,
}

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub rpc_url: String,
    pub photon_url: String,
    pub prover_url: Option<String>,
    pub tree: Address,
    pub tree_id: u16,
}

pub struct IdentityConfig {
    pub keypair: ShieldedKeypair,
}

#[derive(Clone, Debug)]
pub struct PairConfig {
    pub pair: Pair,
    pub collateral: TokenConfig,
    pub shares: TokenConfig,
}

impl PairConfig {
    pub fn new(pair: Pair) -> Self {
        Self {
            pair,
            collateral: TokenConfig::default(),
            shares: TokenConfig::default(),
        }
    }

    fn token(&self, asset: &Address) -> Option<&TokenConfig> {
        if self.pair.token_mint == *asset {
            Some(&self.collateral)
        } else if self.pair.shares_mint == *asset {
            Some(&self.shares)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TokenConfig {
    pub range: Option<TargetRange>,
    pub profile: Option<InventoryProfile>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetRange {
    pub min: u64,
    pub max: u64,
}

impl TargetRange {
    pub fn contains(&self, balance: u64) -> bool {
        (self.min..=self.max).contains(&balance)
    }

    pub fn middle(&self) -> u64 {
        self.min + (self.max - self.min) / 2
    }
}

#[derive(Clone, Debug)]
pub struct ConcurrencyConfig {
    pub profile: InventoryProfile,
    pub max_shield_utxos: usize,
    pub utxo_upkeep_delay: Option<Duration>,
    pub provers: usize,
    pub max_provers: usize,
    pub status_interval: Duration,
    pub sync_interval: Duration,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            profile: InventoryProfile::equal(1, MIN_UTXO_VALUE),
            max_shield_utxos: 8,
            utxo_upkeep_delay: None,
            provers: 4,
            max_provers: 16,
            status_interval: Duration::from_millis(400),
            sync_interval: Duration::from_millis(1_000),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteConfig {
    pub fee_bps: u64,
    pub ttl: Duration,
}

impl Default for QuoteConfig {
    fn default() -> Self {
        Self {
            fee_bps: 30,
            ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub quotes: QuoteConfig,
    pub retiring: HashSet<Address>,
    pub profile: InventoryProfile,
    pub max_shield_utxos: usize,
    pub idle_delay: Option<Duration>,
    pub status_interval: Duration,
    pub pairs: Vec<PairConfig>,
}

impl Settings {
    pub fn new(
        concurrency: &ConcurrencyConfig,
        quotes: QuoteConfig,
        pairs: Vec<PairConfig>,
    ) -> Self {
        Self {
            quotes,
            retiring: HashSet::new(),
            profile: concurrency.profile.clone(),
            max_shield_utxos: concurrency.max_shield_utxos,
            idle_delay: concurrency.utxo_upkeep_delay,
            status_interval: concurrency.status_interval,
            pairs,
        }
    }

    pub fn assets(&self) -> Vec<Address> {
        self.pairs
            .iter()
            .flat_map(|config| [config.pair.token_mint, config.pair.shares_mint])
            .collect()
    }

    pub fn pair(&self, vault: &Address) -> Option<&PairConfig> {
        self.pairs.iter().find(|config| config.pair.vault == *vault)
    }

    pub fn serves(&self, pair: &Pair) -> Result<(), MakerError> {
        let served = self
            .pair(&pair.vault)
            .is_some_and(|config| config.pair == *pair)
            && !self.retiring.contains(&pair.vault);
        if served {
            Ok(())
        } else {
            Err(MakerError::PairNotServed { vault: pair.vault })
        }
    }

    pub fn range(&self, asset: &Address) -> Option<TargetRange> {
        self.pairs
            .iter()
            .find_map(|config| config.token(asset).and_then(|token| token.range))
    }

    pub fn profile(&self, asset: &Address) -> &InventoryProfile {
        self.pairs
            .iter()
            .find_map(|config| config.token(asset).and_then(|token| token.profile.as_ref()))
            .unwrap_or(&self.profile)
    }
}
