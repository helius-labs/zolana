use std::time::Duration;

use solana_address::Address;
use zolana_keypair::ShieldedKeypair;
use zolana_test_utils::wallet::Wallet;

use kamino_vault_rfq_sdk::kvault::VaultAccounts;

use super::scheduler::profile::LaneProfile;

const MIN_LANE_VALUE: u64 = 1_000_000;

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
    pub tree: Address,
    pub tree_id: u16,
}

pub struct IdentityConfig {
    pub keypair: ShieldedKeypair,
    pub wallet: Wallet,
}

#[derive(Clone, Debug)]
pub struct PairConfig {
    pub vault: VaultAccounts,
    pub collateral: TokenConfig,
    pub shares: TokenConfig,
}

impl PairConfig {
    pub fn new(vault: VaultAccounts) -> Self {
        Self {
            vault,
            collateral: TokenConfig::default(),
            shares: TokenConfig::default(),
        }
    }

    fn token(&self, asset: &Address) -> Option<&TokenConfig> {
        if self.vault.token_mint == *asset {
            Some(&self.collateral)
        } else if self.vault.shares_mint == *asset {
            Some(&self.shares)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TokenConfig {
    pub range: Option<TargetRange>,
    pub lanes: Option<LaneProfile>,
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
    pub lanes: LaneProfile,
    pub max_shield_lanes: usize,
    pub lane_upkeep_delay: Option<Duration>,
    pub provers: usize,
    pub max_provers: usize,
    pub status_interval: Duration,
    pub sync_interval: Duration,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            lanes: LaneProfile::equal(1, MIN_LANE_VALUE),
            max_shield_lanes: 8,
            lane_upkeep_delay: None,
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
    pub tree_id: u16,
    pub lanes: LaneProfile,
    pub max_shield_lanes: usize,
    pub idle_delay: Option<Duration>,
    pub status_interval: Duration,
    pub pairs: Vec<PairConfig>,
}

impl Settings {
    pub fn new(
        connection: &ConnectionConfig,
        concurrency: &ConcurrencyConfig,
        pairs: Vec<PairConfig>,
    ) -> Self {
        Self {
            tree_id: connection.tree_id,
            lanes: concurrency.lanes.clone(),
            max_shield_lanes: concurrency.max_shield_lanes,
            idle_delay: concurrency.lane_upkeep_delay,
            status_interval: concurrency.status_interval,
            pairs,
        }
    }

    pub fn assets(&self) -> Vec<Address> {
        self.pairs
            .iter()
            .flat_map(|pair| [pair.vault.token_mint, pair.vault.shares_mint])
            .collect()
    }

    pub fn range(&self, asset: &Address) -> Option<TargetRange> {
        self.pairs
            .iter()
            .find_map(|pair| pair.token(asset).and_then(|token| token.range))
    }

    pub fn profile(&self, asset: &Address) -> &LaneProfile {
        self.pairs
            .iter()
            .find_map(|pair| pair.token(asset).and_then(|token| token.lanes.as_ref()))
            .unwrap_or(&self.lanes)
    }
}
