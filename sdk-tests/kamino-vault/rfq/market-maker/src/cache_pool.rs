use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::AsyncRpc;
use zolana_interface::{
    instruction::CreateCacheData,
    pda,
    state::cache::{CacheAccount, CACHE_CAPACITY},
};
use zolana_program::instruction::{CloseCache, CreateCache};

use super::{error::MakerError, tracker::UtxoTracker};

pub const CACHE_NONCE_WINDOW: u64 = 64;

const CLOCK_UNIX_TIMESTAMP_OFFSET: usize = 32;

pub fn parse_cache_account(data: &[u8]) -> Option<CacheAccount> {
    data.get(..CacheAccount::SIZE)
        .and_then(|bytes| bytemuck::try_from_bytes::<CacheAccount>(bytes).ok())
        .filter(|cache| cache.has_discriminator())
        .copied()
}

#[derive(Clone, Copy, Debug)]
pub struct ChainClock {
    unix_timestamp: i64,
    fetched_at: Instant,
}

impl ChainClock {
    pub async fn fetch(rpc: &dyn AsyncRpc) -> Result<Self, MakerError> {
        let account = rpc
            .get_account(solana_sdk_ids::sysvar::clock::ID)
            .await
            .map_err(MakerError::Rpc)?
            .ok_or(MakerError::InvalidClock)?;
        let bytes: [u8; 8] = account
            .data
            .get(CLOCK_UNIX_TIMESTAMP_OFFSET..CLOCK_UNIX_TIMESTAMP_OFFSET + 8)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(MakerError::InvalidClock)?;
        Ok(Self {
            unix_timestamp: i64::from_le_bytes(bytes),
            fetched_at: Instant::now(),
        })
    }

    pub fn now(&self) -> i64 {
        self.unix_timestamp
            .saturating_add(seconds(self.fetched_at.elapsed()))
    }
}

fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

#[derive(Clone, Debug)]
pub struct PoolCache {
    pub address: Address,
    pub data: CreateCacheData,
    pub exists: bool,
    pub retired: bool,
    pub confirmed_through: u64,
}

pub struct CachePoolConfig {
    pub rent_sponsor: Address,
    pub write_authority: Address,
    pub tree_id: u16,
    pub lifetime: Duration,
    pub rotation_margin: Duration,
}

pub struct AdoptedCache {
    pub address: Address,
    pub utxo_hashes: [[u8; 32]; CACHE_CAPACITY],
}

pub struct CachePool {
    config: CachePoolConfig,
    caches: Vec<PoolCache>,
    next_nonce: u64,
    clock: ChainClock,
}

impl CachePool {
    pub async fn open(
        config: CachePoolConfig,
        rpc: &dyn AsyncRpc,
    ) -> Result<(Self, Vec<AdoptedCache>), MakerError> {
        let clock = ChainClock::fetch(rpc).await?;
        let addresses: Vec<Address> = (0..CACHE_NONCE_WINDOW)
            .map(|nonce| pda::cache(&config.rent_sponsor, nonce).0)
            .collect();
        let accounts = rpc
            .get_multiple_accounts(addresses.clone())
            .await
            .map_err(MakerError::Rpc)?;
        let mut pool = Self {
            config,
            caches: Vec::new(),
            next_nonce: 0,
            clock,
        };
        let mut adopted = Vec::new();
        for ((nonce, address), account) in (0..CACHE_NONCE_WINDOW).zip(addresses).zip(accounts) {
            let Some(account) = account else {
                continue;
            };
            pool.next_nonce = nonce + 1;
            let Some(cache) = parse_cache_account(&account.data) else {
                continue;
            };
            if cache.write_authority != pool.config.write_authority
                || u16::from_le_bytes(cache.tree_id) != pool.config.tree_id
            {
                continue;
            }
            let expires_at = cache.expiry_unix_ts();
            let retired = pool.is_within_margin(expires_at);
            pool.caches.push(PoolCache {
                address,
                data: CreateCacheData {
                    write_authority: pool.config.write_authority,
                    nonce,
                    tree_id: pool.config.tree_id,
                    expires_at,
                },
                exists: true,
                retired,
                confirmed_through: 0,
            });
            if !retired {
                adopted.push(AdoptedCache {
                    address,
                    utxo_hashes: cache.utxo_hashes,
                });
            }
        }
        Ok((pool, adopted))
    }

    pub fn set_clock(&mut self, clock: ChainClock) {
        self.clock = clock;
    }

    fn is_within_margin(&self, expires_at: i64) -> bool {
        expires_at.saturating_sub(self.clock.now()) < seconds(self.config.rotation_margin)
    }

    pub fn addresses(&self) -> Vec<Address> {
        self.caches.iter().map(|cache| cache.address).collect()
    }

    pub fn get(&self, address: &Address) -> Option<&PoolCache> {
        self.caches.iter().find(|cache| cache.address == *address)
    }

    fn get_mut(&mut self, address: &Address) -> Option<&mut PoolCache> {
        self.caches
            .iter_mut()
            .find(|cache| cache.address == *address)
    }

    fn open_cache(&mut self) -> Address {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        let data = CreateCacheData {
            write_authority: self.config.write_authority,
            nonce,
            tree_id: self.config.tree_id,
            expires_at: self
                .clock
                .now()
                .saturating_add(seconds(self.config.lifetime)),
        };
        let address = pda::cache(&self.config.rent_sponsor, nonce).0;
        self.caches.push(PoolCache {
            address,
            data,
            exists: false,
            retired: false,
            confirmed_through: 0,
        });
        address
    }

    pub fn allocate(
        &mut self,
        tracker: &UtxoTracker,
        count: usize,
        reusable: &[(Address, u8)],
        open: bool,
    ) -> Option<(Address, Vec<u8>)> {
        if count == 0 {
            return None;
        }
        let reused_cache = reusable.first().map(|(cache, _)| *cache);
        let live = self
            .caches
            .iter()
            .rev()
            .filter(|cache| !cache.retired)
            .map(|cache| cache.address);
        let candidates: Vec<Address> = reused_cache
            .filter(|cache| self.get(cache).is_some_and(|entry| !entry.retired))
            .into_iter()
            .chain(live)
            .collect();
        for cache in candidates {
            if let Some(slots) = free_slots(tracker, &cache, count, reusable) {
                return Some((cache, slots));
            }
        }
        if !open {
            return None;
        }
        let cache = self.open_cache();
        free_slots(tracker, &cache, count, &[]).map(|slots| (cache, slots))
    }

    pub fn create_instruction(&self, address: &Address) -> Option<Instruction> {
        let cache = self.get(address)?;
        (!cache.exists).then(|| {
            CreateCache {
                payer: self.config.rent_sponsor,
                data: cache.data,
            }
            .instruction()
        })
    }

    pub fn close_instruction(&self, address: &Address) -> Instruction {
        CloseCache {
            cache: *address,
            rent_recipient: self.config.rent_sponsor,
            writer: None,
        }
        .instruction()
    }

    pub fn mark_written(&mut self, address: &Address, slot: u64) {
        if let Some(cache) = self.get_mut(address) {
            cache.exists = true;
            cache.confirmed_through = cache.confirmed_through.max(slot);
        }
    }

    pub fn mark_exists(&mut self, address: &Address) {
        if let Some(cache) = self.get_mut(address) {
            cache.exists = true;
        }
    }

    pub fn retire_expiring(&mut self) -> Vec<Address> {
        let expiring: Vec<Address> = self
            .caches
            .iter()
            .filter(|cache| !cache.retired && self.is_within_margin(cache.data.expires_at))
            .map(|cache| cache.address)
            .collect();
        for address in &expiring {
            if let Some(cache) = self.get_mut(address) {
                cache.retired = true;
            }
        }
        expiring
    }

    pub fn expired(&self) -> Vec<Address> {
        let now = self.clock.now();
        self.caches
            .iter()
            .filter(|cache| cache.data.expires_at <= now)
            .map(|cache| cache.address)
            .collect()
    }

    pub fn remove(&mut self, address: &Address) {
        self.caches.retain(|cache| cache.address != *address);
    }
}

fn free_slots(
    tracker: &UtxoTracker,
    cache: &Address,
    count: usize,
    reusable: &[(Address, u8)],
) -> Option<Vec<u8>> {
    let used: HashSet<u8> = tracker.slots_in(cache).into_iter().collect();
    let reused = reusable
        .iter()
        .filter(|(reused, _)| reused == cache)
        .map(|(_, index)| *index);
    let unused = (0..CACHE_CAPACITY)
        .filter_map(|index| u8::try_from(index).ok())
        .filter(|index| !used.contains(index));
    let slots: Vec<u8> = reused.chain(unused).take(count).collect();
    (slots.len() == count).then_some(slots)
}
