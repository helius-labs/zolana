//! The ring's accounts as the chain holds them, every read checked against its canonical address.

use custom_ring_interface::{
    stream::tag_epoch, CoSignScope, MemberRegistry, ReadAccessRecord, RecordQueue, RingAccount,
    RingMode, RingProgramConfig, ROOT_HISTORY,
};
use solana_account::Account;
use solana_address::Address;
use zolana_client::AsyncRpc;
use zolana_interface::{pda, state::RingConfig, BPF_LOADER_UPGRADEABLE_ID, RING_AUTH_PDA_SEED};
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ring_id_field, RuleTable, SourceMap};

use crate::RingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustomRing {
    program_id: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingConfig {
    pub authority: Address,
    pub auditor_pubkey: X25519Pubkey,
    /// A policy ring enforces its table, an audit-only ring proves only the audit statement.
    pub has_policy: bool,
    /// Selects the spend rail and the disclosure layout, `SetDelegate` moves Off to Registry.
    pub mode: RingMode,
    /// Lamports a member's record write pays the authority.
    pub insert_fee: u64,
    pub co_signer: Option<CustomRingCoSigner>,
    pub delegate: Option<Address>,
    pub created_slot: u64,
    account: RingProgramConfig,
}

/// SOL under the zero address, a mint without a row always needs the co-signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignThreshold {
    pub mint: Address,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingCoSigner {
    pub signer: Address,
    pub scope: CoSignScope,
    pub thresholds: Vec<CoSignThreshold>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingRegistration {
    pub activated: bool,
    pub paused: bool,
    /// The delegate rail the activation enables.
    pub authority_rail: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryRoot {
    pub index: u8,
    pub root: [u8; 32],
    /// The queue position the root reached.
    pub applied: u64,
    pub slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryStatus {
    /// Newest first, unwritten slots left out.
    pub roots: Vec<RegistryRoot>,
    pub next_index: u32,
    pub floor: u64,
    pub prior_floor: u64,
    pub floor_slot: u64,
    /// Zero before the first policy write.
    pub policy_hash: [u8; 32],
    account: Box<MemberRegistry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueStatus {
    pub head: u64,
    pub tail: u64,
    pub pending: u64,
    /// The first slot a permissionless application may land in.
    pub next_apply_slot: u64,
}

/// `None` for an absent account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingStatus {
    pub config: CustomRingConfig,
    pub registration: Option<RingRegistration>,
    pub registry: Option<RegistryStatus>,
    pub queue: Option<QueueStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedPolicy {
    pub table: RuleTable,
    pub sources: SourceMap,
    pub policy_hash: [u8; 32],
    pub curator: Option<Address>,
}

impl CustomRing {
    pub const fn new(program_id: Address) -> Self {
        Self { program_id }
    }

    pub const fn program_id(self) -> Address {
        self.program_id
    }

    /// `hash_bytes` of the program id, the ring id every statement and UTXO binds.
    pub fn ring_id(self) -> Result<[u8; 32], RingError> {
        Ok(ring_id_field(self.program_id.as_array())?)
    }

    fn pda(self, seeds: &[&[u8]]) -> (Address, u8) {
        Address::find_program_address(seeds, &self.program_id)
    }

    pub fn config_pda(self) -> Address {
        self.pda(&[RingProgramConfig::SEED]).0
    }

    pub fn registry_pda(self) -> Address {
        self.pda(&[MemberRegistry::SEED]).0
    }

    pub fn queue_pda(self) -> Address {
        self.pda(&[RecordQueue::SEED]).0
    }

    pub fn read_access_record_pda(self, reader: &ReaderKey) -> Address {
        reader.record_address(&self.program_id)
    }

    /// SPP stores the ring config here and requires it as the signer of ring CPIs.
    pub fn ring_auth_pda(self) -> Address {
        self.pda(&[RING_AUTH_PDA_SEED]).0
    }

    pub fn program_data_pda(self) -> Address {
        Address::find_program_address(
            &[self.program_id.as_ref()],
            &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
        )
        .0
    }

    /// The canonical account of `A`, `None` when absent.
    pub async fn read<A: RingAccount>(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<A>, RingError> {
        let (address, bump) = self.pda(&[A::SEED]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        A::decode(&account.owner, &self.program_id, &account.data)
            .filter(|state| state.bump() == bump)
            .map(Some)
            .ok_or(RingError::InvalidAccount { address })
    }

    pub async fn config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<CustomRingConfig>, RingError> {
        let Some(account) = self.read::<RingProgramConfig>(rpc).await? else {
            return Ok(None);
        };
        CustomRingConfig::new(account, self.config_pda()).map(Some)
    }

    pub async fn require_config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<CustomRingConfig, RingError> {
        self.config(rpc).await?.ok_or(RingError::MissingRingConfig)
    }

    pub async fn registry(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<Box<MemberRegistry>>, RingError> {
        Ok(self.read::<MemberRegistry>(rpc).await?.map(Box::new))
    }

    pub async fn require_registry(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Box<MemberRegistry>, RingError> {
        self.registry(rpc)
            .await?
            .ok_or(RingError::MissingMemberRegistry)
    }

    pub async fn queue(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<RecordQueue>, RingError> {
        self.read::<RecordQueue>(rpc).await
    }

    pub async fn require_queue(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<RecordQueue, RingError> {
        self.queue(rpc).await?.ok_or(RingError::MissingRecordQueue)
    }

    /// `None` on an audit-only ring.
    pub async fn pinned_policy(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<PinnedPolicy>, RingError> {
        if !self.require_config(rpc).await?.has_policy {
            return Ok(None);
        }
        PinnedPolicy::of(&*self.require_registry(rpc).await?).map(Some)
    }

    pub async fn access_record(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
        reader: &ReaderKey,
    ) -> Result<Option<ReadAccessRecord>, RingError> {
        let bytes = reader.to_bytes();
        let seed_hash = ReadAccessRecord::seed_hash(&bytes)?;
        let (address, bump) = self.pda(&[ReadAccessRecord::SEED, &seed_hash]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        ReadAccessRecord::decode(&account.owner, &self.program_id, &account.data)
            .filter(|record| record.bump() == bump && record.reader == bytes)
            .map(Some)
            .ok_or(RingError::InvalidAccount { address })
    }

    pub async fn registration(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<RingRegistration>, RingError> {
        let (address, bump) = self.pda(&[RING_AUTH_PDA_SEED]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        let config = spp_ring_config(&account, self.program_id, bump)
            .ok_or(RingError::InvalidAccount { address })?;
        Ok(Some(RingRegistration {
            activated: config.is_activated(),
            paused: config.is_paused(),
            authority_rail: config.enabled(),
        }))
    }

    /// SPP's deposit, transfer and merge rails refuse a ring not registered, not activated or paused.
    pub async fn require_active(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<(), RingError> {
        match self.registration(rpc).await? {
            None => Err(RingError::RingNotRegistered),
            Some(registration) if !registration.activated => Err(RingError::RingNotActivated),
            Some(registration) if registration.paused => Err(RingError::RingPaused),
            Some(_) => Ok(()),
        }
    }

    pub async fn status(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<RingStatus, RingError> {
        let config = self.require_config(rpc).await?;
        let registry = self.registry(rpc).await?;
        let queue = self.queue(rpc).await?;
        Ok(RingStatus {
            config,
            registration: self.registration(rpc).await?,
            registry: registry.map(RegistryStatus::of),
            queue: queue.map(|queue| QueueStatus {
                head: queue.head(),
                tail: queue.tail(),
                pending: queue.pending(),
                next_apply_slot: queue.next_apply_slot(),
            }),
        })
    }
}

impl CustomRingConfig {
    fn new(account: RingProgramConfig, address: Address) -> Result<Self, RingError> {
        let invalid = || RingError::InvalidAccount { address };
        let co_signer = match account.co_signer() {
            Some(signer) => Some(CustomRingCoSigner {
                signer: *signer,
                scope: account.co_sign_scope().ok_or_else(invalid)?,
                thresholds: account
                    .thresholds()
                    .iter()
                    .map(|row| CoSignThreshold {
                        mint: row.mint,
                        amount: row.amount(),
                    })
                    .collect(),
            }),
            None => None,
        };
        Ok(Self {
            authority: account.authority,
            auditor_pubkey: X25519Pubkey::from_bytes(account.auditor_pubkey)
                .map_err(|_| invalid())?,
            has_policy: account.has_policy(),
            mode: account.mode()?,
            insert_fee: account.insert_fee(),
            co_signer,
            delegate: account.delegate().copied(),
            created_slot: account.created_slot(),
            account,
        })
    }

    pub fn account(&self) -> &RingProgramConfig {
        &self.account
    }

    /// No stream of the ring holds an output from an earlier epoch.
    pub fn creation_epoch(&self) -> u64 {
        tag_epoch(self.created_slot)
    }

    /// `None` when the authority writes or the ring charges no fee.
    pub fn insert_fee_for(&self, writer: &Address) -> Option<u64> {
        (self.insert_fee != 0 && *writer != self.authority).then_some(self.insert_fee)
    }
}

impl RegistryStatus {
    fn of(registry: Box<MemberRegistry>) -> Self {
        let cursor = usize::from(registry.history_cursor);
        let roots = (0..ROOT_HISTORY)
            .map(|back| (cursor + ROOT_HISTORY - back) % ROOT_HISTORY)
            .filter_map(|index| {
                let entry = &registry.history[index];
                (entry.root != [0; 32]).then(|| RegistryRoot {
                    index: index as u8,
                    root: entry.root,
                    applied: entry.applied(),
                    slot: entry.slot(),
                })
            })
            .collect();
        Self {
            roots,
            next_index: registry.next_index(),
            floor: registry.floor(),
            prior_floor: registry.prior_floor(),
            floor_slot: registry.floor_slot(),
            policy_hash: registry.policy_hash,
            account: registry,
        }
    }

    pub fn account(&self) -> &MemberRegistry {
        &self.account
    }
}

impl PinnedPolicy {
    /// The stored table and sources, refused unless they reproduce the pinned hash.
    pub fn of(registry: &MemberRegistry) -> Result<Self, RingError> {
        let policy_hash = *registry.policy_hash()?;
        let sources = registry.source_map()?;
        let table = registry.rule_table()?;
        if table.hash(&sources)? != policy_hash {
            return Err(RingError::HashMismatch);
        }
        Ok(Self {
            table,
            sources,
            policy_hash,
            curator: registry.curator(),
        })
    }

    pub fn matches(&self, rules: &RuleTable) -> Result<(), RingError> {
        if rules.encode() != self.table.encode() {
            return Err(RingError::TableMismatch);
        }
        Ok(())
    }
}

fn spp_ring_config(account: &Account, program_id: Address, bump: u8) -> Option<RingConfig> {
    (account.owner == pda::shielded_pool_program_id() && account.data.len() == RingConfig::SIZE)
        .then(|| {
            bytemuck::try_from_bytes::<RingConfig>(&account.data)
                .ok()
                .copied()
        })
        .flatten()
        .filter(|config| {
            config.has_discriminator() && config.program_id == program_id && config.bump == bump
        })
}
