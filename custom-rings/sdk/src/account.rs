use custom_ring_interface::{
    CoSignScope, CoSigner, Delegate, DepositAudit, KeyEscrow, KeyRegistryRoot, PolicyConfig,
    ReadAccessRecord, RingAccount, RingProgramConfig, SpendWindow, KEY_REGISTRY_CAPACITY,
};
use solana_account::Account;
use solana_address::Address;
use zolana_client::AsyncRpc;
use zolana_interface::{
    is_reserved_p256_derivation_point, pda, state::RingConfig, BPF_LOADER_UPGRADEABLE_ID,
    RING_AUTH_PDA_SEED,
};
use zolana_keypair::P256Pubkey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ListNamespace, RuleTable, SourceMap, SourceOwner, NAMESPACE_PDA_SEED};

use crate::RingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustomRing {
    program_id: Address,
}

pub struct CustomRingConfig {
    pub authority: Address,
    pub auditor_pubkey: P256Pubkey,
    /// A policy ring enforces its compiled rules, an audit-only ring proves only the audit statement.
    pub has_policy: bool,
    pub key_escrow: KeyEscrow,
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
pub struct CurrentKeyRegistryRoot {
    pub root: [u8; 32],
    pub next_index: u64,
    /// The history slot a statement names `root` by.
    pub history_index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolTree {
    pub address: Address,
    pub id: u16,
}

impl PoolTree {
    /// SPP derives every tree account from its id.
    pub fn from_id(id: u16) -> Self {
        Self {
            address: pda::tree(id),
            id,
        }
    }

    pub fn address_tree(config: &PolicyConfig) -> Self {
        Self {
            address: config.address_tree,
            id: config.address_tree_id(),
        }
    }

    /// Keeps `self` when the ids agree.
    pub(crate) fn sibling(self, id: u16) -> Self {
        if id == self.id {
            self
        } else {
            Self::from_id(id)
        }
    }
}

pub struct PinnedPolicy {
    pub config: PolicyConfig,
    pub table: RuleTable,
}

impl CustomRing {
    pub const fn new(program_id: Address) -> Self {
        Self { program_id }
    }

    pub const fn program_id(self) -> Address {
        self.program_id
    }

    fn pda(self, seeds: &[&[u8]]) -> (Address, u8) {
        Address::find_program_address(seeds, &self.program_id)
    }

    pub fn config_pda(self) -> Address {
        self.pda(&[RingProgramConfig::SEED]).0
    }

    pub fn policy_config_pda(self) -> Address {
        self.pda(&[PolicyConfig::SEED]).0
    }

    /// The shielded owner of every policy entry.
    pub fn namespace_pda(self) -> Address {
        self.pda(&[NAMESPACE_PDA_SEED]).0
    }

    pub fn cosigner_pda(self) -> Address {
        self.pda(&[CoSigner::SEED]).0
    }

    pub fn deposit_audit_pda(self) -> Address {
        self.pda(&[DepositAudit::SEED]).0
    }

    pub fn delegate_pda(self) -> Address {
        self.pda(&[Delegate::SEED]).0
    }

    pub fn key_registry_root_pda(self) -> Address {
        self.pda(&[KeyRegistryRoot::SEED]).0
    }

    /// SOL under the zero address.
    pub fn spend_window_pda(self, mint: &Address) -> Address {
        self.pda(&[SpendWindow::SEED, mint.as_array()]).0
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

    /// The canonical account at `seeds`, `None` when absent or, for an `optional` control, empty.
    pub async fn read<A: RingAccount>(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
        seeds: &[&[u8]],
        optional: bool,
    ) -> Result<Option<A>, RingError> {
        let (address, bump) = self.pda(seeds);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        if optional && account.data.is_empty() {
            return Ok(None);
        }
        A::decode(&account.owner, &self.program_id, &account.data)
            .filter(|state| state.bump() == bump)
            .map(Some)
            .ok_or(RingError::InvalidAccount { address })
    }

    pub async fn config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<CustomRingConfig>, RingError> {
        let Some(config) = self
            .read::<RingProgramConfig>(rpc, &[RingProgramConfig::SEED], false)
            .await?
        else {
            return Ok(None);
        };
        let invalid = RingError::InvalidAccount {
            address: self.config_pda(),
        };
        if is_reserved_p256_derivation_point(&config.auditor_pubkey) {
            return Err(invalid);
        }
        Ok(Some(CustomRingConfig {
            authority: config.authority,
            auditor_pubkey: P256Pubkey::from_bytes(config.auditor_pubkey).map_err(|_| invalid)?,
            has_policy: config.has_policy != 0,
            key_escrow: config.key_escrow(),
        }))
    }

    /// Off unless the account requires disclosure, an empty account owned by another program is invalid.
    pub async fn deposit_audit(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        let address = self.deposit_audit_pda();
        if let Some(account) = rpc.get_account(address).await? {
            if account.data.is_empty() {
                return match account.owner == Address::default() {
                    true => Ok(false),
                    false => Err(RingError::InvalidAccount { address }),
                };
            }
        }
        Ok(self
            .read::<DepositAudit>(rpc, &[DepositAudit::SEED], false)
            .await?
            .is_some_and(|audit| audit.required == 1))
    }

    /// `None` when the ring has no co-signer.
    pub async fn cosigner(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<CustomRingCoSigner>, RingError> {
        let Some(cosigner) = self.read::<CoSigner>(rpc, &[CoSigner::SEED], true).await? else {
            return Ok(None);
        };
        let rows = cosigner.thresholds();
        let canonical = cosigner.signer != Address::default()
            && cosigner.thresholds[rows.len()..]
                .iter()
                .all(|row| row.mint == Address::default() && row.amount() == 0)
            && rows
                .iter()
                .enumerate()
                .all(|(index, row)| rows[..index].iter().all(|earlier| earlier.mint != row.mint));
        let scope = CoSignScope::new(cosigner.scope).filter(|_| canonical);
        let scope = scope.ok_or(RingError::InvalidAccount {
            address: self.cosigner_pda(),
        })?;
        Ok(Some(CustomRingCoSigner {
            signer: cosigner.signer,
            scope,
            thresholds: rows
                .iter()
                .map(|row| CoSignThreshold {
                    mint: row.mint,
                    amount: row.amount(),
                })
                .collect(),
        }))
    }

    /// `None` when the ring has no delegate.
    pub async fn delegate(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<Address>, RingError> {
        match self.read::<Delegate>(rpc, &[Delegate::SEED], true).await? {
            Some(state) if state.delegate == Address::default() => Err(RingError::InvalidAccount {
                address: self.delegate_pda(),
            }),
            state => Ok(state.map(|state| state.delegate)),
        }
    }

    /// `None` until the authority creates the registry root. Slot 0 holds the sentinel.
    pub async fn key_registry_root(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<CurrentKeyRegistryRoot>, RingError> {
        let Some(root) = self
            .read::<KeyRegistryRoot>(rpc, &[KeyRegistryRoot::SEED], true)
            .await?
        else {
            return Ok(None);
        };
        let next_index = root.next_index();
        root.root()
            .filter(|_| next_index != 0 && next_index <= KEY_REGISTRY_CAPACITY)
            .map(|current| {
                Some(CurrentKeyRegistryRoot {
                    root: current,
                    next_index,
                    history_index: root.history_cursor,
                })
            })
            .ok_or(RingError::InvalidAccount {
                address: self.key_registry_root_pda(),
            })
    }

    /// `None` when the mint is uncapped.
    pub async fn spend_window(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
        mint: &Address,
    ) -> Result<Option<SpendWindow>, RingError> {
        match self
            .read::<SpendWindow>(rpc, &[SpendWindow::SEED, mint.as_array()], true)
            .await?
        {
            Some(window) if window.window_slots() == 0 || window.mint != *mint => {
                Err(RingError::InvalidAccount {
                    address: self.spend_window_pda(mint),
                })
            }
            window => Ok(window),
        }
    }

    pub async fn policy_config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<PolicyConfig>, RingError> {
        self.read(rpc, &[PolicyConfig::SEED], false).await
    }

    /// The stored table, trusted once its rows reproduce the pinned hash.
    pub async fn pinned_policy(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<PinnedPolicy>, RingError> {
        let Some(config) = self.policy_config(rpc).await? else {
            return Ok(None);
        };
        Ok(Some(PinnedPolicy {
            table: policy_config_table(&config)?,
            config,
        }))
    }

    pub async fn access_record(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
        reader: &ReaderKey,
    ) -> Result<Option<ReadAccessRecord>, RingError> {
        let bytes = reader.to_bytes();
        let seed_hash = ReadAccessRecord::seed_hash(&bytes)?;
        match self
            .read::<ReadAccessRecord>(rpc, &[ReadAccessRecord::SEED, &seed_hash], false)
            .await?
        {
            Some(record) if record.reader != bytes => Err(RingError::InvalidAccount {
                address: self.read_access_record_pda(reader),
            }),
            record => Ok(record),
        }
    }

    /// Owned by SPP, not by the ring program.
    pub async fn spp_ring_config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<RingConfig>, RingError> {
        let (address, bump) = self.pda(&[RING_AUTH_PDA_SEED]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        spp_ring_config(&account, self.program_id, bump)
            .map(Some)
            .ok_or(RingError::InvalidAccount { address })
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

/// The stored table, trusted once its rows reproduce the pinned hash.
pub fn policy_config_table(config: &PolicyConfig) -> Result<RuleTable, RingError> {
    let table = config.rule_table()?;
    check_pinned_hash(config)?;
    Ok(table)
}

pub fn client_rules_match(rules: &RuleTable, config: &PolicyConfig) -> Result<(), RingError> {
    if rules.encode() != config.rules {
        return Err(RingError::TableMismatch);
    }
    check_pinned_hash(config)
}

/// The map the pinned hash binds, each stored namespace hashed to its owner.
pub(crate) fn source_map(config: &PolicyConfig) -> Result<SourceMap, RingError> {
    let mut slots = [SourceOwner::default(); zolana_ring_policy::MAX_SOURCES];
    for (slot, stored) in slots.iter_mut().zip(&config.sources) {
        if stored.list_id != 0 {
            *slot = SourceOwner {
                list_id: stored.list_id,
                owner_hash: ListNamespace::new(stored.namespace.as_array())?.owner_hash,
            };
        }
    }
    SourceMap::from_slots(slots).map_err(|_| RingError::InvalidSources)
}

fn check_pinned_hash(config: &PolicyConfig) -> Result<(), RingError> {
    if config.rules.hash(&source_map(config)?)? != config.policy_hash {
        return Err(RingError::HashMismatch);
    }
    Ok(())
}
