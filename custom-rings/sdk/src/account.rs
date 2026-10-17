use custom_ring_interface::{
    CoSignScope, CoSigner, Delegate, DepositAudit, MemberRegistryRoot, PolicyConfig,
    ReadAccessRecord, RingAccount, RingMode, RingProgramConfig, MEMBER_REGISTRY_CAPACITY,
};
use solana_account::Account;
use solana_address::Address;
use zolana_client::AsyncRpc;
use zolana_interface::{pda, state::RingConfig, BPF_LOADER_UPGRADEABLE_ID, RING_AUTH_PDA_SEED};
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{RuleTable, SourceMap, NAMESPACE_PDA_SEED};

use crate::RingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustomRing {
    program_id: Address,
}

pub struct CustomRingConfig {
    pub authority: Address,
    pub auditor_pubkey: X25519Pubkey,
    /// A policy ring enforces its compiled rules, an audit-only ring proves only the audit statement.
    pub has_policy: bool,
    /// Fixed for the ring's life, selects the spend rail and the disclosure layout.
    pub mode: RingMode,
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

/// The current root of a member registry and the history slot a statement names it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentRegistryRoot {
    pub root: [u8; 32],
    pub next_index: u64,
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

    /// The shielded owner no policy transfer slot may open to.
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

    pub fn member_registry_root_pda(self) -> Address {
        self.pda(&[MemberRegistryRoot::SEED]).0
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
        let invalid = || RingError::InvalidAccount {
            address: self.config_pda(),
        };
        Ok(Some(CustomRingConfig {
            authority: config.authority,
            auditor_pubkey: X25519Pubkey::from_bytes(config.auditor_pubkey)
                .map_err(|_| invalid())?,
            has_policy: config.has_policy != 0,
            mode: config.mode().ok_or_else(invalid)?,
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
    pub async fn member_registry_root(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<CurrentRegistryRoot>, RingError> {
        let Some(root) = self
            .read::<MemberRegistryRoot>(rpc, &[MemberRegistryRoot::SEED], true)
            .await?
        else {
            return Ok(None);
        };
        current_root(&root)
            .map(Some)
            .ok_or(RingError::InvalidAccount {
                address: self.member_registry_root_pda(),
            })
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

/// The current root of a registry account, `None` for an account no creation wrote.
pub(crate) fn current_root(root: &MemberRegistryRoot) -> Option<CurrentRegistryRoot> {
    let next_index = root.next_index();
    root.root()
        .filter(|_| next_index != 0 && next_index <= MEMBER_REGISTRY_CAPACITY)
        .map(|current| CurrentRegistryRoot {
            root: current,
            next_index,
            history_index: root.history_cursor,
        })
}

/// The map the pinned hash binds, each curator registry address as its field.
pub(crate) fn source_map(config: &PolicyConfig) -> Result<SourceMap, RingError> {
    config.source_map().map_err(|_| RingError::InvalidSources)
}

fn check_pinned_hash(config: &PolicyConfig) -> Result<(), RingError> {
    if config.rules.hash(&source_map(config)?)? != config.policy_hash {
        return Err(RingError::HashMismatch);
    }
    Ok(())
}
