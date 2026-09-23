//! Addresses the client shares across instruction builders.

use bytemuck::Pod;
use custom_ring_interface::{
    pda as ring_pda, CoSignScope, CoSigner, Delegate, DepositAudit, KeyEscrow, KeyRegistryRoot,
    PolicyConfig, ReadAccessRecord, RingProgramConfig, SpendWindow, CO_SIGNER, DELEGATE,
    DEPOSIT_AUDIT, KEY_REGISTRY_CAPACITY, KEY_REGISTRY_ROOT, POLICY_CONFIG, READ_ACCESS_RECORD,
    RING_PROGRAM_CONFIG, SPEND_WINDOW,
};
use solana_account::Account;
use solana_address::Address;
use thiserror::Error;
use zolana_client::{AsyncRpc, ClientError, Rpc};
use zolana_interface::{
    is_reserved_p256_derivation_point, pda, state::RingConfig, BPF_LOADER_UPGRADEABLE_ID,
    RING_AUTH_PDA_SEED,
};
use zolana_keypair::P256Pubkey;
pub use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_ring_policy::{
    ListId, ListNamespace, PolicyHashError, RuleTable, RuleTableError, SourceMap, SourceOwner,
    MAX_SOURCES, NAMESPACE_PDA_SEED,
};

use crate::instructions::cosigner::CoSignThreshold;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomRing {
    program_id: Address,
}

pub struct CustomRingConfig {
    pub authority: Address,
    pub auditor_pubkey: P256Pubkey,
    /// A policy ring enforces its compiled rules, an audit-only ring proves only
    /// the audit statement.
    pub has_policy: bool,
    /// Once on, every output key but a namespace-owned record's must be enrolled in the registry.
    pub key_escrow: KeyEscrow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingCoSigner {
    pub signer: Address,
    pub scope: CoSignScope,
    pub thresholds: Vec<CoSignThreshold>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomRingDelegate {
    pub delegate: Address,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingSpendWindow {
    pub mint: Address,
    pub window_slots: u64,
    pub deposit_cap: u64,
    pub withdrawal_cap: u64,
    pub window_start_slot: u64,
    pub deposited: u64,
    pub withdrawn: u64,
}

#[derive(Debug, Error)]
pub enum AccountReadError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("custom ring account is invalid")]
    InvalidAccount { address: Address },
}

/// The stored rows or the client's table disagree with the deployed ring.
#[derive(Debug, Error)]
pub enum PolicyMatchError {
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Rules(#[from] RuleTableError),
    #[error("the compiled table differs from the stored rows")]
    TableMismatch,
    #[error("the rule table does not reproduce the pinned policy hash")]
    HashMismatch,
    #[error("no source serves the {0:?} list")]
    MissingSource(ListId),
    #[error("the stored source map breaks the positional layout")]
    InvalidSources,
    #[error("policy hashing failed")]
    Hashing,
}

impl From<PolicyHashError> for PolicyMatchError {
    fn from(error: PolicyHashError) -> Self {
        match error {
            PolicyHashError::Hashing => Self::Hashing,
            PolicyHashError::MissingSource(list_id) => Self::MissingSource(list_id),
            PolicyHashError::Table(error) => Self::Rules(error),
        }
    }
}

#[derive(Clone, Copy)]
struct Pda {
    address: Address,
    bump: u8,
}

impl From<(Address, u8)> for Pda {
    fn from((address, bump): (Address, u8)) -> Self {
        Self { address, bump }
    }
}

impl CustomRing {
    pub const fn new(program_id: Address) -> Self {
        Self { program_id }
    }

    pub const fn program_id(self) -> Address {
        self.program_id
    }

    /// The program's singleton config account, holding the authority and the auditor
    /// public key.
    pub fn config_pda(self) -> Address {
        Address::find_program_address(&[RingProgramConfig::SEED], &self.program_id).0
    }

    pub fn policy_config_pda(self) -> Address {
        Address::find_program_address(&[PolicyConfig::SEED], &self.program_id).0
    }

    /// The shielded owner of every policy entry.
    pub fn namespace_pda(self) -> Address {
        Address::find_program_address(&[NAMESPACE_PDA_SEED], &self.program_id).0
    }

    pub fn cosigner_pda(self) -> Address {
        self.cosigner_pda_with_bump().address
    }

    pub fn deposit_audit_pda(self) -> Address {
        Address::find_program_address(&[DepositAudit::SEED], &self.program_id).0
    }

    pub fn read_deposit_audit<R: Rpc>(self, rpc: &R) -> Result<bool, AccountReadError> {
        self.decode_deposit_audit(rpc.get_account(self.deposit_audit_pda())?)
    }

    pub async fn read_deposit_audit_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<bool, AccountReadError> {
        self.decode_deposit_audit(rpc.get_account(self.deposit_audit_pda()).await?)
    }

    fn decode_deposit_audit(self, account: Option<Account>) -> Result<bool, AccountReadError> {
        let (address, bump) =
            Address::find_program_address(&[DepositAudit::SEED], &self.program_id);
        if account
            .as_ref()
            .is_some_and(|value| value.data.is_empty() && value.owner != Address::default())
        {
            return Err(AccountReadError::InvalidAccount { address });
        }
        let Some(state) =
            AccountRead::decode_optional::<DepositAudit>(self.program_id, address, account)?
        else {
            return Ok(false);
        };
        if state.bump != bump || state.required > 1 {
            return Err(AccountReadError::InvalidAccount { address });
        }
        Ok(state.required == 1)
    }

    fn cosigner_pda_with_bump(self) -> Pda {
        Address::find_program_address(&[CoSigner::SEED], &self.program_id).into()
    }

    pub fn delegate_pda(self) -> Address {
        self.delegate_pda_with_bump().address
    }

    fn delegate_pda_with_bump(self) -> Pda {
        Address::find_program_address(&[Delegate::SEED], &self.program_id).into()
    }

    /// Slot 0 holds the sentinel, the cursor never reads zero.
    fn decode_key_registry_root(
        self,
        pda: Pda,
        account: Option<Account>,
    ) -> Result<Option<CurrentKeyRegistryRoot>, AccountReadError> {
        let Some(root) =
            AccountRead::decode_optional::<KeyRegistryRoot>(self.program_id, pda.address, account)?
        else {
            return Ok(None);
        };
        let next_index = root.next_index();
        let current = root.root().filter(|_| {
            root.bump == pda.bump && next_index != 0 && next_index <= KEY_REGISTRY_CAPACITY
        });
        let Some(current) = current else {
            return Err(AccountReadError::InvalidAccount {
                address: pda.address,
            });
        };
        Ok(Some(CurrentKeyRegistryRoot {
            root: current,
            next_index,
            history_index: root.history_cursor,
        }))
    }

    /// SOL under the zero address.
    pub fn spend_window_pda(self, mint: &Address) -> Address {
        self.spend_window_pda_with_bump(mint).address
    }

    fn spend_window_pda_with_bump(self, mint: &Address) -> Pda {
        Address::find_program_address(&[SpendWindow::SEED, mint.as_array()], &self.program_id)
            .into()
    }

    pub fn read_access_record_pda(self, reader: &ReaderKey) -> Address {
        reader.record_address(&self.program_id)
    }

    /// The ring authority PDA. SPP stores the ring config under this address and
    /// requires it as a signer on ring deposits and ring transacts, which is why the
    /// program signs its CPIs with it.
    pub fn ring_auth_pda(self) -> Address {
        Address::find_program_address(&[RING_AUTH_PDA_SEED], &self.program_id).0
    }

    pub fn program_data_pda(self) -> Address {
        Address::find_program_address(
            &[self.program_id.as_ref()],
            &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
        )
        .0
    }

    pub fn read_config<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingConfig>, AccountReadError> {
        let address = self.config_pda();
        self.decode_config(address, rpc.get_account(address)?)
    }

    /// The async twin of [`Self::read_config`], over [`AsyncRpc`]. A host that
    /// cannot link a blocking Solana client -- an enclave pinned below the
    /// versions it needs -- reaches the same config through its own transport.
    pub async fn read_config_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingConfig>, AccountReadError> {
        let address = self.config_pda();
        self.decode_config(address, rpc.get_account(address).await?)
    }

    fn decode_config(
        self,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<CustomRingConfig>, AccountReadError> {
        let Some(config) =
            AccountRead::decode::<RingProgramConfig>(self.program_id, address, account)?
        else {
            return Ok(None);
        };
        let bump = Address::find_program_address(&[RingProgramConfig::SEED], &self.program_id).1;
        if config.bump != bump || is_reserved_p256_derivation_point(&config.auditor_pubkey) {
            return Err(AccountReadError::InvalidAccount { address });
        }
        let auditor_pubkey = P256Pubkey::from_bytes(config.auditor_pubkey)
            .map_err(|_| AccountReadError::InvalidAccount { address })?;
        Ok(Some(CustomRingConfig {
            authority: config.authority,
            auditor_pubkey,
            has_policy: config.has_policy != 0,
            key_escrow: config.key_escrow(),
        }))
    }

    /// `None` when the ring has no co-signer.
    pub fn read_cosigner<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingCoSigner>, AccountReadError> {
        let pda = self.cosigner_pda_with_bump();
        self.decode_cosigner(pda, rpc.get_account(pda.address)?)
    }

    /// The async twin of [`Self::read_cosigner`], over [`AsyncRpc`].
    pub async fn read_cosigner_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingCoSigner>, AccountReadError> {
        let pda = self.cosigner_pda_with_bump();
        self.decode_cosigner(pda, rpc.get_account(pda.address).await?)
    }

    fn decode_cosigner(
        self,
        pda: Pda,
        account: Option<Account>,
    ) -> Result<Option<CustomRingCoSigner>, AccountReadError> {
        let Some(cosigner) =
            AccountRead::decode_optional::<CoSigner>(self.program_id, pda.address, account)?
        else {
            return Ok(None);
        };
        let invalid = || AccountReadError::InvalidAccount {
            address: pda.address,
        };
        let scope = CoSignScope::new(cosigner.scope).ok_or_else(invalid)?;
        let (thresholds, padding) = cosigner
            .thresholds
            .split_at_checked(usize::from(cosigner.threshold_count))
            .ok_or_else(invalid)?;
        if cosigner.bump != pda.bump
            || cosigner.signer == Address::default()
            || padding
                .iter()
                .any(|row| row.mint != Address::default() || row.amount() != 0)
            || thresholds.iter().enumerate().any(|(index, row)| {
                thresholds[..index]
                    .iter()
                    .any(|earlier| earlier.mint == row.mint)
            })
        {
            return Err(invalid());
        }
        Ok(Some(CustomRingCoSigner {
            signer: cosigner.signer,
            scope,
            thresholds: thresholds
                .iter()
                .map(|row| CoSignThreshold {
                    mint: row.mint,
                    amount: row.amount(),
                })
                .collect(),
        }))
    }

    /// `None` when the ring has no delegate.
    pub fn read_delegate<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingDelegate>, AccountReadError> {
        let pda = self.delegate_pda_with_bump();
        self.decode_delegate(pda, rpc.get_account(pda.address)?)
    }

    /// The async twin of [`Self::read_delegate`], over [`AsyncRpc`].
    pub async fn read_delegate_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingDelegate>, AccountReadError> {
        let pda = self.delegate_pda_with_bump();
        self.decode_delegate(pda, rpc.get_account(pda.address).await?)
    }

    fn decode_delegate(
        self,
        pda: Pda,
        account: Option<Account>,
    ) -> Result<Option<CustomRingDelegate>, AccountReadError> {
        let Some(delegate) =
            AccountRead::decode_optional::<Delegate>(self.program_id, pda.address, account)?
        else {
            return Ok(None);
        };
        if delegate.bump != pda.bump || delegate.delegate == Address::default() {
            return Err(AccountReadError::InvalidAccount {
                address: pda.address,
            });
        }
        Ok(Some(CustomRingDelegate {
            delegate: delegate.delegate,
        }))
    }

    pub fn key_registry_root_pda(self) -> Address {
        self.key_registry_root_pda_with_bump().address
    }

    fn key_registry_root_pda_with_bump(self) -> Pda {
        ring_pda::key_registry_root(&self.program_id).into()
    }

    /// `None` until the authority creates the registry root.
    pub fn read_key_registry_root<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CurrentKeyRegistryRoot>, AccountReadError> {
        let pda = self.key_registry_root_pda_with_bump();
        self.decode_key_registry_root(pda, rpc.get_account(pda.address)?)
    }

    /// The async twin of [`Self::read_key_registry_root`], over [`AsyncRpc`].
    pub async fn read_key_registry_root_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CurrentKeyRegistryRoot>, AccountReadError> {
        let pda = self.key_registry_root_pda_with_bump();
        self.decode_key_registry_root(pda, rpc.get_account(pda.address).await?)
    }

    /// `None` when the mint is uncapped.
    pub fn read_spend_window<R: Rpc>(
        self,
        rpc: &R,
        mint: &Address,
    ) -> Result<Option<CustomRingSpendWindow>, AccountReadError> {
        let pda = self.spend_window_pda_with_bump(mint);
        self.decode_spend_window(pda, rpc.get_account(pda.address)?)
    }

    /// The async twin of [`Self::read_spend_window`], over [`AsyncRpc`].
    pub async fn read_spend_window_async<R: AsyncRpc>(
        self,
        rpc: &R,
        mint: &Address,
    ) -> Result<Option<CustomRingSpendWindow>, AccountReadError> {
        let pda = self.spend_window_pda_with_bump(mint);
        self.decode_spend_window(pda, rpc.get_account(pda.address).await?)
    }

    fn decode_spend_window(
        self,
        pda: Pda,
        account: Option<Account>,
    ) -> Result<Option<CustomRingSpendWindow>, AccountReadError> {
        let Some(window) =
            AccountRead::decode_optional::<SpendWindow>(self.program_id, pda.address, account)?
        else {
            return Ok(None);
        };
        if window.bump != pda.bump
            || window.window_slots() == 0
            || self.spend_window_pda(&window.mint) != pda.address
        {
            return Err(AccountReadError::InvalidAccount {
                address: pda.address,
            });
        }
        Ok(Some(CustomRingSpendWindow {
            mint: window.mint,
            window_slots: window.window_slots(),
            deposit_cap: window.deposit_cap(),
            withdrawal_cap: window.withdrawal_cap(),
            window_start_slot: window.window_start_slot(),
            deposited: window.deposited(),
            withdrawn: window.withdrawn(),
        }))
    }

    pub fn read_policy_config<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<PolicyConfig>, AccountReadError> {
        let address = self.policy_config_pda();
        self.decode_policy_config(address, rpc.get_account(address)?)
    }

    pub fn read_pinned_policy<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<PinnedPolicy>, PolicyMatchError> {
        self.read_policy_config(rpc)?.map(pinned_policy).transpose()
    }

    pub async fn read_pinned_policy_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<PinnedPolicy>, PolicyMatchError> {
        self.read_policy_config_async(rpc)
            .await?
            .map(pinned_policy)
            .transpose()
    }

    /// The async twin of [`Self::read_policy_config`], over [`AsyncRpc`].
    pub async fn read_policy_config_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<PolicyConfig>, AccountReadError> {
        let address = self.policy_config_pda();
        self.decode_policy_config(address, rpc.get_account(address).await?)
    }

    fn decode_policy_config(
        self,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<PolicyConfig>, AccountReadError> {
        let Some(config) = AccountRead::decode::<PolicyConfig>(self.program_id, address, account)?
        else {
            return Ok(None);
        };
        let bump = Address::find_program_address(&[PolicyConfig::SEED], &self.program_id).1;
        if config.bump != bump {
            return Err(AccountReadError::InvalidAccount { address });
        }
        Ok(Some(config))
    }

    pub fn read_access_record<R: Rpc>(
        self,
        rpc: &R,
        reader: &ReaderKey,
    ) -> Result<Option<ReadAccessRecord>, AccountReadError> {
        let address = self.read_access_record_pda(reader);
        let Some(record) = AccountRead::decode::<ReadAccessRecord>(
            self.program_id,
            address,
            rpc.get_account(address)?,
        )?
        else {
            return Ok(None);
        };
        let reader_bytes = reader.to_bytes();
        let seed_hash = ReadAccessRecord::seed_hash(&reader_bytes)
            .map_err(|_| AccountReadError::InvalidAccount { address })?;
        let bump =
            Address::find_program_address(&[ReadAccessRecord::SEED, &seed_hash], &self.program_id)
                .1;
        if record.reader != reader_bytes || record.bump != bump {
            return Err(AccountReadError::InvalidAccount { address });
        }
        Ok(Some(record))
    }

    /// Owned by SPP, not by the ring program.
    pub fn read_spp_ring_config<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<RingConfig>, AccountReadError> {
        let address = self.ring_auth_pda();
        let Some(account) = rpc.get_account(address)? else {
            return Ok(None);
        };
        let invalid = || AccountReadError::InvalidAccount { address };
        if account.owner.to_bytes() != pda::shielded_pool_program_id().to_bytes()
            || account.data.len() != RingConfig::SIZE
        {
            return Err(invalid());
        }
        let config =
            bytemuck::try_from_bytes::<RingConfig>(&account.data).map_err(|_| invalid())?;
        let bump = Address::find_program_address(&[RING_AUTH_PDA_SEED], &self.program_id).1;
        if !config.has_discriminator()
            || config.program_id != self.program_id
            || config.bump != bump
        {
            return Err(invalid());
        }
        Ok(Some(*config))
    }
}

/// The stored table, trusted once its rows reproduce the pinned hash.
pub fn policy_config_table(config: &PolicyConfig) -> Result<RuleTable, PolicyMatchError> {
    let table = config.rule_table()?;
    check_pinned_hash(config)?;
    Ok(table)
}

fn pinned_policy(config: PolicyConfig) -> Result<PinnedPolicy, PolicyMatchError> {
    Ok(PinnedPolicy {
        table: policy_config_table(&config)?,
        config,
    })
}

pub fn client_rules_match(
    rules: &RuleTable,
    config: &PolicyConfig,
) -> Result<(), PolicyMatchError> {
    if rules.encode() != config.rules {
        return Err(PolicyMatchError::TableMismatch);
    }
    check_pinned_hash(config)
}

/// The map the pinned hash binds, each stored namespace hashed to its owner.
pub(crate) fn source_map(config: &PolicyConfig) -> Result<SourceMap, PolicyMatchError> {
    let mut slots = [SourceOwner::default(); MAX_SOURCES];
    for (slot, stored) in slots.iter_mut().zip(&config.sources) {
        if stored.list_id == 0 {
            continue;
        }
        let owner = ListNamespace::new(stored.namespace.as_array())
            .map_err(|_| PolicyMatchError::Hashing)?;
        *slot = SourceOwner {
            list_id: stored.list_id,
            owner_hash: owner.owner_hash,
        };
    }
    SourceMap::from_slots(slots).map_err(|_| PolicyMatchError::InvalidSources)
}

fn check_pinned_hash(config: &PolicyConfig) -> Result<(), PolicyMatchError> {
    if config.rules.hash(&source_map(config)?)? != config.policy_hash {
        return Err(PolicyMatchError::HashMismatch);
    }
    Ok(())
}

trait ReadableAccount: Pod + Copy {
    const DISCRIMINATOR: u8;

    fn discriminator(self) -> u8;
}

impl ReadableAccount for RingProgramConfig {
    const DISCRIMINATOR: u8 = RING_PROGRAM_CONFIG;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for PolicyConfig {
    const DISCRIMINATOR: u8 = POLICY_CONFIG;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for ReadAccessRecord {
    const DISCRIMINATOR: u8 = READ_ACCESS_RECORD;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for CoSigner {
    const DISCRIMINATOR: u8 = CO_SIGNER;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for DepositAudit {
    const DISCRIMINATOR: u8 = DEPOSIT_AUDIT;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for Delegate {
    const DISCRIMINATOR: u8 = DELEGATE;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for SpendWindow {
    const DISCRIMINATOR: u8 = SPEND_WINDOW;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

impl ReadableAccount for KeyRegistryRoot {
    const DISCRIMINATOR: u8 = KEY_REGISTRY_ROOT;

    fn discriminator(self) -> u8 {
        self.discriminator
    }
}

struct AccountRead;

impl AccountRead {
    /// Shared by both transports: only fetching the account differs.
    fn decode<T: ReadableAccount>(
        program_id: Address,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<T>, AccountReadError> {
        let Some(account) = account else {
            return Ok(None);
        };
        if account.owner.to_bytes() != *program_id.as_array()
            || account.data.len() != core::mem::size_of::<T>()
        {
            return Err(AccountReadError::InvalidAccount { address });
        }
        let value = bytemuck::try_from_bytes::<T>(&account.data)
            .map_err(|_| AccountReadError::InvalidAccount { address })?;
        if value.discriminator() != T::DISCRIMINATOR {
            return Err(AccountReadError::InvalidAccount { address });
        }
        Ok(Some(*value))
    }

    /// An empty account reads as unconfigured, the program's own rule.
    fn decode_optional<T: ReadableAccount>(
        program_id: Address,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<T>, AccountReadError> {
        match account {
            Some(account) if account.data.is_empty() => Ok(None),
            other => Self::decode(program_id, address, other),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;
    use custom_ring_interface::{
        ReadAccessRecord, RingProgramConfig, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG,
    };
    use solana_account::Account;
    use solana_pubkey::Pubkey;
    use zolana_interface::P_DERIVE_SEC1;
    use zolana_keypair::ViewingKey;
    use zolana_ring_policy::{ListSet, Rule, Subject, MAX_RULES};

    use super::*;

    struct AccountRpc {
        address: Address,
        account: Option<Account>,
    }

    type Mutation<T> = (&'static str, fn(&mut T));

    impl Rpc for AccountRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            assert_eq!(address, self.address);
            Ok(self.account.clone())
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for AccountRpc {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Rpc::get_account(self, address)
        }
    }

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([42u8; 32]))
    }

    fn account<T: Pod>(value: &T) -> Account {
        Account {
            lamports: 1,
            data: bytemuck::bytes_of(value).to_vec(),
            owner: Pubkey::new_from_array(ring().program_id().to_bytes()),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn config() -> RingProgramConfig {
        RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority: Address::new_from_array([3u8; 32]),
            auditor_pubkey: *ViewingKey::new().pubkey().as_bytes(),
            bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring().program_id()).1,
            has_policy: 1,
            key_escrow: 0,
        }
    }

    fn config_rpc(value: RingProgramConfig) -> AccountRpc {
        AccountRpc {
            address: ring().config_pda(),
            account: Some(account(&value)),
        }
    }

    #[test]
    fn deposit_audit_defaults_off_and_rejects_malformed_state() {
        let address = ring().deposit_audit_pda();
        let read = |account| ring().read_deposit_audit(&AccountRpc { address, account });
        assert!(!read(None).unwrap());
        assert!(!read(Some(Account::default())).unwrap());
        let bump = Address::find_program_address(&[DepositAudit::SEED], &ring().program_id()).1;
        let value = DepositAudit {
            discriminator: DEPOSIT_AUDIT,
            required: 1,
            bump,
        };
        assert!(read(Some(account(&value))).unwrap());
        assert!(!read(Some(account(&DepositAudit {
            required: 0,
            ..value
        })))
        .unwrap());
        let foreign = Account {
            owner: Address::new_from_array([99; 32]),
            ..Account::default()
        };
        let mut wrong_owner = account(&value);
        wrong_owner.owner = Address::default();
        let mut truncated = account(&value);
        truncated.data.pop();
        for invalid in [
            foreign,
            wrong_owner,
            truncated,
            account(&DepositAudit {
                required: 2,
                ..value
            }),
            account(&DepositAudit {
                discriminator: 0,
                ..value
            }),
            account(&DepositAudit {
                bump: bump ^ 1,
                ..value
            }),
        ] {
            assert!(matches!(
                read(Some(invalid)),
                Err(AccountReadError::InvalidAccount { .. })
            ));
        }
    }

    #[test]
    fn config_read_accepts_only_canonical_typed_state() {
        let missing = AccountRpc {
            address: ring().config_pda(),
            account: None,
        };
        assert!(ring()
            .read_config(&missing)
            .expect("missing config")
            .is_none());

        let value = config();
        let read = ring()
            .read_config(&config_rpc(value))
            .expect("valid config")
            .expect("config");
        assert_eq!(read.authority, value.authority);
        assert_eq!(read.auditor_pubkey.as_bytes(), &value.auditor_pubkey);

        let mut wrong_owner = account(&value);
        wrong_owner.owner = Pubkey::new_from_array([9u8; 32]);
        let mut wrong_size = account(&value);
        wrong_size.data.pop();
        let mut wrong_discriminator = value;
        wrong_discriminator.discriminator = 0;
        let mut wrong_bump = value;
        wrong_bump.bump ^= 1;
        let mut invalid_key = value;
        invalid_key.auditor_pubkey = [0u8; 33];
        let mut reserved_key = value;
        reserved_key.auditor_pubkey = P_DERIVE_SEC1;

        let invalid = [
            AccountRpc {
                address: ring().config_pda(),
                account: Some(wrong_owner),
            },
            AccountRpc {
                address: ring().config_pda(),
                account: Some(wrong_size),
            },
            config_rpc(wrong_discriminator),
            config_rpc(wrong_bump),
            config_rpc(invalid_key),
            config_rpc(reserved_key),
        ];
        for rpc in invalid {
            assert!(matches!(
                ring().read_config(&rpc),
                Err(AccountReadError::InvalidAccount { .. })
            ));
        }
    }

    #[test]
    fn reader_read_rejects_substituted_state() {
        let reader = ReaderKey::p256(ViewingKey::new().pubkey()).expect("reader");
        let address = ring().read_access_record_pda(&reader);
        let reader_bytes = reader.to_bytes();
        let seed_hash = ReadAccessRecord::seed_hash(&reader_bytes).expect("seed hash");
        let value = ReadAccessRecord {
            discriminator: READ_ACCESS_RECORD,
            reader: reader_bytes,
            bump: Address::find_program_address(
                &[ReadAccessRecord::SEED, &seed_hash],
                &ring().program_id(),
            )
            .1,
        };
        let valid = AccountRpc {
            address,
            account: Some(account(&value)),
        };
        assert_eq!(
            ring()
                .read_access_record(&valid, &reader)
                .expect("valid reader")
                .expect("reader"),
            value
        );

        let mut wrong_reader = value;
        wrong_reader.reader[1] ^= 1;
        let mut wrong_bump = value;
        wrong_bump.bump ^= 1;
        for value in [wrong_reader, wrong_bump] {
            let rpc = AccountRpc {
                address,
                account: Some(account(&value)),
            };
            assert!(matches!(
                ring().read_access_record(&rpc, &reader),
                Err(AccountReadError::InvalidAccount { .. })
            ));
        }
    }

    const PINNED: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Block))
        .build();

    /// Every referenced list reads the ring's own entries.
    fn pinned(table: &RuleTable) -> PolicyConfig {
        let mut sources = [SourceSlot {
            list_id: 0,
            namespace: Address::default(),
        }; N_SOURCE_SLOTS];
        for list_id in table.referenced().iter() {
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                namespace: ring().namespace_pda(),
            };
        }
        let mut config = PolicyConfig {
            discriminator: POLICY_CONFIG,
            policy_hash: [0; 32],
            address_tree: Address::new_from_array([5u8; 32]),
            address_tree_id: [0; 2],
            namespace_bump: 0,
            namespace_owner_hash: [0u8; 32],
            bump: Address::find_program_address(&[PolicyConfig::SEED], &ring().program_id()).1,
            sources,
            rules: table.encode(),
            generation: 1u32.to_le_bytes(),
            generation_slot: [0; 8],
        };
        config.policy_hash = config
            .rules
            .hash(&source_map(&config).expect("map"))
            .expect("hash");
        config
    }

    #[test]
    fn cosigner_read_rejects_invalid_threshold_count() {
        let mut value = cosigner();
        value.threshold_count = u8::MAX;
        let address = ring().cosigner_pda();
        let rpc = AccountRpc {
            address,
            account: Some(account(&value)),
        };
        assert!(matches!(
            ring().read_cosigner(&rpc),
            Err(AccountReadError::InvalidAccount { address: invalid }) if invalid == address
        ));
    }

    fn cosigner() -> CoSigner {
        CoSigner {
            discriminator: CO_SIGNER,
            signer: Address::new_from_array([45; 32]),
            scope: CoSignScope::WITHDRAWALS.bits(),
            bump: ring().cosigner_pda_with_bump().bump,
            ..CoSigner::zeroed()
        }
    }

    #[test]
    fn cosigner_read_rejects_noncanonical_fields() {
        let cases: [Mutation<CoSigner>; 7] = [
            ("zero signer", |value| value.signer = Address::default()),
            ("empty scope", |value| value.scope = 0),
            ("unsupported scope", |value| value.scope = 8),
            ("too many thresholds", |value| value.threshold_count = 9),
            ("duplicate mint", |value| value.threshold_count = 2),
            ("mint in padding", |value| {
                value.thresholds[1].mint = Address::new_from_array([1; 32]);
            }),
            ("amount in padding", |value| {
                value.thresholds[1].amount = 1_u64.to_le_bytes();
            }),
        ];
        let address = ring().cosigner_pda();
        for (name, change) in cases {
            let mut value = cosigner();
            value.threshold_count = 1;
            change(&mut value);
            let rpc = AccountRpc {
                address,
                account: Some(account(&value)),
            };
            for result in [
                ring().read_cosigner(&rpc),
                futures::executor::block_on(ring().read_cosigner_async(&rpc)),
            ] {
                assert!(
                    matches!(result, Err(AccountReadError::InvalidAccount { address: invalid }) if invalid == address),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn cosigner_read_preserves_valid_thresholds_and_scope() {
        let mut value = cosigner();
        value.scope = CoSignScope::ALL.bits();
        value.threshold_count = value.thresholds.len() as u8;
        for (index, row) in value.thresholds.iter_mut().enumerate() {
            row.mint = Address::new_from_array([index as u8; 32]);
            row.amount = if index == 0 { 0 } else { u64::MAX }.to_le_bytes();
        }
        let expected = CustomRingCoSigner {
            signer: value.signer,
            scope: CoSignScope::ALL,
            thresholds: value
                .thresholds()
                .iter()
                .map(|row| CoSignThreshold {
                    mint: row.mint,
                    amount: row.amount(),
                })
                .collect(),
        };
        let rpc = AccountRpc {
            address: ring().cosigner_pda(),
            account: Some(account(&value)),
        };
        for result in [
            ring().read_cosigner(&rpc),
            futures::executor::block_on(ring().read_cosigner_async(&rpc)),
        ] {
            assert_eq!(result.expect("valid co-signer"), Some(expected.clone()));
        }
    }

    #[test]
    fn optional_control_readers_reject_malformed_accounts() {
        let mint = Address::new_from_array([60; 32]);
        let controls = [
            (ring().cosigner_pda(), account(&cosigner())),
            (
                ring().delegate_pda(),
                account(&Delegate {
                    discriminator: DELEGATE,
                    delegate: Address::new_from_array([47; 32]),
                    bump: ring().delegate_pda_with_bump().bump,
                }),
            ),
            (
                ring().spend_window_pda(&mint),
                account(&SpendWindow {
                    discriminator: SPEND_WINDOW,
                    mint,
                    window_slots: 100_u64.to_le_bytes(),
                    bump: ring().spend_window_pda_with_bump(&mint).bump,
                    ..SpendWindow::zeroed()
                }),
            ),
        ];
        let changes: [Mutation<Account>; 5] = [
            ("foreign owner", |account| {
                account.owner = Address::new_from_array([99; 32]);
            }),
            ("truncated", |account| {
                account.data.pop();
            }),
            ("oversized", |account| account.data.push(0)),
            ("wrong discriminator", |account| account.data[0] ^= 1),
            ("wrong bump", |account| {
                *account.data.last_mut().expect("bump") ^= 1;
            }),
        ];
        for (address, valid) in controls {
            let read = |account| {
                let rpc = AccountRpc { address, account };
                let sync = match valid.data[0] {
                    CO_SIGNER => ring().read_cosigner(&rpc).map(|value| value.is_some()),
                    DELEGATE => ring().read_delegate(&rpc).map(|value| value.is_some()),
                    SPEND_WINDOW => ring()
                        .read_spend_window(&rpc, &mint)
                        .map(|value| value.is_some()),
                    _ => unreachable!(),
                };
                let asynchronous = futures::executor::block_on(async {
                    match valid.data[0] {
                        CO_SIGNER => ring()
                            .read_cosigner_async(&rpc)
                            .await
                            .map(|value| value.is_some()),
                        DELEGATE => ring()
                            .read_delegate_async(&rpc)
                            .await
                            .map(|value| value.is_some()),
                        SPEND_WINDOW => ring()
                            .read_spend_window_async(&rpc, &mint)
                            .await
                            .map(|value| value.is_some()),
                        _ => unreachable!(),
                    }
                });
                [sync, asynchronous]
            };
            for result in read(Some(valid.clone())) {
                assert!(result.expect("valid control"));
            }
            for account in [
                None,
                Some(empty([0; 32])),
                Some(empty(ring().program_id().to_bytes())),
            ] {
                for result in read(account) {
                    assert!(!result.expect("unconfigured control"));
                }
            }
            for (name, change) in changes {
                let mut value = valid.clone();
                change(&mut value);
                for result in read(Some(value)) {
                    assert!(
                        matches!(result, Err(AccountReadError::InvalidAccount { address: invalid }) if invalid == address),
                        "{name} for {}",
                        valid.data[0]
                    );
                }
            }
        }
    }

    #[test]
    fn delegate_read_rejects_substituted_state() {
        let key = Address::new_from_array([47; 32]);
        let address = ring().delegate_pda();
        let value = Delegate {
            discriminator: DELEGATE,
            delegate: key,
            bump: ring().delegate_pda_with_bump().bump,
        };
        let valid = AccountRpc {
            address,
            account: Some(account(&value)),
        };
        assert_eq!(
            ring()
                .read_delegate(&valid)
                .expect("valid delegate")
                .expect("delegate"),
            CustomRingDelegate { delegate: key }
        );
        let mut wrong_bump = value;
        wrong_bump.bump ^= 1;
        let mut zero_key = value;
        zero_key.delegate = Address::default();
        for value in [wrong_bump, zero_key] {
            let rpc = AccountRpc {
                address,
                account: Some(account(&value)),
            };
            assert!(matches!(
                ring().read_delegate(&rpc),
                Err(AccountReadError::InvalidAccount { .. })
            ));
        }
    }

    #[test]
    fn spend_window_read_rejects_substituted_state() {
        let mint = Address::new_from_array([60; 32]);
        let address = ring().spend_window_pda(&mint);
        let value = SpendWindow {
            discriminator: SPEND_WINDOW,
            mint,
            window_slots: 100u64.to_le_bytes(),
            deposit_cap: 7u64.to_le_bytes(),
            withdrawal_cap: 0u64.to_le_bytes(),
            window_start_slot: 1200u64.to_le_bytes(),
            deposited: 1u64.to_le_bytes(),
            withdrawn: 0u64.to_le_bytes(),
            bump: ring().spend_window_pda_with_bump(&mint).bump,
        };
        let valid = AccountRpc {
            address,
            account: Some(account(&value)),
        };
        assert_eq!(
            ring()
                .read_spend_window(&valid, &mint)
                .expect("valid window")
                .expect("window"),
            CustomRingSpendWindow {
                mint,
                window_slots: 100,
                deposit_cap: 7,
                withdrawal_cap: 0,
                window_start_slot: 1200,
                deposited: 1,
                withdrawn: 0,
            }
        );

        let mut wrong_mint = value;
        wrong_mint.mint = Address::new_from_array([61; 32]);
        let mut wrong_bump = value;
        wrong_bump.bump ^= 1;
        let mut zero_window = value;
        zero_window.window_slots = [0; 8];
        for value in [wrong_mint, wrong_bump, zero_window] {
            let rpc = AccountRpc {
                address,
                account: Some(account(&value)),
            };
            assert!(matches!(
                ring().read_spend_window(&rpc, &mint),
                Err(AccountReadError::InvalidAccount { .. })
            ));
        }
    }

    #[test]
    fn the_stored_table_is_trusted_only_under_its_pinned_hash() {
        let config = pinned(&PINNED);
        assert_eq!(policy_config_table(&config).expect("table"), PINNED);
        client_rules_match(&PINNED, &config).expect("match");

        let mut hash_drift = config;
        hash_drift.policy_hash[0] ^= 1;
        assert!(matches!(
            policy_config_table(&hash_drift),
            Err(PolicyMatchError::HashMismatch)
        ));
        assert!(matches!(
            client_rules_match(&PINNED, &hash_drift),
            Err(PolicyMatchError::HashMismatch)
        ));

        let mut row_drift = config;
        row_drift.rules.rules[1][29] = ListSet::single(ListId::Frozen).bits();
        assert!(matches!(
            client_rules_match(&PINNED, &row_drift),
            Err(PolicyMatchError::TableMismatch)
        ));
        let shorter = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .build();
        assert!(matches!(
            client_rules_match(&shorter, &config),
            Err(PolicyMatchError::TableMismatch)
        ));

        let mut padded = config;
        padded.rules.rules[MAX_RULES - 1] = [1u8; 32];
        assert!(matches!(
            policy_config_table(&padded),
            Err(PolicyMatchError::Rules(RuleTableError::NonZeroPadding))
        ));

        let mut unsourced = config;
        unsourced.sources[ListId::Block.slot()] = SourceSlot {
            list_id: 0,
            namespace: Address::default(),
        };
        assert!(matches!(
            policy_config_table(&unsourced),
            Err(PolicyMatchError::MissingSource(ListId::Block))
        ));
    }

    fn empty(owner: [u8; 32]) -> Account {
        Account {
            lamports: 1,
            data: Vec::new(),
            owner: Pubkey::new_from_array(owner),
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn an_optional_control_reads_unconfigured_for_an_empty_pda() {
        let mint = Address::new_from_array([7u8; 32]);
        for (address, account) in [
            (ring().cosigner_pda(), empty(ring().program_id().to_bytes())),
            (ring().delegate_pda(), empty(ring().program_id().to_bytes())),
            (ring().spend_window_pda(&mint), empty([0u8; 32])),
        ] {
            let rpc = AccountRpc {
                address,
                account: Some(account),
            };
            let read = if address == ring().spend_window_pda(&mint) {
                ring().read_spend_window(&rpc, &mint).map(|w| w.is_none())
            } else if address == ring().delegate_pda() {
                ring().read_delegate(&rpc).map(|d| d.is_none())
            } else {
                ring().read_cosigner(&rpc).map(|c| c.is_none())
            };
            assert!(read.expect("empty control"));
        }

        // A nonempty malformed account stays strict.
        let truncated = AccountRpc {
            address: ring().cosigner_pda(),
            account: Some(Account {
                lamports: 1,
                data: vec![0u8; 4],
                owner: Pubkey::new_from_array(ring().program_id().to_bytes()),
                executable: false,
                rent_epoch: 0,
            }),
        };
        assert!(ring().read_cosigner(&truncated).is_err());
    }
}
