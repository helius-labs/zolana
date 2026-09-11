//! Addresses the client shares across instruction builders.

use bytemuck::Pod;
use custom_ring_interface::{
    CoSigner, Delegate, PolicyConfig, ReadAccessRecord, RingProgramConfig, SpendWindow, CO_SIGNER,
    DELEGATE, POLICY_CONFIG, READ_ACCESS_RECORD, RING_PROGRAM_CONFIG, SPEND_WINDOW,
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
}

/// The ring's second signature, `scope` is a subset of the `COSIGN_*` bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingCoSigner {
    pub signer: Address,
    pub scope: u8,
    /// Per mint, SOL under the zero address.
    pub thresholds: Vec<(Address, u64)>,
}

/// The key that moves notes between members on the authority rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomRingDelegate {
    pub delegate: Address,
}

/// A mint's public-leg caps over fixed windows, zero caps do not bind.
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
    #[error("the ring has no policy config")]
    NoPolicy,
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
        Address::find_program_address(&[CoSigner::SEED], &self.program_id).0
    }

    pub fn delegate_pda(self) -> Address {
        self.delegate_pda_with_bump().0
    }

    fn delegate_pda_with_bump(self) -> (Address, u8) {
        Address::find_program_address(&[Delegate::SEED], &self.program_id)
    }

    /// SOL under the zero address.
    pub fn spend_window_pda(self, mint: &Address) -> Address {
        self.spend_window_pda_with_bump(mint).0
    }

    fn spend_window_pda_with_bump(self, mint: &Address) -> (Address, u8) {
        Address::find_program_address(&[SpendWindow::SEED, mint.as_array()], &self.program_id)
    }

    pub fn read_access_record_pda(self, reader: &ReaderKey) -> Address {
        reader.entry_address(&self.program_id)
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
        }))
    }

    /// `None` when the ring has no co-signer.
    pub fn read_cosigner<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingCoSigner>, AccountReadError> {
        let address = self.cosigner_pda();
        self.decode_cosigner(address, rpc.get_account(address)?)
    }

    /// The async twin of [`Self::read_cosigner`], over [`AsyncRpc`].
    pub async fn read_cosigner_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingCoSigner>, AccountReadError> {
        let address = self.cosigner_pda();
        self.decode_cosigner(address, rpc.get_account(address).await?)
    }

    fn decode_cosigner(
        self,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<CustomRingCoSigner>, AccountReadError> {
        let Some(cosigner) = AccountRead::decode::<CoSigner>(self.program_id, address, account)?
        else {
            return Ok(None);
        };
        let bump = Address::find_program_address(&[CoSigner::SEED], &self.program_id).1;
        if cosigner.bump != bump {
            return Err(AccountReadError::InvalidAccount { address });
        }
        Ok(Some(CustomRingCoSigner {
            signer: cosigner.signer,
            scope: cosigner.scope,
            thresholds: cosigner
                .thresholds()
                .iter()
                .map(|row| (row.mint, row.amount()))
                .collect(),
        }))
    }

    /// `None` when the ring has no delegate.
    pub fn read_delegate<R: Rpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingDelegate>, AccountReadError> {
        let address = self.delegate_pda();
        self.decode_delegate(address, rpc.get_account(address)?)
    }

    /// The async twin of [`Self::read_delegate`], over [`AsyncRpc`].
    pub async fn read_delegate_async<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<CustomRingDelegate>, AccountReadError> {
        let address = self.delegate_pda();
        self.decode_delegate(address, rpc.get_account(address).await?)
    }

    fn decode_delegate(
        self,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<CustomRingDelegate>, AccountReadError> {
        let Some(delegate) = AccountRead::decode::<Delegate>(self.program_id, address, account)?
        else {
            return Ok(None);
        };
        if delegate.bump != self.delegate_pda_with_bump().1
            || delegate.delegate == Address::default()
        {
            return Err(AccountReadError::InvalidAccount { address });
        }
        Ok(Some(CustomRingDelegate {
            delegate: delegate.delegate,
        }))
    }

    /// `None` when the mint is uncapped.
    pub fn read_spend_window<R: Rpc>(
        self,
        rpc: &R,
        mint: &Address,
    ) -> Result<Option<CustomRingSpendWindow>, AccountReadError> {
        let address = self.spend_window_pda(mint);
        self.decode_spend_window(mint, address, rpc.get_account(address)?)
    }

    /// The async twin of [`Self::read_spend_window`], over [`AsyncRpc`].
    pub async fn read_spend_window_async<R: AsyncRpc>(
        self,
        rpc: &R,
        mint: &Address,
    ) -> Result<Option<CustomRingSpendWindow>, AccountReadError> {
        let address = self.spend_window_pda(mint);
        self.decode_spend_window(mint, address, rpc.get_account(address).await?)
    }

    fn decode_spend_window(
        self,
        mint: &Address,
        address: Address,
        account: Option<Account>,
    ) -> Result<Option<CustomRingSpendWindow>, AccountReadError> {
        let Some(window) = AccountRead::decode::<SpendWindow>(self.program_id, address, account)?
        else {
            return Ok(None);
        };
        let bump = self.spend_window_pda_with_bump(mint).1;
        if window.mint != *mint || window.bump != bump || window.window_slots() == 0 {
            return Err(AccountReadError::InvalidAccount { address });
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

    pub fn verify_client_rules<R: Rpc>(
        self,
        rpc: &R,
        rules: &RuleTable,
    ) -> Result<(), PolicyMatchError> {
        let config = self
            .read_policy_config(rpc)?
            .ok_or(PolicyMatchError::NoPolicy)?;
        client_rules_match(rules, &config)
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
}

#[cfg(test)]
mod tests {
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

    impl Rpc for AccountRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            assert_eq!(address, self.address);
            Ok(self.account.clone())
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
        }
    }

    fn config_rpc(value: RingProgramConfig) -> AccountRpc {
        AccountRpc {
            address: ring().config_pda(),
            account: Some(account(&value)),
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
            entries_tree: Address::new_from_array([5u8; 32]),
            entries_tree_id: [0; 2],
            namespace_bump: 0,
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
    fn delegate_read_rejects_substituted_state() {
        let key = Address::new_from_array([47; 32]);
        let address = ring().delegate_pda();
        let value = Delegate {
            discriminator: DELEGATE,
            delegate: key,
            bump: ring().delegate_pda_with_bump().1,
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
            bump: ring().spend_window_pda_with_bump(&mint).1,
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

    #[test]
    fn verify_client_rules_reads_the_pinned_config() {
        let config = pinned(&PINNED);
        let rpc = AccountRpc {
            address: ring().policy_config_pda(),
            account: Some(account(&config)),
        };
        ring()
            .verify_client_rules(&rpc, &PINNED)
            .expect("pinned table");
        let missing = AccountRpc {
            address: ring().policy_config_pda(),
            account: None,
        };
        assert!(matches!(
            ring().verify_client_rules(&missing, &PINNED),
            Err(PolicyMatchError::NoPolicy)
        ));
    }
}
