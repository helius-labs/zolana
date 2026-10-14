//! Fixtures the unit tests share: notes, accounts, a pinned policy and lineage mocks.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use bytemuck::Pod;
use custom_ring_interface::{PolicyConfig, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG};
use solana_account::Account;
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, ClientError, Context,
    IndexerRpcConfig, OutputContext, OutputSlot, ShieldedTransaction,
};
use zolana_interface::{
    state::{default_tree_fees, discriminator::TREE_ACCOUNT_DISCRIMINATOR, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, NullifierKey, ShieldedKeypair};
use zolana_ring_policy::{
    entry_nullifier, EntryState, ListEntry, ListId, ListNamespace, Member, RuleTable,
};
use zolana_transaction::{utxo::SppProofInputUtxo, Data, Mint, Utxo, WalletUtxo};
use zolana_tree::TreeAccount;

use crate::{
    account::source_map,
    entry::{EntryLookup, LineageLookup},
    CustomRing, LiveEntry, PoolTree,
};

/// An indexer the tests never ask for input witnesses.
macro_rules! no_witnesses {
    ($($ty:ty),*) => {$(
        impl zolana_client::AsyncWitnessReader for $ty {
            fn input_witnesses(
                &self,
                _inputs: &[&zolana_transaction::utxo::SppProofInputUtxo],
                _dummy_nullifiers: &[[u8; 32]],
                _config: Option<zolana_client::IndexerRpcConfig>,
            ) -> impl std::future::Future<
                Output = Result<zolana_client::InputWitnesses, zolana_client::ClientError>,
            > + Send {
                std::future::ready(Err(zolana_client::ClientError::NoInputs))
            }
        }
    )*};
}
pub(crate) use no_witnesses;

pub(crate) fn ring() -> CustomRing {
    CustomRing::new(Address::new_from_array([42; 32]))
}

/// An indexed note with its committed hashes, as a wallet scan returns it.
pub(crate) fn wallet(
    utxo: Utxo,
    key: &NullifierKey,
    tree_id: u16,
    leaf_index: u64,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
) -> WalletUtxo {
    let nullifier_pubkey = key.pubkey().unwrap();
    let utxo_hash = utxo
        .hash(
            &nullifier_pubkey,
            &data_hash.unwrap_or_default(),
            &ring_data_hash.unwrap_or_default(),
            tree_id,
        )
        .unwrap();
    WalletUtxo {
        nullifier: key.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        data_hash,
        ring_data_hash,
        tree_id,
        leaf_index,
        slot: 0,
        tx_signature: Default::default(),
        slot_index: 0,
    }
}

/// A SOL note of `owner` with its leaf in `tree_id`.
pub(crate) fn note(
    owner: &ShieldedKeypair,
    amount: u64,
    tree_id: u16,
    ring: Option<Address>,
) -> WalletUtxo {
    wallet(
        Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount,
            blinding: random_blinding(),
            ring_program_id: ring,
            data: Data::default(),
        },
        &owner.nullifier_key,
        tree_id,
        0,
        None,
        None,
    )
}

pub(crate) fn input(
    owner: &ShieldedKeypair,
    amount: u64,
    tree_id: u16,
    ring: Option<Address>,
) -> SppProofInputUtxo {
    note(owner, amount, tree_id, ring).into()
}

pub(crate) fn account<T: Pod>(owner: Address, value: &T) -> Account {
    Account {
        lamports: 1,
        data: bytemuck::bytes_of(value).to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

pub(crate) fn empty(owner: Address) -> Account {
    Account {
        lamports: 1,
        data: Vec::new(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

pub(crate) fn tree_account(tree: PoolTree) -> Account {
    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        32,
        tree.address.to_bytes(),
        tree.id,
        params,
        default_tree_fees(params.input_queue_zkp_batch_size).unwrap(),
    )
    .unwrap();
    Account {
        lamports: 1,
        data,
        owner: Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

/// `table` pinned under its own hash at the ring's canonical bump.
pub(crate) fn pinned(
    ring: CustomRing,
    table: &RuleTable,
    namespace: Address,
    address_tree: PoolTree,
) -> PolicyConfig {
    let mut sources = [SourceSlot {
        list_id: 0,
        namespace: Address::default(),
    }; N_SOURCE_SLOTS];
    for list_id in table.referenced().iter() {
        sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            namespace,
        };
    }
    let mut config = PolicyConfig {
        discriminator: POLICY_CONFIG,
        policy_hash: [0; 32],
        address_tree: address_tree.address,
        address_tree_id: address_tree.id.to_le_bytes(),
        namespace_bump: 0,
        bump: Address::find_program_address(&[PolicyConfig::SEED], &ring.program_id()).1,
        namespace_owner_hash: ListNamespace::new(ring.namespace_pda().as_array())
            .unwrap()
            .owner_hash,
        sources,
        rules: table.encode(),
        generation: 1u32.to_le_bytes(),
        generation_slot: [0; 8],
    };
    config.policy_hash = config.rules.hash(&source_map(&config).unwrap()).unwrap();
    config
}

/// Serves fixed accounts by address, an unknown address is absent.
#[derive(Default)]
pub(crate) struct Accounts {
    pub accounts: HashMap<Address, Account>,
    pub reads: Mutex<Vec<Address>>,
}

impl Accounts {
    pub(crate) fn with(mut self, address: Address, account: Account) -> Self {
        self.accounts.insert(address, account);
        self
    }

    pub(crate) fn reads(&self) -> Vec<Address> {
        self.reads.lock().unwrap().clone()
    }
}

#[async_trait]
impl AsyncRpc for Accounts {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.reads.lock().unwrap().push(address);
        Ok(self.accounts.get(&address).cloned())
    }
}

pub(crate) fn tree() -> Address {
    zolana_interface::pda::tree(7)
}

pub(crate) fn namespace() -> Address {
    Address::new_from_array([8; 32])
}

pub(crate) fn owner() -> ListNamespace {
    ListNamespace::new(namespace().as_array()).unwrap()
}

pub(crate) fn member(byte: u8) -> Member {
    Member::owner_tag(&[byte; 32]).unwrap()
}

pub(crate) fn lookup(list_id: ListId, member: Member) -> EntryLookup {
    EntryLookup {
        owner: owner(),
        list_id,
        member,
        address_tree_id: 0,
    }
}

/// One entry lineage with version `i` in `trees[i]`.
pub(crate) struct Lineage {
    pub lookup: EntryLookup,
    pub versions: Vec<LiveEntry>,
}

impl Lineage {
    pub(crate) fn new(lookup: EntryLookup, states: &[EntryState]) -> Self {
        Self::across(lookup, states, &vec![lookup.address_tree_id; states.len()])
    }

    pub(crate) fn across(lookup: EntryLookup, states: &[EntryState], trees: &[u16]) -> Self {
        let address = lookup.address().unwrap();
        let versions = states
            .iter()
            .zip(trees)
            .enumerate()
            .map(|(version, (state, &tree_id))| {
                let entry = ListEntry {
                    list_id: lookup.list_id,
                    member: lookup.member,
                    state: *state,
                    version: version as u64,
                    content_hash: [0; 32],
                    blinding: [version as u8 + 1; 32],
                };
                let utxo_hash = entry.utxo_hash(&lookup.owner, &address, tree_id).unwrap();
                LiveEntry {
                    entry,
                    utxo_hash,
                    nullifier: entry_nullifier(&utxo_hash, &entry.blinding).unwrap(),
                    tree_id,
                }
            })
            .collect();
        Self { lookup, versions }
    }

    pub(crate) fn address(&self) -> [u8; 32] {
        self.lookup.address().unwrap()
    }

    pub(crate) fn live(&self) -> Option<LiveEntry> {
        self.versions.last().copied()
    }

    pub(crate) fn spender(&self, index: usize) -> ShieldedTransaction {
        let spent = match index {
            0 => self.address(),
            _ => self.versions[index - 1].nullifier,
        };
        transaction(spent, vec![slot(&self.versions[index])])
    }

    pub(crate) fn spenders(&self) -> Vec<ShieldedTransaction> {
        (0..self.versions.len())
            .map(|index| self.spender(index))
            .collect()
    }
}

pub(crate) fn slot(live: &LiveEntry) -> OutputSlot {
    OutputSlot {
        view_tag: namespace().to_bytes(),
        output_context: OutputContext {
            hash: live.utxo_hash,
            tree_id: live.tree_id,
            leaf_index: live.entry.version,
        },
        payload: live.entry.to_output_data().to_vec(),
    }
}

pub(crate) fn transaction(spent: [u8; 32], output_slots: Vec<OutputSlot>) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: 0,
        tx_signature: Signature::default(),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots,
        messages: Vec::new(),
        nullifiers: vec![spent],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    }
}

/// Serves spenders by nullifier in pages of `page_size`.
pub(crate) struct NullifierRpc {
    pub spenders: Vec<ShieldedTransaction>,
    pub page_size: Option<usize>,
    pub requests: Mutex<Vec<Vec<[u8; 32]>>>,
}

impl NullifierRpc {
    pub(crate) fn new(spenders: Vec<ShieldedTransaction>) -> Self {
        Self {
            spenders,
            page_size: None,
            requests: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn requests(&self) -> Vec<Vec<[u8; 32]>> {
        self.requests.lock().unwrap().clone()
    }

    pub(crate) fn page(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
    ) -> GetShieldedTransactionsByNullifiersResponse {
        self.requests.lock().unwrap().push(nullifiers.clone());
        let matching: Vec<ShieldedTransaction> = self
            .spenders
            .iter()
            .filter(|spender| {
                spender
                    .nullifiers
                    .iter()
                    .any(|nullifier| nullifiers.contains(nullifier))
            })
            .cloned()
            .collect();
        let start = cursor.map_or(0, |cursor| usize::from(cursor[0]));
        let end = self
            .page_size
            .map_or(matching.len(), |size| (start + size).min(matching.len()));
        let rows = matching[start..end].to_vec();
        // Photon treats a full page as truncated and names a cursor on any row.
        let truncated = self.page_size.is_some_and(|size| rows.len() >= size);
        GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            next_cursor: (!rows.is_empty()).then(|| vec![end as u8]),
            scanned_through: (!truncated).then(|| vec![end as u8]),
            transactions: rows,
            output_tree_id: None,
        }
    }
}

#[async_trait]
impl AsyncRpc for NullifierRpc {
    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(self.page(nullifiers, cursor))
    }
}
