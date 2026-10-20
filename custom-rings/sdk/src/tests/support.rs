//! Fixtures the unit tests share: notes, accounts and a pinned policy.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use bytemuck::Pod;
use custom_ring_interface::{PolicyConfig, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG};
use solana_account::Account;
use solana_address::Address;
use zolana_client::{
    AsyncRpc, ClientError, Context, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
};
use zolana_interface::{
    state::{default_tree_fees, discriminator::TREE_ACCOUNT_DISCRIMINATOR, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, NullifierKey, ShieldedKeypair};
use zolana_ring_policy::{ListNamespace, ListSet, Member, RuleTable};
use zolana_transaction::{
    utxo::SppProofInputUtxo, Data, Mint, OutputContext, OutputSlot, ShieldedTransaction, Utxo,
    WalletUtxo,
};
use zolana_tree::TreeAccount;

use crate::{account::source_map, CustomRing, PoolTree};

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

/// `table` pinned under its own hash at the ring's canonical bump, every list its own.
pub(crate) fn pinned(ring: CustomRing, table: &RuleTable, address_tree: PoolTree) -> PolicyConfig {
    pinned_with_curator(
        ring,
        table,
        address_tree,
        Address::default(),
        ListSet::EMPTY,
    )
}

/// `curated` lists read `curator`, a registry root account of another ring.
pub(crate) fn pinned_with_curator(
    ring: CustomRing,
    table: &RuleTable,
    address_tree: PoolTree,
    curator: Address,
    curated: ListSet,
) -> PolicyConfig {
    let mut sources = [SourceSlot {
        list_id: 0,
        registry: Address::default(),
    }; N_SOURCE_SLOTS];
    for list_id in table.referenced().iter() {
        sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            registry: if curated.contains(list_id) {
                curator
            } else {
                Address::default()
            },
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

    /// Every tag stream is free.
    async fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            output_tree_id: None,
            transactions: Vec::new(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

/// An indexer with one output under each occupied tag, every stream read is recorded.
#[derive(Default)]
pub(crate) struct OccupiedTags {
    pub occupied: Vec<[u8; 32]>,
    pub queries: Mutex<Vec<Vec<[u8; 32]>>>,
}

#[async_trait]
impl AsyncRpc for OccupiedTags {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let slots = tags
            .iter()
            .filter(|tag| self.occupied.contains(tag))
            .map(|tag| OutputSlot {
                view_tag: *tag,
                output_context: OutputContext {
                    hash: [1; 32],
                    tree_id: 0,
                    leaf_index: 0,
                },
                payload: Vec::new(),
            })
            .collect();
        self.queries.lock().unwrap().push(tags);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            output_tree_id: None,
            transactions: vec![ShieldedTransaction {
                slot: 0,
                tx_signature: solana_signature::Signature::default(),
                event_index: None,
                tx_viewing_pk: None,
                salt: None,
                output_slots: slots,
                messages: Vec::new(),
                nullifiers: Vec::new(),
                proofless: false,
                ring_config: None,
                ring_program_id: None,
            }],
            next_cursor: None,
            scanned_through: None,
        })
    }
}

pub(crate) fn tree() -> Address {
    zolana_interface::pda::tree(7)
}

pub(crate) fn member(byte: u8) -> Member {
    Member::owner_tag(&[byte; 32]).unwrap()
}
