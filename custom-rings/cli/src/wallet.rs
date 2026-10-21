//! A member's anonymous ring state between runs and the scan that keeps it current.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context as _, Result};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_client::{AnonymousRingState, IndexerRpcConfig, Rpc, UtxoScan};
use zolana_keypair::{x25519::X25519_PUBKEY_LEN, ShieldedKeypair, X25519Pubkey};
use zolana_transaction::{AssetRegistry, SpendableDecryptionResult};

use crate::{file, Context};

/// Under the `keys/` that `new` writes into `.gitignore`.
pub const ANONYMOUS_RING_DIR: &str = "keys/anonymous-ring";

const STATE_VERSION: u32 = 1;

pub struct AnonymousRingStore {
    path: PathBuf,
    viewing_pubkey: X25519Pubkey,
}

pub struct WalletScan<'a> {
    pub keys: &'a ShieldedKeypair,
    pub registry: &'a AssetRegistry,
    pub ring: Address,
    /// The indexer answers only after it holds the slot.
    pub slot: u64,
    pub store: &'a AnonymousRingStore,
}

#[derive(Deserialize)]
struct Versioned {
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV1 {
    version: u32,
    viewing_pubkey: String,
    issued_addresses: u32,
    known_counterparties: Vec<String>,
}

impl AnonymousRingStore {
    pub fn new(dir: &Path, keys: &ShieldedKeypair) -> Self {
        let viewing_pubkey = keys.viewing_pubkey();
        Self {
            path: dir.join(format!("{}.json", hex::encode(viewing_pubkey.as_bytes()))),
            viewing_pubkey,
        }
    }

    pub fn load(&self) -> Result<AnonymousRingState> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AnonymousRingState::default())
            }
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", self.path.display()))
            }
        };
        self.decode(&text)
            .with_context(|| format!("cannot parse {}", self.path.display()))
    }

    /// Applies `change` to the stored state, not to the copy a scan started from.
    pub fn update<T>(
        &self,
        change: impl FnOnce(&mut AnonymousRingState) -> Result<T>,
    ) -> Result<T> {
        let stored = self.load()?;
        let mut state = stored.clone();
        let outcome = change(&mut state)?;
        if state != stored {
            file::replace_private(&self.path, self.encode(&state)?)?;
        }
        Ok(outcome)
    }

    fn decode(&self, text: &str) -> Result<AnonymousRingState> {
        let Versioned { version } = serde_json::from_str(text)?;
        ensure!(
            version == STATE_VERSION,
            "state version {version} is not supported"
        );
        let state: StateV1 = serde_json::from_str(text)?;
        ensure!(
            x25519_pubkey(&state.viewing_pubkey)? == self.viewing_pubkey,
            "the state belongs to viewing key {}",
            state.viewing_pubkey
        );
        let known_counterparties = state
            .known_counterparties
            .iter()
            .map(|key| x25519_pubkey(key))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            known_counterparties.len() == state.known_counterparties.len(),
            "a known counterparty repeats"
        );
        Ok(AnonymousRingState::restore(
            state.issued_addresses,
            known_counterparties,
        )?)
    }

    fn encode(&self, state: &AnonymousRingState) -> Result<String> {
        Ok(serde_json::to_string_pretty(&StateV1 {
            version: STATE_VERSION,
            viewing_pubkey: hex::encode(self.viewing_pubkey.as_bytes()),
            issued_addresses: state.issued_addresses(),
            known_counterparties: state
                .known_counterparties
                .iter()
                .map(|key| hex::encode(key.as_bytes()))
                .collect(),
        })?)
    }
}

impl WalletScan<'_> {
    /// The store keeps the addresses and counterparties the scan found.
    pub fn fetch<I: Rpc + ?Sized>(self, indexer: &I) -> Result<SpendableDecryptionResult> {
        let scanned = UtxoScan::new(self.keys, self.registry)
            .with_ring_deposit_payload(self.ring, zolana_ring_client::deposit_payload)
            .with_indexer_config(IndexerRpcConfig::at_slot(self.slot))
            .with_anonymous_ring(self.store.load()?)
            .fetch(indexer)?;
        if let Some(report) = &scanned.anonymous {
            self.store.update(|state| Ok(state.absorb(report)?))?;
        }
        Ok(scanned.spendable)
    }
}

impl Context {
    pub fn anonymous_ring_store(&self, keys: &ShieldedKeypair) -> AnonymousRingStore {
        AnonymousRingStore::new(&self.path(Path::new(ANONYMOUS_RING_DIR)), keys)
    }

    /// Every command that reads notes with the member's own keys reads them here.
    pub fn spendable_utxos(
        &self,
        keys: &ShieldedKeypair,
        registry: &AssetRegistry,
    ) -> Result<SpendableDecryptionResult> {
        WalletScan {
            keys,
            registry,
            ring: self.ring.program_id(),
            slot: self.rpc().get_slot()?,
            store: &self.anonymous_ring_store(keys),
        }
        .fetch(self.zolana.indexer())
    }
}

fn x25519_pubkey(text: &str) -> Result<X25519Pubkey> {
    let bytes: [u8; X25519_PUBKEY_LEN] = hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow!("key {text} is not {X25519_PUBKEY_LEN} bytes"))?;
    Ok(X25519Pubkey::from_bytes(bytes)?)
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Scheme-9 notes sealed to their owners and an indexer that serves them by tag and nullifier.

    use solana_signature::Signature;
    use zolana_client::{
        rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context as Page,
        GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse, OutputContext,
        OutputSlot, ShieldedTransaction,
    };
    use zolana_keypair::{viewing_key::ViewTag, SigningKey};
    use zolana_transaction::{
        serialization::ring_anonymous::{
            ring_anonymous_message, RingAnonymousOutputPlaintext, RingAnonymousSlot,
        },
        Data, Mint, Utxo,
    };

    use super::*;

    pub(crate) const RING: Address = Address::new_from_array([4; 32]);
    const TREE: u16 = 2;
    const SALT: [u8; 16] = [7; 16];
    const PAGE: Page = Page {
        block_time: 0,
        slot: 1,
    };

    pub(crate) fn keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    /// A keypair with a store no other test shares.
    pub(crate) struct Member {
        pub(crate) keys: ShieldedKeypair,
        pub(crate) store: AnonymousRingStore,
        dir: PathBuf,
    }

    impl Member {
        pub(crate) fn new(seed: u8, test: &str) -> Self {
            let keys = keypair(seed);
            let dir =
                std::env::temp_dir().join(format!("ring-wallet-{test}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Self {
                store: AnonymousRingStore::new(&dir, &keys),
                keys,
                dir,
            }
        }

        /// What `Context::spendable_utxos` reads, over `indexer`.
        pub(crate) fn scan(&self, indexer: &Indexer) -> SpendableDecryptionResult {
            WalletScan {
                keys: &self.keys,
                registry: &AssetRegistry::default(),
                ring: RING,
                slot: 1,
                store: &self.store,
            }
            .fetch(indexer)
            .unwrap()
        }

        pub(crate) fn state_file(&self) -> PathBuf {
            self.store.path.clone()
        }
    }

    impl Drop for Member {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// A SOL note of the ring, one per owner and amount.
    pub(crate) struct RingUtxo {
        pub(crate) utxo: Utxo,
        pub(crate) hash: [u8; 32],
        pub(crate) nullifier: [u8; 32],
    }

    impl RingUtxo {
        pub(crate) fn new(owner: &ShieldedKeypair, amount: u64) -> Self {
            let mut blinding = [0; 32];
            blinding[24..].copy_from_slice(&amount.to_be_bytes());
            let utxo = Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount,
                blinding,
                ring_program_id: Some(RING),
                data: Data::default(),
            };
            let nullifier_pubkey = owner.nullifier_key.pubkey().unwrap();
            let hash = utxo
                .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
                .unwrap();
            Self {
                nullifier: owner.nullifier(&hash, &blinding).unwrap(),
                hash,
                utxo,
            }
        }
    }

    pub(crate) fn inbox_tag(owner: &ShieldedKeypair, index: u32) -> ViewTag {
        owner
            .viewing_key
            .inbox_secret(index)
            .unwrap()
            .view_tag(0)
            .unwrap()
    }

    pub(crate) struct Paid<'a> {
        pub(crate) to: &'a ShieldedKeypair,
        pub(crate) output: &'a RingUtxo,
        pub(crate) tag: ViewTag,
    }

    pub(crate) struct AnonymousTransfer<'a> {
        pub(crate) payer: &'a ShieldedKeypair,
        pub(crate) nullifiers: Vec<[u8; 32]>,
        pub(crate) outputs: Vec<Paid<'a>>,
    }

    impl AnonymousTransfer<'_> {
        pub(crate) fn transaction(self) -> ShieldedTransaction {
            let first_nullifier = self.nullifiers[0];
            let tx_key = self
                .payer
                .viewing_key
                .get_transaction_viewing_key(&first_nullifier)
                .unwrap();
            let output_slots = (0u8..)
                .zip(&self.outputs)
                .map(|(slot, paid)| {
                    let recipient_pk = paid.to.viewing_pubkey();
                    let pair_u = self
                        .payer
                        .viewing_key
                        .pair_key(&recipient_pk)
                        .unwrap()
                        .pubkey()
                        .u();
                    let body = RingAnonymousSlot {
                        tx_viewing_pk: tx_key.pubkey(),
                        recipient_pk,
                        salt: SALT,
                        slot,
                    }
                    .seal(
                        &tx_key,
                        &RingAnonymousOutputPlaintext {
                            asset_address: paid.output.utxo.asset.asset.to_bytes(),
                            amount: paid.output.utxo.amount,
                            blinding: paid.output.utxo.blinding,
                            pair_u,
                        },
                    )
                    .unwrap();
                    OutputSlot {
                        view_tag: paid.tag,
                        output_context: OutputContext {
                            hash: paid.output.hash,
                            tree_id: TREE,
                            leaf_index: u64::from(slot),
                        },
                        payload: ring_anonymous_message(&body, paid.tag).unwrap().data,
                    }
                })
                .collect();
            let mut signature = [0; 64];
            signature[..32].copy_from_slice(&first_nullifier);
            ShieldedTransaction {
                slot: 1,
                tx_signature: Signature::from(signature),
                event_index: Some(0),
                tx_viewing_pk: Some(tx_key.pubkey()),
                salt: Some(SALT),
                output_slots,
                messages: Vec::new(),
                nullifiers: self.nullifiers,
                proofless: false,
                ring_config: None,
                ring_program_id: Some(RING),
            }
        }
    }

    pub(crate) struct Indexer(pub(crate) Vec<ShieldedTransaction>);

    impl Rpc for Indexer {
        fn get_shielded_transactions_by_tags(
            &self,
            tags: Vec<[u8; 32]>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: PAGE,
                output_tree_id: Some(TREE),
                transactions: self
                    .0
                    .iter()
                    .filter(|tx| {
                        tx.output_slots
                            .iter()
                            .any(|slot| tags.contains(&slot.view_tag))
                    })
                    .cloned()
                    .collect(),
                next_cursor: None,
                scanned_through: None,
            })
        }

        fn get_encrypted_utxos_by_tags(
            &self,
            _tags: Vec<[u8; 32]>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            Ok(GetEncryptedUtxosByTagsResponse {
                context: PAGE,
                output_tree_id: Some(TREE),
                matches: Vec::new(),
                next_cursor: None,
                scanned_through: None,
            })
        }

        fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(GetShieldedTransactionsByNullifiersResponse {
                context: PAGE,
                output_tree_id: Some(TREE),
                transactions: self
                    .0
                    .iter()
                    .filter(|tx| tx.nullifiers.iter().any(|spent| nullifiers.contains(spent)))
                    .cloned()
                    .collect(),
                next_cursor: None,
                scanned_through: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use zolana_client::ClientError;

    use super::{fixtures::Member, *};

    #[test]
    fn the_state_of_an_older_workspace_loads_and_a_foreign_one_is_refused() {
        let member = Member::new(1, "versions");
        assert_eq!(member.store.load().unwrap(), AnonymousRingState::default());

        let other = fixtures::keypair(2);
        let key = |keys: &ShieldedKeypair| hex::encode(keys.viewing_pubkey().as_bytes());
        let state = |version: u32, owner: &ShieldedKeypair| {
            format!(
                r#"{{"version":{version},"viewing_pubkey":"{}","issued_addresses":3,"known_counterparties":["{}"]}}"#,
                key(owner),
                key(&other)
            )
        };
        let path = member.state_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, state(1, &member.keys)).unwrap();
        assert_eq!(
            member.store.load().unwrap(),
            AnonymousRingState::restore(3, BTreeSet::from([other.viewing_pubkey()])).unwrap()
        );
        for refused in [state(2, &member.keys), state(1, &other)] {
            fs::write(&path, refused).unwrap();
            assert!(member.store.load().is_err());
        }
    }

    #[test]
    fn a_state_past_the_issued_maximum_fails_to_load() {
        let member = Member::new(1, "issued-maximum");
        let path = member.state_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"viewing_pubkey":"{}","issued_addresses":{},"known_counterparties":[]}}"#,
                hex::encode(member.keys.viewing_pubkey().as_bytes()),
                u32::MAX
            ),
        )
        .unwrap();
        let refused = member.store.load().unwrap_err();
        assert!(matches!(
            refused.downcast_ref::<ClientError>(),
            Some(ClientError::TooManyIssuedAddresses { count }) if *count == u64::from(u32::MAX)
        ));
    }
}
