//! A member's anonymous ring state between runs and the scans that read its notes.

use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context as _, Result};
use custom_ring_interface::RingMode;
use custom_ring_sdk::CustomRingConfig;
use serde::Deserialize;
use solana_address::Address;
use zolana_client::{
    AnonymousRingState, AnonymousRingSync, BlockingIndexer, BlockingRpc, IndexerRpcConfig, Rpc,
    UtxoScan, ZolanaClient,
};
use zolana_keypair::{x25519::X25519_PUBKEY_LEN, ShieldedKeypair, X25519Pubkey};
use zolana_secret_file::{create_new, Visibility};
use zolana_transaction::{verify_owned, AssetRegistry, SpendableDecryptionResult, WalletUtxo};

use crate::{file, Context};

/// Under the `keys/` that `new` writes into `.gitignore`.
pub const ANONYMOUS_RING_DIR: &str = "keys/anonymous-ring";

const STATE_V1: u32 = 1;

pub struct AnonymousRingStore {
    path: PathBuf,
    ring: Address,
    viewing_pubkey: X25519Pubkey,
    /// The ring config's, where a store that kept no notes starts its scan.
    creation_epoch: u64,
}

#[must_use]
pub struct StoreLocation<'a> {
    pub dir: &'a Path,
    pub ring: Address,
    pub keys: &'a ShieldedKeypair,
    pub creation_epoch: u64,
}

#[must_use]
pub struct WalletScan<'a> {
    pub keys: &'a ShieldedKeypair,
    pub registry: &'a AssetRegistry,
    pub config: &'a CustomRingConfig,
}

#[must_use]
struct ScanAt<'a> {
    keys: &'a ShieldedKeypair,
    registry: &'a AssetRegistry,
    ring: Address,
    /// The indexer answers only after it holds the slot.
    slot: u64,
    /// Present on an anonymous ring.
    store: Option<&'a AnonymousRingStore>,
}

#[must_use]
struct ScanOutcome<'a> {
    state: AnonymousRingState,
    found: &'a [WalletUtxo],
    spent: &'a HashSet<[u8; 32]>,
}

/// The addresses and first contacts a state holds, what no scan can rebuild.
struct Decisions<'a>(&'a AnonymousRingState);

/// Held while a store's files change, any part file found under it is a crashed run's.
#[must_use]
struct StoreLock {
    _file: fs::File,
}

#[derive(Deserialize)]
struct Versioned {
    version: u32,
}

#[derive(Deserialize)]
struct StateV1 {
    viewing_pubkey: String,
    issued_addresses: u32,
}

impl StoreLocation<'_> {
    pub fn open(self) -> AnonymousRingStore {
        let viewing_pubkey = self.keys.viewing_pubkey();
        AnonymousRingStore {
            path: self
                .dir
                .join(format!("{}.json", hex::encode(viewing_pubkey.as_bytes()))),
            ring: self.ring,
            viewing_pubkey,
            creation_epoch: self.creation_epoch,
        }
    }
}

impl AnonymousRingStore {
    pub fn load(&self) -> Result<AnonymousRingState> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AnonymousRingState::new(self.ring, self.creation_epoch))
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
        self.update_locked(|state, _| change(state))
    }

    fn update_locked<T>(
        &self,
        change: impl FnOnce(&mut AnonymousRingState, &StoreLock) -> Result<T>,
    ) -> Result<T> {
        // Two runs replacing from one load would drop an issued index.
        let lock = self.lock()?;
        let stored = self.load()?;
        let mut state = stored.clone();
        let outcome = change(&mut state, &lock)?;
        if state != stored || !self.path.exists() {
            lock.replace(&self.path, state.to_json())?;
        }
        Ok(outcome)
    }

    /// `None` until a scan keeps its notes.
    fn kept_utxos(&self) -> Result<Option<Vec<WalletUtxo>>> {
        let path = self.utxos_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .with_context(|| format!("cannot parse {}", path.display())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    fn utxos_path(&self) -> PathBuf {
        self.path.with_extension("notes.json")
    }

    fn lock(&self) -> Result<StoreLock> {
        let path = self.path.with_extension("lock");
        if let Some(dir) = path.parent() {
            file::create_dir_all(dir)?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        lock.lock()
            .with_context(|| format!("cannot lock {}", path.display()))?;
        Ok(StoreLock { _file: lock })
    }

    /// A version 1 store restarts at the ring's creation epoch.
    fn decode(&self, text: &str) -> Result<AnonymousRingState> {
        let Versioned { version } = serde_json::from_str(text)?;
        if version != STATE_V1 {
            let state = AnonymousRingState::from_json(text)?;
            ensure!(
                state.ring() == self.ring,
                "the state belongs to ring {}",
                state.ring()
            );
            return Ok(state);
        }
        let state: StateV1 = serde_json::from_str(text)?;
        ensure!(
            x25519_pubkey(&state.viewing_pubkey)? == self.viewing_pubkey,
            "the state belongs to viewing key {}",
            state.viewing_pubkey
        );
        Ok(AnonymousRingState::migrate_v1(
            self.ring,
            self.creation_epoch,
            state.issued_addresses,
        )?)
    }
}

impl WalletScan<'_> {
    pub fn fetch(self, ctx: &Context) -> Result<SpendableDecryptionResult> {
        let store = (self.config.mode == RingMode::Anonymous)
            .then(|| ctx.anonymous_ring_store(self.keys, self.config));
        ScanAt {
            keys: self.keys,
            registry: self.registry,
            ring: ctx.ring.program_id(),
            slot: ctx.rpc().get_slot()?,
            store: store.as_ref(),
        }
        .fetch(&ctx.zolana)
    }
}

impl ScanAt<'_> {
    /// Kept notes let a scan resume where the last stopped, without them it starts at the ring's creation.
    fn fetch<R: BlockingRpc, I: BlockingIndexer>(
        self,
        zolana: &ZolanaClient<R, I>,
    ) -> Result<SpendableDecryptionResult> {
        let (keys, registry) = (self.keys, self.registry);
        let config = IndexerRpcConfig::at_slot(self.slot);
        let owned = UtxoScan::new(keys, registry)
            .with_ring_deposit_payload(self.ring, zolana_ring_client::deposit_payload)
            .with_indexer_config(config)
            .fetch(zolana.indexer())?;
        let mut spendable = owned.spendable;
        let Some(store) = self.store else {
            return Ok(spendable);
        };
        let stored = store.load()?;
        let kept = store.kept_utxos()?;
        let from = match kept {
            Some(_) => stored,
            None => {
                let mut fresh = AnonymousRingState::new(stored.ring(), store.creation_epoch);
                Decisions(&stored).onto(&mut fresh)?;
                fresh
            }
        };
        let kept = kept.unwrap_or_default();
        let synced = zolana.block_on(
            AnonymousRingSync::new(keys, registry)
                .with_indexer_config(config)
                .with_deposit_payload(zolana_ring_client::deposit_payload)
                .with_held_utxos(owned.history.utxos.iter().chain(&kept))
                .with_default_ring_spends(owned.history.transactions.clone())
                .fetch(zolana.as_async().indexer(), &from, self.slot),
        )?;
        let found = verify_owned(keys, &synced.decrypted)?
            .spendable()
            .with_transaction_keys(keys)?;
        let utxos = ScanOutcome {
            state: synced.state,
            found: &found.utxos().cloned().collect::<Vec<_>>(),
            spent: &synced.decrypted.spent_nullifiers,
        }
        .record(store)?;
        for utxo in utxos {
            if !spendable
                .utxos()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                spendable.utxos_with_data.push(utxo);
            }
        }
        spendable.unknown_asset_ids.extend(found.unknown_asset_ids);
        spendable.unknown_mints.extend(found.unknown_mints);
        Ok(spendable)
    }
}

impl ScanOutcome<'_> {
    /// Under the store's lock the notes land before the state, a crash between leaves a scan that finds them again.
    fn record(self, store: &AnonymousRingStore) -> Result<Vec<WalletUtxo>> {
        let ScanOutcome {
            mut state,
            found,
            spent,
        } = self;
        store.update_locked(|current, lock| {
            let mut utxos = store.kept_utxos()?.unwrap_or_default();
            utxos.retain(|utxo| !spent.contains(&utxo.nullifier));
            for utxo in found {
                if !utxos.iter().any(|kept| kept.utxo_hash == utxo.utxo_hash) {
                    utxos.push(utxo.clone());
                }
            }
            lock.replace(&store.utxos_path(), serde_json::to_vec(&utxos)?)?;
            Decisions(current).onto(&mut state)?;
            *current = state;
            Ok(utxos)
        })
    }
}

impl Decisions<'_> {
    fn onto(self, state: &mut AnonymousRingState) -> Result<()> {
        for issued in self.0.issued() {
            state.issue(issued.index, issued.pairing.clone())?;
        }
        for contact in self.0.sent() {
            state.record_first_contact(*contact);
        }
        Ok(())
    }
}

impl StoreLock {
    /// Owner-only, a crash leaves the previous contents whole.
    fn replace(&self, path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
        let part = path.with_added_extension("part");
        let _ = fs::remove_file(&part);
        create_new(&part, contents.as_ref(), Visibility::Secret)
            .with_context(|| format!("cannot write {}", part.display()))?;
        fs::rename(&part, path)
            .inspect_err(|_| {
                let _ = fs::remove_file(&part);
            })
            .with_context(|| format!("cannot write {}", path.display()))
    }
}

impl Context {
    pub fn anonymous_ring_store(
        &self,
        keys: &ShieldedKeypair,
        config: &CustomRingConfig,
    ) -> AnonymousRingStore {
        StoreLocation {
            dir: &self.path(Path::new(ANONYMOUS_RING_DIR)),
            ring: self.ring.program_id(),
            keys,
            creation_epoch: config.creation_epoch(),
        }
        .open()
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
    use zolana_keypair::SigningKey;

    use super::*;

    pub(crate) const RING: Address = Address::new_from_array([4; 32]);
    pub(crate) const EPOCH: u64 = 3;

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
            let store = StoreLocation {
                dir: &dir,
                ring: RING,
                keys: &keys,
                creation_epoch: EPOCH,
            }
            .open();
            Self { keys, store, dir }
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
}

#[cfg(test)]
mod tests {
    use zolana_client::ClientError;
    use zolana_keypair::Pairing;

    use super::{
        fixtures::{keypair, Member, EPOCH, RING},
        *,
    };

    fn v1(owner: &ShieldedKeypair, issued: u32) -> String {
        format!(
            r#"{{"version":1,"viewing_pubkey":"{}","issued_addresses":{issued},"known_counterparties":[]}}"#,
            hex::encode(owner.viewing_pubkey().as_bytes())
        )
    }

    #[test]
    fn a_new_store_starts_at_the_rings_creation_epoch_and_a_v1_store_keeps_its_addresses() {
        let member = Member::new(1, "versions");
        let fresh = member.store.load().unwrap();
        assert_eq!(fresh, AnonymousRingState::new(RING, EPOCH));

        let path = member.state_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, v1(&member.keys, 3)).unwrap();
        let migrated = member.store.load().unwrap();
        assert_eq!(
            migrated,
            AnonymousRingState::migrate_v1(RING, EPOCH, 3).unwrap()
        );
        assert_eq!(migrated.scanned_epoch(), None, "a migration rescans");
        let indexes: Vec<u32> = migrated
            .issued()
            .iter()
            .map(|issued| issued.index)
            .collect();
        assert_eq!(indexes, [0, 1, 2]);
    }

    #[test]
    fn a_foreign_or_unknown_state_is_refused() {
        let member = Member::new(1, "foreign");
        let path = member.state_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, v1(&keypair(2), 3)).unwrap();
        assert!(member.store.load().is_err(), "another viewing key");
        let other_ring = AnonymousRingState::new(Address::new_from_array([5; 32]), EPOCH);
        fs::write(&path, other_ring.to_json()).unwrap();
        assert!(member.store.load().is_err(), "another ring");
        fs::write(
            &path,
            v1(&member.keys, 3).replace(r#""version":1"#, r#""version":9"#),
        )
        .unwrap();
        let refused = member.store.load().unwrap_err();
        assert!(matches!(
            refused.downcast_ref::<ClientError>(),
            Some(ClientError::AnonymousRingStateVersion { version: 9 })
        ));
    }

    #[test]
    fn concurrent_updates_keep_every_issued_index() {
        let member = Member::new(1, "concurrent");
        let store = &member.store;
        std::thread::scope(|scope| {
            for index in 0..16 {
                scope.spawn(move || {
                    store
                        .update(|state| Ok(state.issue(index, Pairing::default())?))
                        .unwrap()
                });
            }
        });
        assert_eq!(store.load().unwrap().issued().len(), 16);
    }

    #[test]
    fn a_scan_result_keeps_the_addresses_and_pairing_issued_while_it_ran() {
        let member = Member::new(1, "decisions");
        member
            .store
            .update(|state| Ok(state.issue(0, Pairing::off())?))
            .unwrap();
        let mut scanned = AnonymousRingState::new(RING, EPOCH);
        scanned.issue(0, Pairing::default()).unwrap();
        scanned.issue(4, Pairing::default()).unwrap();
        member
            .store
            .update(|current| {
                Decisions(current).onto(&mut scanned)?;
                *current = scanned;
                Ok(())
            })
            .unwrap();
        let stored = member.store.load().unwrap();
        let issued: Vec<(u32, bool)> = stored
            .issued()
            .iter()
            .map(|issued| (issued.index, issued.pairing.is_off()))
            .collect();
        assert_eq!(issued, [(0, true), (4, false)]);
    }

    #[test]
    fn a_part_left_by_a_crashed_run_does_not_block_the_next_write() {
        let member = Member::new(1, "crashed-part");
        let path = member.state_file();
        let part = path.with_added_extension("part");
        let lock = member.store.lock().unwrap();
        fs::write(&part, b"torn").unwrap();
        lock.replace(&path, b"whole").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"whole");
        assert!(!part.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}

#[cfg(test)]
mod scan_tests;
