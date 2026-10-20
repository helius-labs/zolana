//! Anonymous ring streams read by exact tag, never by trial decryption.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    num::NonZeroUsize,
};

use solana_address::Address;
use zolana_keypair::{viewing_key::ViewTag, X25519Pubkey};
use zolana_transaction::{
    AnonymousDecryption, AnonymousTagRoutes, EncryptedScheme, PairHintError, RingTagRequest,
    ShieldedKeys, TransactionError,
};

use crate::{
    error::ClientError,
    recovery::RingRecoveryReport,
    rpc::{IndexerRpcConfig, Rpc, ShieldedTransaction},
    scan::{tagged_transactions, PAGE_LIMIT},
    tags::{indices, TagWindow, DEFAULT_TAG_WINDOW},
};

/// Consecutive unused addresses past the issued ones that end the address scan.
pub const ADDRESS_GAP: u32 = 20;

/// Outputs opened under one inbox index, the rest are spam.
pub const DECRYPTIONS_PER_INDEX: NonZeroUsize = NonZeroUsize::new(16).unwrap();

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnonymousRingState {
    /// Ring addresses handed out, scanned whole before the gap rule applies.
    pub issued_addresses: u32,
    /// Pair keys of payers and viewing keys of recipients paid before.
    pub known_counterparties: HashSet<X25519Pubkey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnonymousStream {
    Inbox {
        address_index: u32,
    },
    Pair {
        counterparty: X25519Pubkey,
    },
    Deposit,
    Change {
        first_nullifier: [u8; 32],
    },
    /// Found by a [`crate::RingRecovery`], its tag was not derived.
    Untagged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousRingNote {
    pub utxo_hash: [u8; 32],
    /// `None` for a bad pair hint, the note is kept.
    pub pair_pk: Option<X25519Pubkey>,
    pub stream: AnonymousStream,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnonymousRingReport {
    pub notes: Vec<AnonymousRingNote>,
    /// Pair keys read from first payments, absent from the state's counterparties.
    pub new_counterparties: HashSet<X25519Pubkey>,
    /// Never below the issued count.
    pub used_addresses: u32,
    pub inbox_next: BTreeMap<u32, u64>,
    pub pair_next: HashMap<X25519Pubkey, u64>,
    pub deposit_next: u64,
    /// Streams with a tag past [`DECRYPTIONS_PER_INDEX`] outputs, the recovery
    /// scan of their ring opened what the cap left.
    pub capped_streams: HashSet<AnonymousStream>,
    pub bad_pair_hints: Vec<PairHintError>,
    /// One per ring a capped tag was published in.
    pub recoveries: Vec<RingRecoveryReport>,
}

/// Change tags come from spends, not windows.
#[derive(Clone, Copy)]
enum Window {
    Inbox(u32),
    Pair(X25519Pubkey),
    Deposit,
}

impl Window {
    fn stream(self) -> AnonymousStream {
        match self {
            Self::Inbox(address_index) => AnonymousStream::Inbox { address_index },
            Self::Pair(counterparty) => AnonymousStream::Pair { counterparty },
            Self::Deposit => AnonymousStream::Deposit,
        }
    }

    fn request(self, viewing_pubkey: X25519Pubkey, index: u64) -> RingTagRequest {
        match self {
            Self::Inbox(address_index) => RingTagRequest::Inbox {
                viewing_pubkey,
                address_index,
                j: index,
            },
            Self::Pair(counterparty) => RingTagRequest::Pair {
                viewing_pubkey,
                counterparty,
                k: index,
            },
            Self::Deposit => RingTagRequest::Deposit {
                viewing_pubkey,
                n: index,
            },
        }
    }
}

struct OpenStream {
    window: Window,
    start: u64,
}

/// Routes of the change tags alone, the spends were opened under the stream routes before.
pub(crate) struct ChangeRoutes {
    pub(crate) spends: Vec<ShieldedTransaction>,
    pub(crate) routes: AnonymousTagRoutes,
}

pub(crate) struct AnonymousStreams<'a, K: ?Sized> {
    keys: &'a K,
    viewing_pubkey: X25519Pubkey,
    config: Option<IndexerRpcConfig>,
    counterparties: HashSet<X25519Pubkey>,
    open: Vec<OpenStream>,
    opened_addresses: u32,
    routes: AnonymousTagRoutes,
    sources: HashMap<ViewTag, AnonymousStream>,
    change_routed: HashSet<[u8; 32]>,
    used_tags: BTreeSet<ViewTag>,
    capped_rings: BTreeSet<Address>,
    report: AnonymousRingReport,
}

impl<'a, K: ShieldedKeys + ?Sized> AnonymousStreams<'a, K> {
    pub(crate) fn new(
        keys: &'a K,
        state: &AnonymousRingState,
        config: Option<IndexerRpcConfig>,
    ) -> Result<Self, ClientError> {
        let mut streams = Self {
            keys,
            viewing_pubkey: keys.address()?.viewing_pubkey,
            config,
            counterparties: state.known_counterparties.clone(),
            open: vec![OpenStream {
                window: Window::Deposit,
                start: 0,
            }],
            opened_addresses: 0,
            routes: AnonymousTagRoutes::new().with_decryptions_per_tag(DECRYPTIONS_PER_INDEX),
            sources: HashMap::new(),
            change_routed: HashSet::new(),
            used_tags: BTreeSet::new(),
            capped_rings: BTreeSet::new(),
            report: AnonymousRingReport {
                used_addresses: state.issued_addresses,
                ..AnonymousRingReport::default()
            },
        };
        for counterparty in &state.known_counterparties {
            streams.open_pair(*counterparty);
        }
        streams.open_addresses();
        Ok(streams)
    }

    pub(crate) fn is_done(&self) -> bool {
        self.open.is_empty()
    }

    pub(crate) fn routes(&self) -> &AnonymousTagRoutes {
        &self.routes
    }

    pub(crate) fn used_tags(&self) -> impl Iterator<Item = ViewTag> + '_ {
        self.used_tags.iter().copied()
    }

    /// The rings whose capped tags still wait for a recovery scan, each taken once.
    pub(crate) fn take_capped_rings(&mut self) -> BTreeSet<Address> {
        std::mem::take(&mut self.capped_rings)
    }

    pub(crate) fn record_recovery(&mut self, report: RingRecoveryReport) {
        self.report.recoveries.push(report);
    }

    /// A window with no occupied index closes its stream.
    pub(crate) fn read<I: Rpc + ?Sized>(
        &mut self,
        indexer: &I,
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        if self.open.is_empty() {
            return Ok(Vec::new());
        }
        let mut requests = Vec::new();
        let mut positions = Vec::new();
        for (position, open) in self.open.iter().enumerate() {
            for index in indices(open.start) {
                requests.push(open.window.request(self.viewing_pubkey, index));
                positions.push(position);
            }
        }
        let tags = self.derive(&requests)?;
        let mut by_stream: Vec<Vec<ViewTag>> = vec![Vec::new(); self.open.len()];
        for (tag, position) in tags.iter().zip(positions) {
            by_stream[position].push(*tag);
        }
        let windows: Vec<TagWindow> = self
            .open
            .iter()
            .zip(by_stream)
            .map(|(open, tags)| TagWindow::new(open.start, tags))
            .collect();
        for (open, window) in self.open.iter().zip(&windows) {
            for tag in window.tags() {
                self.routes.insert(tag, self.viewing_pubkey);
                self.sources.insert(tag, open.window.stream());
            }
        }
        let mut transactions = Vec::new();
        for chunk in tags.chunks(PAGE_LIMIT as usize) {
            transactions.extend(tagged_transactions(indexer, chunk, self.config)?);
        }
        let open = std::mem::take(&mut self.open);
        for (open, window) in open.into_iter().zip(windows) {
            let Some(&highest) = window.occupied(&transactions).last() else {
                continue;
            };
            self.advance(open.window, highest.saturating_add(1));
            if let Some(start) = open.start.checked_add(DEFAULT_TAG_WINDOW) {
                self.open.push(OpenStream {
                    window: open.window,
                    start,
                });
            }
        }
        Ok(transactions)
    }

    pub(crate) fn route_change(
        &mut self,
        transactions: &[ShieldedTransaction],
        owned: &HashSet<[u8; 32]>,
    ) -> Result<Option<ChangeRoutes>, ClientError> {
        let mut spends = Vec::new();
        let mut requests = Vec::new();
        for tx in transactions {
            let Some(&first_nullifier) = tx.nullifiers.first() else {
                continue;
            };
            if self.change_routed.contains(&first_nullifier)
                || !tx
                    .nullifiers
                    .iter()
                    .any(|nullifier| owned.contains(nullifier))
            {
                continue;
            }
            self.change_routed.insert(first_nullifier);
            if !tx.output_slots.iter().any(|slot| {
                slot.encrypted_body(EncryptedScheme::RingAnonymous)
                    .is_some()
            }) {
                continue;
            }
            for slot in 0..tx.output_slots.len() {
                let slot = u8::try_from(slot).map_err(|_| TransactionError::TooManyOutputs)?;
                requests.push(RingTagRequest::Change {
                    viewing_pubkey: self.viewing_pubkey,
                    first_nullifier,
                    slot,
                });
            }
            spends.push(tx.clone());
        }
        if requests.is_empty() {
            return Ok(None);
        }
        let mut routes = AnonymousTagRoutes::new();
        for (tag, request) in self.derive(&requests)?.into_iter().zip(requests) {
            let RingTagRequest::Change {
                first_nullifier, ..
            } = request
            else {
                continue;
            };
            routes.insert(tag, self.viewing_pubkey);
            self.sources
                .insert(tag, AnonymousStream::Change { first_nullifier });
        }
        Ok(Some(ChangeRoutes { spends, routes }))
    }

    pub(crate) fn record(&mut self, decrypted: AnonymousDecryption) {
        for note in decrypted.notes {
            let Some(&stream) = self.sources.get(&note.view_tag) else {
                continue;
            };
            self.used_tags.insert(note.view_tag);
            self.report.notes.push(AnonymousRingNote {
                utxo_hash: note.utxo_hash,
                pair_pk: note.pair_pk,
                stream,
            });
            if let AnonymousStream::Inbox { address_index } = stream {
                self.report.used_addresses = self
                    .report
                    .used_addresses
                    .max(address_index.saturating_add(1));
                if let Some(pair_pk) = note.pair_pk {
                    if self.counterparties.insert(pair_pk) {
                        self.report.new_counterparties.insert(pair_pk);
                        self.open_pair(pair_pk);
                    }
                }
            }
        }
        for tag in decrypted.capped_tags {
            if let Some(stream) = self.sources.get(&tag) {
                self.report.capped_streams.insert(*stream);
            }
        }
        self.capped_rings.extend(decrypted.capped_rings);
        self.report.bad_pair_hints.extend(decrypted.bad_pair_hints);
        self.open_addresses();
    }

    pub(crate) fn finish(self) -> AnonymousRingReport {
        self.report
    }

    fn derive(&self, requests: &[RingTagRequest]) -> Result<Vec<ViewTag>, ClientError> {
        let tags = self.keys.ring_view_tags(requests)?;
        if tags.len() != requests.len() {
            return Err(TransactionError::IncompleteDerivation {
                got: tags.len(),
                want: requests.len(),
            }
            .into());
        }
        Ok(tags)
    }

    fn advance(&mut self, window: Window, next: u64) {
        match window {
            Window::Inbox(address_index) => {
                self.report.inbox_next.insert(address_index, next);
            }
            Window::Pair(counterparty) => {
                self.report.pair_next.insert(counterparty, next);
            }
            Window::Deposit => self.report.deposit_next = next,
        }
    }

    fn open_addresses(&mut self) {
        let end = self.report.used_addresses.saturating_add(ADDRESS_GAP);
        while self.opened_addresses < end {
            self.open.push(OpenStream {
                window: Window::Inbox(self.opened_addresses),
                start: 0,
            });
            self.opened_addresses += 1;
        }
    }

    fn open_pair(&mut self, counterparty: X25519Pubkey) {
        self.open.push(OpenStream {
            window: Window::Pair(counterparty),
            start: 0,
        });
    }
}
