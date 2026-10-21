use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
use custom_ring_interface::{
    stream::{RingTag, SlotSecret},
    RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_event::{split_merge_output_body, EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;
use zolana_keypair::{
    shielded::ShieldedAddress, x25519::X25519_PUBKEY_LEN, KeypairError, PublicKey, X25519Pubkey,
};

use crate::{
    asset::{AssetBalance, AssetRegistry, Balances, Mint},
    data::Data,
    error::TransactionError,
    indexer_types::{OutputSlot, ShieldedTransaction},
    instructions::merge::MergeOutputPlaintext,
    keys::{
        DecryptLabel, DecryptRequest, DeriveRequest, RingDeliveryRequest, RingRecipientKey,
        ShieldedKeys, TransactionKeyRequest,
    },
    serialization::{
        anonymous::AnonymousRecipient,
        confidential::Confidential,
        plaintext::PlaintextTransfer,
        proofless::Proofless,
        ring_delivered::{is_contributory, RingDeliveryOpening, RingDeliverySlot, RingNoteOwner},
        ring_deposit::RingDepositPlaintext,
        ring_packed::RingPacked,
        scheme::EncryptedScheme,
        OwnerCx, UtxoSerialization,
    },
    utxo::{owner_utxo_hash, Blinding, Utxo, WalletUtxo},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecryptionResult {
    pub utxos: Vec<WalletUtxo>,
    pub spent_nullifiers: HashSet<[u8; 32]>,
    /// Asset ids read from decoded outputs that the asset registry does not
    /// know. Those outputs are left out. The sender wrote the id and nothing on
    /// chain checks it, so it is unverified: register the assets that exist
    /// and decrypt again, and the commitment decides.
    pub unknown_asset_ids: BTreeSet<u64>,
    /// Mints an opened output names that the registry has no id for, a refresh admits them.
    pub unknown_mints: BTreeSet<Address>,
    /// Delivered ring notes whose commitment matched in a mint the registry has
    /// no id for, [`Self::resolve_pending`] admits them without a rescan.
    pub pending_assets: Vec<PendingNote>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendableDecryptionResult {
    pub balances: Balances,
    pub utxos_with_data: Vec<WalletUtxo>,
    /// As on [`DecryptionResult`].
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`].
    pub unknown_mints: BTreeSet<Address>,
    /// As on [`DecryptionResult`].
    pub pending_assets: Vec<PendingNote>,
}

/// A commitment-verified delivered ring note held back until its mint is registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingNote {
    pub asset_address: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub owner: PublicKey,
    pub nullifier_pk: [u8; 32],
    pub ring_program_id: Address,
    pub utxo_hash: [u8; 32],
    pub tree_id: u16,
    pub leaf_index: u64,
    pub slot: u64,
    pub tx_signature: Signature,
    pub slot_index: u32,
}

impl PendingNote {
    /// `None` while the registry still lacks the mint.
    pub fn resolve(&self, assets: &AssetRegistry) -> Result<Option<WalletUtxo>, TransactionError> {
        let asset = match assets.mint(&self.asset_address) {
            Ok(asset) => asset,
            Err(TransactionError::UnknownMint(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(WalletUtxo {
            utxo: Utxo {
                owner: self.owner,
                asset,
                amount: self.amount,
                blinding: self.blinding,
                ring_program_id: Some(self.ring_program_id),
                data: Data::default(),
            },
            nullifier_pubkey: self.nullifier_pk,
            utxo_hash: self.utxo_hash,
            nullifier: [0; 32],
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id: self.tree_id,
            leaf_index: self.leaf_index,
            latest_tree_id: None,
            slot: self.slot,
            tx_signature: self.tx_signature,
            slot_index: self.slot_index,
        }))
    }
}

/// A pending note admitted by [`DecryptionResult::resolve_pending`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNote {
    pub utxo: WalletUtxo,
    /// Its nullifier was among the spent ones before it was admitted.
    pub spent: bool,
}

impl SpendableDecryptionResult {
    /// Every spendable UTXO: the balances' UTXOs, then the data-bearing ones.
    pub fn utxos(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.balances
            .assets
            .iter()
            .flat_map(|balance| &balance.utxos)
            .chain(&self.utxos_with_data)
    }

    /// Attach to every spendable UTXO the transaction viewing key of a
    /// transaction that spends it first, derived for the holder's viewing key
    /// in one [`ShieldedKeys::transaction_keys`] request, so encrypting that
    /// transaction needs no further key request.
    pub fn with_transaction_keys<K: ShieldedKeys + ?Sized>(
        mut self,
        shielded_keys: &K,
    ) -> Result<Self, TransactionError> {
        let viewing_pubkey = shielded_keys.address()?.viewing_pubkey;
        let mut utxos: Vec<&mut WalletUtxo> = self
            .balances
            .assets
            .iter_mut()
            .flat_map(|balance| balance.utxos.iter_mut())
            .chain(self.utxos_with_data.iter_mut())
            .collect();
        let requests: Vec<TransactionKeyRequest> = utxos
            .iter()
            .map(|utxo| TransactionKeyRequest {
                viewing_pubkey,
                first_nullifier: utxo.nullifier,
            })
            .collect();
        if requests.is_empty() {
            return Ok(self);
        }
        let keys = shielded_keys.transaction_keys(&requests)?;
        if keys.len() != requests.len() {
            return Err(TransactionError::IncompleteDerivation {
                got: keys.len(),
                want: requests.len(),
            });
        }
        for (utxo, key) in utxos.iter_mut().zip(keys) {
            utxo.tx_viewing_key = Some(*key.secret_bytes());
        }
        Ok(self)
    }

    /// Stamp every spendable UTXO with the newest output tree the indexer
    /// reported on the pages it came from (`output_tree_id`), so a
    /// transaction spending one appends its outputs there by default. `None`
    /// means the indexer named no unpaused tree.
    #[must_use]
    pub fn with_latest_tree_id(mut self, latest_tree_id: Option<u16>) -> Self {
        for utxo in self
            .balances
            .assets
            .iter_mut()
            .flat_map(|balance| &mut balance.utxos)
            .chain(&mut self.utxos_with_data)
        {
            utxo.latest_tree_id = latest_tree_id;
        }
        self
    }
}

/// One delivered ring output and the slot secret its recipient agreed for it.
#[derive(Clone)]
pub struct RingDeliveredCandidate<'a> {
    pub tx: &'a ShieldedTransaction,
    pub slot_index: u32,
    /// The published tag of an anonymous output, `None` for a confidential delivered one.
    pub tag: Option<RingTag>,
    pub slot_secret: SlotSecret,
}

/// What every delivered slot secret of one ring transaction binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveryContext {
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: [u8; 16],
    pub first_nullifier: [u8; 32],
}

/// A candidate whose rebuilt note matched its published commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveredFind {
    /// Index into the candidates.
    pub candidate: usize,
    pub utxo_hash: [u8; 32],
    pub asset_address: Address,
    pub amount: u64,
    /// Held in `pending_assets` until its mint is registered.
    pub pending: bool,
}

/// Decrypts and verifies notes against the supplied transactions.
pub fn decrypt_spendable<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &[ShieldedTransaction],
    assets: &AssetRegistry,
) -> Result<SpendableDecryptionResult, TransactionError> {
    let decrypted = decrypt(shielded_keys, transactions, assets)?;
    verify_spendable(shielded_keys, &decrypted)
}

/// Returns decoded candidates without commitment or spend verification.
pub fn decrypt<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &[ShieldedTransaction],
    assets: &AssetRegistry,
) -> Result<DecryptionResult, TransactionError> {
    let mut decrypted = DecryptionResult::default();
    decrypted.extend(shielded_keys, transactions, assets)?;
    Ok(decrypted)
}

impl RingDeliveryContext {
    /// `None` unless a ring transaction has a contributory key, a salt and a canonical first nullifier.
    pub fn of(tx: &ShieldedTransaction) -> Option<Self> {
        tx.ring_program_id?;
        let context = Self {
            tx_viewing_pk: tx.tx_viewing_pk?,
            salt: tx.salt?,
            first_nullifier: *tx.nullifiers.first()?,
        };
        (is_contributory(&context.tx_viewing_pk)
            && is_canonical_bn254_scalar_be(&context.first_nullifier))
        .then_some(context)
    }
}

impl DecryptionResult {
    /// Adds the candidates of `transactions`, decrypting only those, so a
    /// client that reads its transactions in rounds decrypts each one once. A
    /// merge output decrypts from its own transaction like any other output.
    /// Left unchanged on error.
    pub fn extend<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
    ) -> Result<(), TransactionError> {
        let address = shielded_keys.address()?;
        let mut found = Vec::new();
        let mut unknown_asset_ids = BTreeSet::new();
        let mut unknown_mints = BTreeSet::new();
        for tx in transactions {
            for (position, slot) in tx.output_slots.iter().enumerate() {
                let slot_index =
                    u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
                let decoded =
                    match decode_slot(shielded_keys, &address, tx, slot, slot_index, assets) {
                        Ok(Some(decoded)) => decoded,
                        Ok(None) => continue,
                        // An asset the registry lacks leaves one output out and
                        // is reported, rather than failing the whole scan.
                        // Deposits and merges name their mint; every other
                        // output carries a registry id.
                        Err(TransactionError::UnknownAsset(asset_id)) => {
                            unknown_asset_ids.insert(asset_id);
                            continue;
                        }
                        Err(TransactionError::UnknownMint(mint)) => {
                            unknown_mints.insert(mint);
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                let site = Site {
                    address: &address,
                    tx,
                    slot,
                    slot_index,
                };
                for utxo in decoded.utxos {
                    found.push(site.wallet_utxo(utxo, decoded.data_hash, decoded.ring_data_hash));
                }
            }
        }
        let candidates = confidential_delivered(shielded_keys, transactions)?;
        let opened = open_delivered(&address, assets, &candidates)?;
        found.extend(opened.found);
        self.absorb(
            shielded_keys,
            found,
            transactions,
            unknown_asset_ids,
            unknown_mints,
        )?;
        self.hold_pending(opened.pending);
        Ok(())
    }

    /// Keeps every candidate whose body rebuilds its published commitment, unchanged on error.
    pub fn extend_ring_delivered<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        assets: &AssetRegistry,
        transactions: &[ShieldedTransaction],
        candidates: &[RingDeliveredCandidate<'_>],
    ) -> Result<Vec<RingDeliveredFind>, TransactionError> {
        let address = shielded_keys.address()?;
        let opened = open_delivered(&address, assets, candidates)?;
        self.absorb(
            shielded_keys,
            opened.found,
            transactions,
            BTreeSet::new(),
            BTreeSet::new(),
        )?;
        self.hold_pending(opened.pending);
        Ok(opened.finds)
    }

    /// The mint joins `unknown_mints` as every other output's does, a registry refresh resolves it.
    fn hold_pending(&mut self, pending: Vec<PendingNote>) {
        for note in pending {
            self.unknown_mints.insert(note.asset_address);
            if !self
                .pending_assets
                .iter()
                .any(|held| held.utxo_hash == note.utxo_hash)
            {
                self.pending_assets.push(note);
            }
        }
    }

    /// Admits every pending note the registry now resolves, each one's spent
    /// state read before it joins `utxos`.
    pub fn resolve_pending<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        assets: &AssetRegistry,
    ) -> Result<Vec<ResolvedNote>, TransactionError> {
        let resolutions = self
            .pending_assets
            .iter()
            .map(|note| note.resolve(assets))
            .collect::<Result<Vec<_>, _>>()?;
        let mut keep = resolutions
            .iter()
            .map(Option::is_none)
            .collect::<Vec<_>>()
            .into_iter();
        let mut admitted: Vec<WalletUtxo> = resolutions.into_iter().flatten().collect();
        // A failed step returns before any note leaves `pending_assets`.
        assign_nullifiers(shielded_keys, &mut admitted)?;
        self.pending_assets.retain(|_| keep.next().unwrap_or(true));
        let resolved: Vec<ResolvedNote> = admitted
            .into_iter()
            .map(|utxo| ResolvedNote {
                spent: self.spent_nullifiers.contains(&utxo.nullifier),
                utxo,
            })
            .collect();
        self.utxos
            .extend(resolved.iter().map(|note| note.utxo.clone()));
        sort_by_publication(&mut self.utxos);
        Ok(resolved)
    }

    fn absorb<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        mut found: Vec<WalletUtxo>,
        transactions: &[ShieldedTransaction],
        unknown_asset_ids: BTreeSet<u64>,
        unknown_mints: BTreeSet<Address>,
    ) -> Result<(), TransactionError> {
        assign_nullifiers(shielded_keys, &mut found)?;
        let mut utxos = self.utxos.clone();
        utxos.extend(found);
        sort_by_publication(&mut utxos);
        self.utxos = utxos;
        self.spent_nullifiers.extend(
            transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied()),
        );
        self.unknown_asset_ids.extend(unknown_asset_ids);
        self.unknown_mints.extend(unknown_mints);
        Ok(())
    }
}

fn sort_by_publication(utxos: &mut [WalletUtxo]) {
    utxos.sort_by_key(|utxo| {
        (
            utxo.slot,
            utxo.tx_signature.as_ref().to_vec(),
            utxo.slot_index,
        )
    });
}

#[derive(Clone, Copy)]
struct Site<'a> {
    address: &'a ShieldedAddress,
    tx: &'a ShieldedTransaction,
    slot: &'a OutputSlot,
    slot_index: u32,
}

impl Site<'_> {
    fn wallet_utxo(
        &self,
        utxo: Utxo,
        data_hash: Option<[u8; 32]>,
        ring_data_hash: Option<[u8; 32]>,
    ) -> WalletUtxo {
        WalletUtxo {
            utxo,
            nullifier_pubkey: self.address.nullifier_pubkey,
            utxo_hash: self.slot.output_context.hash,
            nullifier: [0; 32],
            tx_viewing_key: None,
            data_hash,
            ring_data_hash,
            tree_id: self.slot.output_context.tree_id,
            leaf_index: self.slot.output_context.leaf_index,
            latest_tree_id: None,
            slot: self.tx.slot,
            tx_signature: self.tx.tx_signature,
            slot_index: self.slot_index,
        }
    }
}

/// What [`open_delivered`] kept, the notes in a registered mint and the ones held back.
struct OpenedDelivered {
    found: Vec<WalletUtxo>,
    pending: Vec<PendingNote>,
    finds: Vec<RingDeliveredFind>,
}

/// Opens every candidate under its own slot secret, nothing is absorbed here.
fn open_delivered(
    address: &ShieldedAddress,
    assets: &AssetRegistry,
    candidates: &[RingDeliveredCandidate<'_>],
) -> Result<OpenedDelivered, TransactionError> {
    let owner = RingNoteOwner {
        signing_pubkey: &address.signing_pubkey,
        nullifier_pubkey: &address.nullifier_pubkey,
    };
    let mut opened = OpenedDelivered {
        found: Vec::new(),
        pending: Vec::new(),
        finds: Vec::new(),
    };
    for (index, candidate) in candidates.iter().enumerate() {
        let tx = candidate.tx;
        let (Some(ring), Some(&first_nullifier)) = (tx.ring_program_id, tx.nullifiers.first())
        else {
            continue;
        };
        let Some(slot) = tx.output_slots.get(candidate.slot_index as usize) else {
            continue;
        };
        let Some(body) = delivered_body(slot) else {
            continue;
        };
        let context = &slot.output_context;
        let note = RingDeliverySlot {
            ring,
            first_nullifier,
            output_index: candidate.slot_index,
            tag: candidate.tag,
        }
        .open(RingDeliveryOpening {
            body: &body,
            slot_secret: &candidate.slot_secret,
            owner,
            commitment: &context.hash,
            tree_id: context.tree_id,
        })?;
        let Some(note) = note else {
            continue;
        };
        let asset_address = note.utxo.asset.asset;
        let pending = match assets.mint(&asset_address) {
            Ok(asset) => {
                let site = Site {
                    address,
                    tx,
                    slot,
                    slot_index: candidate.slot_index,
                };
                let mut wallet_utxo = site.wallet_utxo(note.utxo.clone(), None, None);
                wallet_utxo.utxo.asset = asset;
                opened.found.push(wallet_utxo);
                false
            }
            Err(TransactionError::UnknownMint(_)) => {
                opened.pending.push(PendingNote {
                    asset_address,
                    amount: note.utxo.amount,
                    blinding: note.utxo.blinding,
                    owner: address.signing_pubkey,
                    nullifier_pk: address.nullifier_pubkey,
                    ring_program_id: ring,
                    utxo_hash: note.utxo_hash,
                    tree_id: context.tree_id,
                    leaf_index: context.leaf_index,
                    slot: tx.slot,
                    tx_signature: tx.tx_signature,
                    slot_index: candidate.slot_index,
                });
                true
            }
            Err(error) => return Err(error),
        };
        opened.finds.push(RingDeliveredFind {
            candidate: index,
            utxo_hash: note.utxo_hash,
            asset_address,
            amount: note.utxo.amount,
            pending,
        });
    }
    Ok(opened)
}

/// The 40-byte body of a scheme-9 or scheme-10 slot, `None` for any other slot or length.
fn delivered_body(slot: &OutputSlot) -> Option<[u8; RING_DELIVERED_BODY_LEN]> {
    let body = slot
        .encrypted_body(EncryptedScheme::RingAnonymous)
        .or_else(|| slot.encrypted_body(EncryptedScheme::RingConfidentialDelivered))?;
    body.try_into().ok()
}

/// Every scheme-10 slot published under one of the wallet's viewing keys, its owner tag.
fn confidential_delivered<'a, K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &'a [ShieldedTransaction],
) -> Result<Vec<RingDeliveredCandidate<'a>>, TransactionError> {
    let held: HashMap<[u8; 32], X25519Pubkey> = shielded_keys
        .viewing_public_keys()
        .into_iter()
        .map(|pubkey| (pubkey.u(), pubkey))
        .collect();
    let mut sites = Vec::new();
    let mut requests = Vec::new();
    for tx in transactions {
        let Some(RingDeliveryContext {
            tx_viewing_pk,
            salt,
            first_nullifier,
        }) = RingDeliveryContext::of(tx)
        else {
            continue;
        };
        for (position, slot) in tx.output_slots.iter().enumerate() {
            let Some(&viewing_pubkey) = held.get(&slot.view_tag) else {
                continue;
            };
            if slot
                .encrypted_body(EncryptedScheme::RingConfidentialDelivered)
                .is_none()
            {
                continue;
            }
            let output_index =
                u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
            sites.push((tx, output_index));
            requests.push(RingDeliveryRequest {
                recipient: RingRecipientKey::Viewing(viewing_pubkey),
                tx_viewing_pk,
                salt,
                output_index,
                first_nullifier,
            });
        }
    }
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let secrets = shielded_keys.ring_delivery_secrets(&requests)?;
    if secrets.len() != requests.len() {
        return Err(TransactionError::IncompleteDerivation {
            got: secrets.len(),
            want: requests.len(),
        });
    }
    sites
        .into_iter()
        .zip(secrets)
        .map(|((tx, slot_index), secret)| {
            Ok(RingDeliveredCandidate {
                tx,
                slot_index,
                tag: None,
                slot_secret: SlotSecret::new(secret)?,
            })
        })
        .collect()
}

/// Skips unresolved, mismatched and spent notes; spend status covers the supplied batch.
pub fn verify_spendable<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &DecryptionResult,
) -> Result<SpendableDecryptionResult, TransactionError> {
    Ok(verify_owned(shielded_keys, decrypted)?.spendable())
}

/// The UTXOs a wallet owns among a [`DecryptionResult`], spent or not, as
/// [`verify_owned`] returns them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedUtxos {
    /// In the order the [`DecryptionResult`] holds them.
    pub utxos: Vec<WalletUtxo>,
    /// The nullifiers of the spent ones.
    pub spent: HashSet<[u8; 32]>,
    /// As on [`DecryptionResult`].
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`].
    pub unknown_mints: BTreeSet<Address>,
    /// As on [`DecryptionResult`].
    pub pending_assets: Vec<PendingNote>,
}

impl OwnedUtxos {
    /// The unspent ones, as [`verify_spendable`] returns them, for a caller
    /// that keeps the spent ones too: it asks the key holder nothing more.
    pub fn spendable(&self) -> SpendableDecryptionResult {
        let mut by_mint: HashMap<Address, AssetBalance> = HashMap::new();
        let mut utxos_with_data = Vec::new();
        for wallet_utxo in &self.utxos {
            if self.spent.contains(&wallet_utxo.nullifier) {
                continue;
            }
            let wallet_utxo = wallet_utxo.clone();
            if wallet_utxo.utxo.data.utxo_data().is_some()
                || wallet_utxo.utxo.data.ring_data().is_some()
                || wallet_utxo.data_hash.is_some()
                || wallet_utxo.ring_data_hash.is_some()
                || wallet_utxo.utxo.ring_program_id.is_some()
            {
                utxos_with_data.push(wallet_utxo);
                continue;
            }
            let asset = wallet_utxo.utxo.asset;
            let balance = match by_mint.entry(asset.asset) {
                Entry::Occupied(occupied) => occupied.into_mut(),
                Entry::Vacant(vacant) => vacant.insert(AssetBalance {
                    asset_id: asset.asset_id,
                    mint: asset.asset,
                    amount: 0,
                    utxos: Vec::new(),
                }),
            };
            balance.amount = balance.amount.saturating_add(wallet_utxo.utxo.amount);
            balance.utxos.push(wallet_utxo);
        }
        let mut balances: Vec<AssetBalance> = by_mint.into_values().collect();
        balances.sort_by_key(|balance| balance.asset_id);
        for utxos in balances
            .iter_mut()
            .map(|balance| &mut balance.utxos)
            .chain(std::iter::once(&mut utxos_with_data))
        {
            sort_by_publication(utxos);
        }
        SpendableDecryptionResult {
            balances: Balances { assets: balances },
            utxos_with_data,
            unknown_asset_ids: self.unknown_asset_ids.clone(),
            unknown_mints: self.unknown_mints.clone(),
            pending_assets: self.pending_assets.clone(),
        }
    }
}

/// The UTXOs of `decrypted` this wallet owns, spent or not. Each commitment is
/// recomputed from the decoded fields and must match the published one; a
/// commitment counts once, and every nullifier is derived again rather than
/// taken from `decrypted`. [`verify_spendable`] is this without the spent ones.
pub fn verify_owned<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &DecryptionResult,
) -> Result<OwnedUtxos, TransactionError> {
    let address = shielded_keys.address()?;
    let mut claimed = HashSet::new();
    let mut verified = Vec::new();
    for input in &decrypted.utxos {
        if input.utxo.owner != address.signing_pubkey
            || input.nullifier_pubkey != address.nullifier_pubkey
            || (input.utxo.data.utxo_data().is_some() && input.data_hash.is_none())
            || (input.utxo.data.ring_data().is_some() && input.ring_data_hash.is_none())
        {
            continue;
        }
        let hash = input.utxo.hash(
            &address.nullifier_pubkey,
            &input.data_hash.unwrap_or_default(),
            &input.ring_data_hash.unwrap_or_default(),
            input.tree_id,
        )?;
        if hash != input.utxo_hash {
            continue;
        }
        if claimed.insert(hash) {
            verified.push(input.clone());
        }
    }
    assign_nullifiers(shielded_keys, &mut verified)?;
    let spent = verified
        .iter()
        .map(|utxo| utxo.nullifier)
        .filter(|nullifier| decrypted.spent_nullifiers.contains(nullifier))
        .collect();
    Ok(OwnedUtxos {
        utxos: verified,
        spent,
        unknown_asset_ids: decrypted.unknown_asset_ids.clone(),
        unknown_mints: decrypted.unknown_mints.clone(),
        pending_assets: decrypted.pending_assets.clone(),
    })
}

/// One slot's decoded contents. `data_hash` and `ring_data_hash` are the ones
/// the commitment was built with; only the proofless rail publishes them.
struct DecodedSlot {
    utxos: Vec<Utxo>,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
}

fn decode_slot<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    slot_index: u32,
    assets: &AssetRegistry,
) -> Result<Option<DecodedSlot>, TransactionError> {
    let Some(output_data) = slot.output_data() else {
        return Ok(None);
    };
    let owner_cx = OwnerCx {
        owner: address.signing_pubkey,
        assets,
        ring_program_id: None,
        first_nullifier: tx.nullifiers.first().copied(),
    };

    match output_data {
        OutputDataEncoding::Plaintext(blob) => {
            let Some((&scheme_byte, body)) = blob.split_first() else {
                return Ok(None);
            };
            let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                return Ok(None);
            };
            match scheme {
                EncryptedScheme::Proofless => {
                    let Ok(plaintext) = Proofless::deserialize(body) else {
                        return Ok(None);
                    };
                    if plaintext.owner != address.owner_hash()? {
                        return Ok(None);
                    }
                    let data_hash = plaintext.data_hash;
                    let ring_data_hash = plaintext.ring_data_hash;
                    Ok(
                        rebuilt(Proofless::into_utxos(plaintext, &owner_cx))?.map(|utxos| {
                            DecodedSlot {
                                utxos,
                                data_hash,
                                ring_data_hash,
                            }
                        }),
                    )
                }
                EncryptedScheme::PlaintextTransfer => {
                    let Ok(plaintext) = PlaintextTransfer::deserialize(body) else {
                        return Ok(None);
                    };
                    Ok(
                        rebuilt(PlaintextTransfer::into_utxos(plaintext, &owner_cx))?.map(
                            |utxos| DecodedSlot {
                                utxos,
                                data_hash: None,
                                ring_data_hash: None,
                            },
                        ),
                    )
                }
                _ => Ok(None),
            }
        }
        OutputDataEncoding::Encrypted(blob) => {
            let Some((&scheme_byte, body)) = blob.split_first() else {
                return Ok(None);
            };
            let Ok(scheme) = EncryptedScheme::from_byte(scheme_byte) else {
                return Ok(None);
            };
            if scheme == EncryptedScheme::RingDeposit {
                return decode_ring_deposit(shielded_keys, address, body, assets);
            }
            let (ciphertext, viewing_pubkeys) = match scheme {
                EncryptedScheme::Confidential
                | EncryptedScheme::RingConfidential
                | EncryptedScheme::RingConfidentialPacked => {
                    let Ok(viewing_pubkey) = Confidential::embedded_viewing_pk(body) else {
                        return Ok(None);
                    };
                    if !shielded_keys
                        .viewing_public_keys()
                        .contains(&viewing_pubkey)
                    {
                        return Ok(None);
                    }
                    let Some((_, ciphertext)) = body.split_at_checked(X25519_PUBKEY_LEN) else {
                        return Ok(None);
                    };
                    (ciphertext, vec![viewing_pubkey])
                }
                EncryptedScheme::AnonymousRecipient => (body, shielded_keys.viewing_public_keys()),
                _ => return Ok(None),
            };
            let (Some(tx_viewing_pubkey), Some(salt)) = (tx.tx_viewing_pk, tx.salt) else {
                return Ok(None);
            };
            let requests: Vec<_> = viewing_pubkeys
                .into_iter()
                .map(|viewing_pubkey| DecryptRequest {
                    ciphertext,
                    viewing_pubkey,
                    tx_viewing_pubkey,
                    salt,
                    slot_index,
                    label: DecryptLabel::Utxo,
                })
                .collect();
            let Some(plaintexts) = trial_decrypt(shielded_keys, &requests)? else {
                return Ok(None);
            };
            for bytes in plaintexts {
                let utxos = match scheme {
                    EncryptedScheme::Confidential | EncryptedScheme::RingConfidential => {
                        let Ok(plaintext) = Confidential::deserialize(&bytes) else {
                            continue;
                        };
                        Confidential::into_utxos(plaintext, &owner_cx)
                    }
                    EncryptedScheme::RingConfidentialPacked => {
                        let Ok(plaintext) = RingPacked::deserialize(&bytes) else {
                            continue;
                        };
                        RingPacked::into_utxos(
                            plaintext,
                            &OwnerCx {
                                ring_program_id: tx.ring_program_id,
                                ..owner_cx
                            },
                        )
                    }
                    EncryptedScheme::AnonymousRecipient => {
                        let Ok(plaintext) = AnonymousRecipient::deserialize(&bytes) else {
                            continue;
                        };
                        if plaintext.owner_pubkey != address.signing_pubkey {
                            continue;
                        }
                        AnonymousRecipient::into_utxos(plaintext, &owner_cx)
                    }
                    _ => return Ok(None),
                };
                let Some(utxos) = rebuilt(utxos)? else {
                    continue;
                };
                return Ok(Some(DecodedSlot {
                    utxos,
                    data_hash: None,
                    ring_data_hash: None,
                }));
            }
            Ok(None)
        }
        OutputDataEncoding::VerifiablyEncrypted(blob) => {
            decode_merge(shielded_keys, address, tx, slot, &blob, owner_cx)
        }
    }
}

/// Another wallet's merge opens to noise, the plaintext range check or the commitment refuses it.
fn decode_merge<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    blob: &[u8],
    owner_cx: OwnerCx,
) -> Result<Option<DecodedSlot>, TransactionError> {
    let Some((&scheme_byte, body)) = blob.split_first() else {
        return Ok(None);
    };
    if EncryptedScheme::from_byte(scheme_byte).ok() != Some(EncryptedScheme::Merge) {
        return Ok(None);
    }
    let Some((ring_data_hash, encrypted)) = split_merge_output_body(body) else {
        return Ok(None);
    };
    // A ring merge carries a ring data hash and a ring program, one without the other is no merge.
    if ring_data_hash.is_some() != tx.ring_program_id.is_some() {
        return Ok(None);
    }
    let Some(&first_nullifier) = tx.nullifiers.first() else {
        return Ok(None);
    };
    let requests = [
        DeriveRequest::MergeOutputKey { first_nullifier },
        DeriveRequest::MergeOutputBlinding { first_nullifier },
    ];
    let derived = shielded_keys.derive(&requests)?;
    let [key, blinding] = <[[u8; 32]; 2]>::try_from(derived).map_err(|derived| {
        TransactionError::IncompleteDerivation {
            got: derived.len(),
            want: requests.len(),
        }
    })?;
    let Ok(plaintext) = MergeOutputPlaintext::decrypt(encrypted, &key) else {
        return Ok(None);
    };
    // The commitment check precedes the registry lookup, an unrelated ciphertext reports no mint.
    let mut utxo = plaintext.into_utxo(
        owner_cx.owner,
        Mint::new(plaintext.mint, 0),
        blinding,
        tx.ring_program_id,
    );
    let context = &slot.output_context;
    let hash = utxo.hash(
        &address.nullifier_pubkey,
        &[0; 32],
        &ring_data_hash.copied().unwrap_or_default(),
        context.tree_id,
    )?;
    if hash != context.hash {
        return Ok(None);
    }
    utxo.asset = owner_cx.assets.mint(&plaintext.mint)?;
    Ok(Some(DecodedSlot {
        utxos: vec![utxo],
        data_hash: None,
        ring_data_hash: ring_data_hash.copied(),
    }))
}

/// A ring deposit publishes its settlement fields in the clear and the owner's
/// preimages under a ciphertext with its own key and salt. The cipher is
/// unauthenticated, so ownership is confirmed by the published owner-UTXO hash,
/// not by the decryption succeeding.
fn decode_ring_deposit<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    body: &[u8],
    assets: &AssetRegistry,
) -> Result<Option<DecodedSlot>, TransactionError> {
    let Ok(output) = EncryptedRingDepositOutput::try_from_slice(body) else {
        return Ok(None);
    };
    let Ok(tx_viewing_pubkey) = X25519Pubkey::from_bytes(output.encrypted.tx_viewing_pk) else {
        return Ok(None);
    };
    let requests: Vec<_> = shielded_keys
        .viewing_public_keys()
        .into_iter()
        .map(|viewing_pubkey| DecryptRequest {
            ciphertext: &output.encrypted.ciphertext,
            viewing_pubkey,
            tx_viewing_pubkey,
            salt: output.encrypted.salt,
            slot_index: 0,
            label: DecryptLabel::RingDeposit,
        })
        .collect();
    let Some(plaintexts) = trial_decrypt(shielded_keys, &requests)? else {
        return Ok(None);
    };
    let owner_hash = address.owner_hash()?;
    for bytes in plaintexts {
        let Ok(plaintext) = wincode::deserialize_exact::<RingDepositPlaintext>(&bytes) else {
            continue;
        };
        // The sender picks the plaintext, a blinding outside the field opens no deposit.
        if owner_utxo_hash(&owner_hash, &plaintext.blinding).ok() != Some(output.owner_utxo_hash) {
            continue;
        }
        let utxo = plaintext.into_utxo(
            address.signing_pubkey,
            assets.mint(&Address::new_from_array(output.asset))?,
            output.amount,
            Address::new_from_array(output.ring_program_id),
        );
        return Ok(Some(DecodedSlot {
            utxos: vec![utxo],
            data_hash: output.data_hash,
            ring_data_hash: Some(output.ring_data_hash),
        }));
    }
    Ok(None)
}

/// A sender-chosen plaintext that rebuilds no note skips its slot, except a registry miss.
fn rebuilt(
    utxos: Result<Vec<Utxo>, TransactionError>,
) -> Result<Option<Vec<Utxo>>, TransactionError> {
    match utxos {
        Ok(utxos) => Ok(Some(utxos)),
        Err(error @ (TransactionError::UnknownAsset(_) | TransactionError::UnknownMint(_))) => {
            Err(error)
        }
        Err(_) => Ok(None),
    }
}

/// `None` when no viewing key can open the requests.
fn trial_decrypt<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    requests: &[DecryptRequest<'_>],
) -> Result<Option<Vec<Vec<u8>>>, TransactionError> {
    if requests.is_empty() {
        return Ok(None);
    }
    let plaintexts = match shielded_keys.decrypt(requests) {
        Ok(plaintexts) => plaintexts,
        // The sender picks `tx_viewing_pk`, a low-order one opens under no key.
        Err(TransactionError::Keypair(KeypairError::NonContributoryKey)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if plaintexts.len() != requests.len() {
        return Err(TransactionError::IncompleteDecryption {
            got: plaintexts.len(),
            want: requests.len(),
        });
    }
    Ok(Some(plaintexts))
}

fn assign_nullifiers<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    utxos: &mut [WalletUtxo],
) -> Result<(), TransactionError> {
    if utxos.is_empty() {
        return Ok(());
    }
    let requests: Vec<_> = utxos
        .iter()
        .map(|input| DeriveRequest::Nullifier {
            utxo_hash: input.utxo_hash,
            blinding: input.utxo.blinding,
        })
        .collect();
    let nullifiers = shielded_keys.derive(&requests)?;
    if nullifiers.len() != utxos.len() {
        return Err(TransactionError::IncompleteDerivation {
            got: nullifiers.len(),
            want: utxos.len(),
        });
    }
    for (input, nullifier) in utxos.iter_mut().zip(nullifiers) {
        input.nullifier = nullifier;
    }
    Ok(())
}
