use std::{
    collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
    num::NonZeroUsize,
};

use borsh::BorshDeserialize;
use custom_ring_interface::ANONYMOUS_OUTPUT_PLAINTEXT_LEN;
use solana_address::Address;
use solana_signature::Signature;
use zolana_event::{split_merge_output_body, EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_keypair::{
    shielded::ShieldedAddress,
    viewing_key::{Salt, ViewTag},
    x25519::X25519_PUBKEY_LEN,
    KeypairError, PublicKey, X25519Pubkey,
};

use crate::{
    asset::{AssetBalance, AssetRegistry, Balances, Mint},
    data::Data,
    error::TransactionError,
    indexer_types::{OutputSlot, ShieldedTransaction},
    instructions::merge::MergeOutputPlaintext,
    keys::{DecryptLabel, DecryptRequest, DeriveRequest, ShieldedKeys},
    serialization::{
        anonymous::AnonymousRecipient, confidential::Confidential, plaintext::PlaintextTransfer,
        proofless::Proofless, ring_anonymous::RingAnonymousOutputPlaintext,
        ring_deposit::RingDepositPlaintext, scheme::EncryptedScheme, OwnerCx, UtxoSerialization,
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
    /// Mints named by owned deposits or authenticated merge openings that the
    /// asset registry has no id for. Those outputs are left out. Register the
    /// mints and decrypt again.
    pub unknown_mints: BTreeSet<Address>,
    /// Anonymous ring notes whose commitment matched in a mint the registry has
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

/// A commitment-verified anonymous ring note held back until its mint is registered.
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
            data_hash: None,
            ring_data_hash: None,
            tree_id: self.tree_id,
            leaf_index: self.leaf_index,
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
}

/// A scheme-9 output under an unrouted tag is never decrypted.
#[derive(Clone, Debug)]
pub struct AnonymousTagRoutes {
    keys: HashMap<ViewTag, X25519Pubkey>,
    decryptions_per_tag: Option<NonZeroUsize>,
}

impl Default for AnonymousTagRoutes {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonymousTagRoutes {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            decryptions_per_tag: None,
        }
    }

    /// Outputs opened under one tag per [`DecryptionResult::extend_ring_anonymous`], the rest are spam.
    #[must_use]
    pub fn with_decryptions_per_tag(mut self, cap: NonZeroUsize) -> Self {
        self.decryptions_per_tag = Some(cap);
        self
    }

    pub fn insert(&mut self, tag: ViewTag, viewing_pubkey: X25519Pubkey) {
        self.keys.insert(tag, viewing_pubkey);
    }

    pub fn viewing_pubkey(&self, tag: &ViewTag) -> Option<X25519Pubkey> {
        self.keys.get(tag).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn allows(&self, opened: usize) -> bool {
        self.decryptions_per_tag
            .is_none_or(|cap| opened < cap.get())
    }
}

/// A scheme-9 note whose recomputed commitment matched the published one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousNote {
    pub view_tag: ViewTag,
    pub utxo_hash: [u8; 32],
    /// `None` when the body's pair hint is no curve point, the note stays.
    pub pair_pk: Option<X25519Pubkey>,
    /// Held in `pending_assets` until its mint is registered.
    pub pending: bool,
}

/// A verified note whose `pair_u` names no X25519 point, the note itself is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairHintError {
    pub utxo_hash: [u8; 32],
    pub pair_u: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnonymousDecryption {
    pub notes: Vec<AnonymousNote>,
    /// Tags with more outputs than the routes open.
    pub capped_tags: BTreeSet<ViewTag>,
    /// Rings a capped tag was published in, the recovery scan covers them.
    pub capped_rings: BTreeSet<Address>,
    pub bad_pair_hints: Vec<PairHintError>,
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
        self.absorb(
            shielded_keys,
            found,
            transactions,
            unknown_asset_ids,
            unknown_mints,
        )
    }

    /// A routed scheme-9 output is kept only on commitment equality, hits past
    /// the per-tag cap stay unopened and name their tag and ring for the recovery scan.
    pub fn extend_ring_anonymous<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
        routes: &AnonymousTagRoutes,
    ) -> Result<AnonymousDecryption, TransactionError> {
        let mut decryption = AnonymousDecryption::default();
        let mut opened: HashMap<ViewTag, usize> = HashMap::new();
        let mut sites = Vec::new();
        for tx in transactions {
            let Some(context) = AnonymousTx::new(tx) else {
                continue;
            };
            let mut by_key: HashMap<X25519Pubkey, Vec<AnonymousSlot<'_>>> = HashMap::new();
            for (position, slot) in tx.output_slots.iter().enumerate() {
                let Some(viewing_pubkey) = routes.viewing_pubkey(&slot.view_tag) else {
                    continue;
                };
                let Some(candidate) = AnonymousSlot::new(slot, position)? else {
                    continue;
                };
                let count = opened.entry(slot.view_tag).or_default();
                if !routes.allows(*count) {
                    decryption.capped_tags.insert(slot.view_tag);
                    decryption.capped_rings.insert(context.ring);
                    continue;
                }
                *count += 1;
                by_key.entry(viewing_pubkey).or_default().push(candidate);
            }
            sites.extend(by_key.into_iter().map(|(viewing_pubkey, slots)| OpenSite {
                tx,
                context,
                viewing_pubkey,
                slots,
            }));
        }
        self.open_anonymous(shielded_keys, assets, transactions, sites, &mut decryption)?;
        Ok(decryption)
    }

    /// Every scheme-9 slot of `transactions` under every held viewing key
    /// whatever its tag, one key agreement per transaction and key.
    pub fn extend_ring_anonymous_untagged<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
    ) -> Result<AnonymousDecryption, TransactionError> {
        let viewing_pubkeys = shielded_keys.viewing_public_keys();
        let mut decryption = AnonymousDecryption::default();
        let mut sites = Vec::new();
        for tx in transactions {
            let Some(context) = AnonymousTx::new(tx) else {
                continue;
            };
            let slots = tx
                .output_slots
                .iter()
                .enumerate()
                .filter_map(|(position, slot)| AnonymousSlot::new(slot, position).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            if slots.is_empty() {
                continue;
            }
            sites.extend(viewing_pubkeys.iter().map(|&viewing_pubkey| OpenSite {
                tx,
                context,
                viewing_pubkey,
                slots: slots.clone(),
            }));
        }
        self.open_anonymous(shielded_keys, assets, transactions, sites, &mut decryption)?;
        Ok(decryption)
    }

    /// Admits every pending note the registry now resolves, each one's spent
    /// state read before it joins `utxos`.
    pub fn resolve_pending<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        assets: &AssetRegistry,
    ) -> Result<Vec<ResolvedNote>, TransactionError> {
        let mut admitted = Vec::new();
        let mut pending = Vec::new();
        for note in std::mem::take(&mut self.pending_assets) {
            match note.resolve(assets)? {
                Some(utxo) => admitted.push(utxo),
                None => pending.push(note),
            }
        }
        self.pending_assets = pending;
        assign_nullifiers(shielded_keys, &mut admitted)?;
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

    /// One batch per site and acceptance on commitment equality before the asset
    /// id is looked up, the commitment binds the wallet's keys, the public ring
    /// and the on-chain tree id.
    fn open_anonymous<K: ShieldedKeys + ?Sized>(
        &mut self,
        shielded_keys: &K,
        assets: &AssetRegistry,
        transactions: &[ShieldedTransaction],
        sites: Vec<OpenSite<'_>>,
        decryption: &mut AnonymousDecryption,
    ) -> Result<(), TransactionError> {
        let address = shielded_keys.address()?;
        let mut found = Vec::new();
        let mut pending = Vec::new();
        for site in &sites {
            let requests: Vec<DecryptRequest<'_>> = site
                .slots
                .iter()
                .map(|slot| DecryptRequest {
                    ciphertext: &slot.ciphertext,
                    viewing_pubkey: site.viewing_pubkey,
                    tx_viewing_pubkey: site.context.tx_viewing_pubkey,
                    salt: site.context.salt,
                    slot_index: slot.slot_index,
                    label: DecryptLabel::RingAnonymous,
                })
                .collect();
            let Some(plaintexts) = trial_decrypt(shielded_keys, &requests)? else {
                continue;
            };
            for (slot, plaintext) in site.slots.iter().zip(plaintexts) {
                let Some(opening) =
                    <&[u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN]>::try_from(plaintext.as_slice())
                        .ok()
                        .and_then(|bytes| RingAnonymousOutputPlaintext::from_bytes(bytes).ok())
                else {
                    continue;
                };
                let asset_address = Address::new_from_array(opening.asset_address);
                let utxo = Utxo {
                    owner: address.signing_pubkey,
                    asset: Mint::new(asset_address, 0),
                    amount: opening.amount,
                    blinding: opening.blinding,
                    ring_program_id: Some(site.context.ring),
                    data: Data::default(),
                };
                let context = &slot.slot.output_context;
                if utxo.hash(
                    &address.nullifier_pubkey,
                    &[0; 32],
                    &[0; 32],
                    context.tree_id,
                )? != context.hash
                {
                    continue;
                }
                let pair_pk = X25519Pubkey::from_u(opening.pair_u).ok();
                if pair_pk.is_none() {
                    decryption.bad_pair_hints.push(PairHintError {
                        utxo_hash: context.hash,
                        pair_u: opening.pair_u,
                    });
                }
                let published = Site {
                    address: &address,
                    tx: site.tx,
                    slot: slot.slot,
                    slot_index: slot.slot_index,
                };
                let mut wallet_utxo = published.wallet_utxo(utxo, None, None);
                let is_pending = match assets.mint(&asset_address) {
                    Ok(asset) => {
                        wallet_utxo.utxo.asset = asset;
                        found.push(wallet_utxo);
                        false
                    }
                    Err(TransactionError::UnknownMint(_)) => {
                        pending.push(PendingNote {
                            asset_address,
                            amount: opening.amount,
                            blinding: opening.blinding,
                            owner: address.signing_pubkey,
                            nullifier_pk: address.nullifier_pubkey,
                            ring_program_id: site.context.ring,
                            utxo_hash: context.hash,
                            tree_id: context.tree_id,
                            leaf_index: context.leaf_index,
                            slot: site.tx.slot,
                            tx_signature: site.tx.tx_signature,
                            slot_index: slot.slot_index,
                        });
                        true
                    }
                    Err(error) => return Err(error),
                };
                decryption.notes.push(AnonymousNote {
                    view_tag: slot.slot.view_tag,
                    utxo_hash: context.hash,
                    pair_pk,
                    pending: is_pending,
                });
            }
        }
        for note in pending {
            if !self
                .pending_assets
                .iter()
                .any(|held| held.utxo_hash == note.utxo_hash)
            {
                self.pending_assets.push(note);
            }
        }
        self.absorb(
            shielded_keys,
            found,
            transactions,
            BTreeSet::new(),
            BTreeSet::new(),
        )
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

/// The public values every scheme-9 slot of one transaction is keyed by.
#[derive(Clone, Copy)]
struct AnonymousTx {
    tx_viewing_pubkey: X25519Pubkey,
    salt: Salt,
    ring: Address,
}

impl AnonymousTx {
    fn new(tx: &ShieldedTransaction) -> Option<Self> {
        Some(Self {
            tx_viewing_pubkey: tx.tx_viewing_pk?,
            salt: tx.salt?,
            ring: tx.ring_program_id?,
        })
    }
}

/// A slot carrying exactly the scheme-9 body length, the only shape the ring program admits.
#[derive(Clone, Copy)]
struct AnonymousSlot<'a> {
    slot: &'a OutputSlot,
    slot_index: u32,
    ciphertext: [u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN],
}

impl<'a> AnonymousSlot<'a> {
    fn new(slot: &'a OutputSlot, position: usize) -> Result<Option<Self>, TransactionError> {
        let Some(body) = slot.encrypted_body(EncryptedScheme::RingAnonymous) else {
            return Ok(None);
        };
        let Ok(ciphertext) = <[u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN]>::try_from(body) else {
            return Ok(None);
        };
        Ok(Some(Self {
            slot,
            slot_index: u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?,
            ciphertext,
        }))
    }
}

/// The slots of one transaction opened under one viewing key.
struct OpenSite<'a> {
    tx: &'a ShieldedTransaction,
    context: AnonymousTx,
    viewing_pubkey: X25519Pubkey,
    slots: Vec<AnonymousSlot<'a>>,
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
            data_hash,
            ring_data_hash,
            tree_id: self.slot.output_context.tree_id,
            leaf_index: self.slot.output_context.leaf_index,
            slot: self.tx.slot,
            tx_signature: self.tx.tx_signature,
            slot_index: self.slot_index,
        }
    }
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
                    Ok(Some(DecodedSlot {
                        utxos: Proofless::into_utxos(plaintext, &owner_cx)?,
                        data_hash,
                        ring_data_hash,
                    }))
                }
                EncryptedScheme::PlaintextTransfer => {
                    let Ok(plaintext) = PlaintextTransfer::deserialize(body) else {
                        return Ok(None);
                    };
                    Ok(Some(DecodedSlot {
                        utxos: PlaintextTransfer::into_utxos(plaintext, &owner_cx)?,
                        data_hash: None,
                        ring_data_hash: None,
                    }))
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
                EncryptedScheme::Confidential | EncryptedScheme::RingConfidential => {
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
                        Confidential::into_utxos(plaintext, &owner_cx)?
                    }
                    EncryptedScheme::AnonymousRecipient => {
                        let Ok(plaintext) = AnonymousRecipient::deserialize(&bytes) else {
                            continue;
                        };
                        if plaintext.owner_pubkey != address.signing_pubkey {
                            continue;
                        }
                        AnonymousRecipient::into_utxos(plaintext, &owner_cx)?
                    }
                    _ => return Ok(None),
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

/// A merge output publishes its amount and mint encrypted under a key the
/// owner derives from the nullifier secret and the first nullifier, and the
/// proof binds that ciphertext, so the owner rebuilds the output from the merge
/// transaction alone, whichever inputs the merger chose. The cipher is
/// unauthenticated: a merge of another wallet decrypts to noise, which the
/// plaintext range check or the commitment rejects.
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
    // A ring merge leads with its output ring data hash and names its ring
    // program; one without the other is not a merge output.
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
    // The asset ID is wallet metadata. Authenticate the mint and opening before
    // asking the registry to resolve that ID, so an unrelated ciphertext cannot
    // report an arbitrary mint as missing.
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
        if owner_utxo_hash(&owner_hash, &plaintext.blinding)? != output.owner_utxo_hash {
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
