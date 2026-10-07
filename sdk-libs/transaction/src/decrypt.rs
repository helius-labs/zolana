use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_hasher::p256::is_reserved_derivation_point;
use zolana_keypair::{
    constants::P256_PUBKEY_LEN, shielded::ShieldedAddress, P256Pubkey,
    MERGE_ENVELOPE_CIPHERTEXT_LEN,
};

use crate::{
    asset::{AssetBalance, AssetRegistry, Balances, Mint},
    data::Data,
    error::TransactionError,
    indexer_types::{MergeOutput, OutputContext, OutputSlot, ShieldedTransaction},
    keys::{DecryptLabel, DecryptRequest, DeriveRequest, ShieldedKeys},
    serialization::{
        anonymous::AnonymousRecipient, confidential::Confidential, plaintext::PlaintextTransfer,
        proofless::Proofless, ring_deposit::RingDepositPlaintext, scheme::EncryptedScheme, OwnerCx,
        UtxoSerialization,
    },
    utxo::{owner_utxo_hash, Utxo, WalletUtxo},
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
    /// Mints named by deposits this wallet owns that the asset registry has no
    /// id for. Those deposits are left out; register the mints and decrypt
    /// again.
    pub unknown_mints: BTreeSet<Address>,
    /// Merges that spend a UTXO no batch has produced yet, including merges
    /// that are not this wallet's. [`extend`](Self::extend) retries them with
    /// every batch: the missing input can be another merge's output that a
    /// later batch brings.
    pub pending_merges: Vec<ShieldedTransaction>,
    /// Merges tagged for this wallet whose envelope the key holder failed to
    /// decrypt under every viewing key. Each is left out; the rest of the sync
    /// stands.
    pub undecryptable_merges: usize,
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
    pub undecryptable_merges: usize,
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
    /// Adds the candidates of `transactions`, decrypting only those. A merge
    /// among them, or one still pending from an earlier call, is rebuilt from
    /// every candidate held so far, so its inputs may come from any call: a
    /// client that reads its transactions in rounds decrypts each one once.
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
                        // Deposits name their mint, in the clear and after the
                        // owner check; every other output carries a registry id.
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
                for utxo in decoded.utxos {
                    let hash = slot.output_context.hash;
                    found.push(WalletUtxo {
                        utxo,
                        nullifier_pubkey: address.nullifier_pubkey,
                        utxo_hash: hash,
                        nullifier: [0; 32],
                        data_hash: decoded.data_hash,
                        ring_data_hash: decoded.ring_data_hash,
                        tree_id: slot.output_context.tree_id,
                        leaf_index: slot.output_context.leaf_index,
                        slot: tx.slot,
                        tx_signature: tx.tx_signature,
                        slot_index,
                    });
                }
            }
        }
        assign_nullifiers(shielded_keys, &mut found)?;
        let mut utxos = self.utxos.clone();
        utxos.extend(found);
        let merges = self
            .pending_merges
            .iter()
            .chain(transactions.iter().filter(|tx| tx.may_be_merge()))
            .collect();
        let mut undecryptable_merges = 0;
        let pending_merges = rebuild_merges(
            shielded_keys,
            &address,
            merges,
            &mut utxos,
            assets,
            MergeSkips {
                unknown_mints: &mut unknown_mints,
                undecryptable: &mut undecryptable_merges,
            },
        )?;
        utxos.sort_by_key(|utxo| {
            (
                utxo.slot,
                utxo.tx_signature.as_ref().to_vec(),
                utxo.slot_index,
            )
        });
        self.utxos = utxos;
        self.spent_nullifiers.extend(
            transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied()),
        );
        self.unknown_asset_ids.extend(unknown_asset_ids);
        self.unknown_mints.extend(unknown_mints);
        self.pending_merges = pending_merges;
        self.undecryptable_merges = self
            .undecryptable_merges
            .saturating_add(undecryptable_merges);
        Ok(())
    }
}

/// Skips unresolved, mismatched and spent notes; spend status covers the supplied batch.
pub fn verify_spendable<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    decrypted: &DecryptionResult,
) -> Result<SpendableDecryptionResult, TransactionError> {
    let address = shielded_keys.address()?;
    let mut by_mint: HashMap<Address, AssetBalance> = HashMap::new();
    let mut claimed = HashSet::new();
    let mut utxos_with_data = Vec::new();
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
    for wallet_utxo in verified {
        if decrypted.spent_nullifiers.contains(&wallet_utxo.nullifier) {
            continue;
        }
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
        utxos.sort_by_key(|utxo| {
            (
                utxo.slot,
                utxo.tx_signature.as_ref().to_vec(),
                utxo.slot_index,
            )
        });
    }
    Ok(SpendableDecryptionResult {
        balances: Balances { assets: balances },
        utxos_with_data,
        unknown_asset_ids: decrypted.unknown_asset_ids.clone(),
        unknown_mints: decrypted.unknown_mints.clone(),
        undecryptable_merges: decrypted.undecryptable_merges,
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
                    let Some((_, ciphertext)) = body.split_at_checked(P256_PUBKEY_LEN) else {
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
            let plaintexts = decrypt_each(shielded_keys, viewing_pubkeys, |viewing_pubkey| {
                DecryptRequest {
                    ciphertext,
                    viewing_pubkey,
                    tx_viewing_pubkey,
                    salt,
                    slot_index,
                    label: DecryptLabel::Utxo,
                }
            })?;
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
        // Legacy merge ciphertexts, undecodable on any current rail.
        OutputDataEncoding::VerifiablyEncrypted(_) => Ok(None),
    }
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
    let Ok(tx_viewing_pubkey) = P256Pubkey::from_bytes(output.encrypted.tx_viewing_pk) else {
        return Ok(None);
    };
    let plaintexts = decrypt_each(
        shielded_keys,
        shielded_keys.viewing_public_keys(),
        |viewing_pubkey| DecryptRequest {
            ciphertext: &output.encrypted.ciphertext,
            viewing_pubkey,
            tx_viewing_pubkey,
            salt: output.encrypted.salt,
            slot_index: 0,
            label: DecryptLabel::RingDeposit,
        },
    )?;
    if plaintexts.is_empty() {
        return Ok(None);
    }
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

/// What [`rebuild_merge`] made of one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeRebuild {
    /// The merge's outputs, each matching its published commitment.
    Rebuilt(Vec<WalletUtxo>),
    /// It spends a UTXO the wallet does not hold yet, possibly another
    /// merge's output.
    Pending,
    /// Not a merge of this wallet's UTXOs.
    NotOurs,
    /// Tagged for this wallet, but the key holder failed to decrypt its
    /// envelope under every viewing key.
    Undecryptable,
}

struct MergeSkips<'a> {
    unknown_mints: &'a mut BTreeSet<Address>,
    undecryptable: &'a mut usize,
}

fn rebuild_merges<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    mut pending: Vec<&ShieldedTransaction>,
    utxos: &mut Vec<WalletUtxo>,
    assets: &AssetRegistry,
    skips: MergeSkips<'_>,
) -> Result<Vec<ShieldedTransaction>, TransactionError> {
    while !pending.is_empty() {
        let mut unresolved = Vec::new();
        for tx in &pending {
            match rebuild(shielded_keys, address, tx, utxos, assets) {
                Ok(MergeRebuild::Rebuilt(rebuilt)) => utxos.extend(rebuilt),
                Ok(MergeRebuild::Pending) => unresolved.push(*tx),
                Ok(MergeRebuild::NotOurs) => {}
                Ok(MergeRebuild::Undecryptable) => {
                    *skips.undecryptable = skips.undecryptable.saturating_add(1);
                }
                Err(TransactionError::UnknownMint(mint)) => {
                    skips.unknown_mints.insert(mint);
                }
                Err(error) => return Err(error),
            }
        }
        if unresolved.len() == pending.len() {
            break;
        }
        pending = unresolved;
    }
    Ok(pending.into_iter().cloned().collect())
}

/// Rebuilds the output of `merge`; a ring merge's inputs are found in `held`.
pub fn rebuild_merge<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    merge: &ShieldedTransaction,
    held: &[WalletUtxo],
    assets: &AssetRegistry,
) -> Result<MergeRebuild, TransactionError> {
    rebuild(
        shielded_keys,
        &shielded_keys.address()?,
        merge,
        held,
        assets,
    )
}

fn rebuild<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    utxos: &[WalletUtxo],
    assets: &AssetRegistry,
) -> Result<MergeRebuild, TransactionError> {
    let (Some(output), [slot]) = (tx.merge_output(), tx.output_slots.as_slice()) else {
        return Ok(MergeRebuild::NotOurs);
    };
    let context = &slot.output_context;
    match output {
        MergeOutput::Envelope {
            ephemeral_pk,
            ciphertext,
        } => decrypt_merge_envelope(
            shielded_keys,
            address,
            tx,
            slot,
            &ephemeral_pk,
            ciphertext,
            assets,
        ),
        MergeOutput::Ring { ring_data_hash } => {
            rebuild_ring_merge(shielded_keys, address, tx, context, utxos, ring_data_hash)
        }
    }
}

fn decrypt_merge_envelope<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    ephemeral_pk: &P256Pubkey,
    ciphertext: &[u8; MERGE_ENVELOPE_CIPHERTEXT_LEN],
    assets: &AssetRegistry,
) -> Result<MergeRebuild, TransactionError> {
    // The program tags a default merge's output with the owner's signing key,
    // so a merge tagged for anyone else is dropped before any key agreement.
    if slot.view_tag != address.confidential_view_tag()?
        || is_reserved_derivation_point(ephemeral_pk.as_bytes())
    {
        return Ok(MergeRebuild::NotOurs);
    }
    let Some(first_nullifier) = tx.nullifiers.first() else {
        return Ok(MergeRebuild::NotOurs);
    };
    let context = &slot.output_context;
    let mut failed = false;
    for viewing_pubkey in shielded_keys.viewing_public_keys() {
        let Ok(envelope) = shielded_keys.decrypt_merge_envelope(
            &viewing_pubkey,
            ephemeral_pk,
            ciphertext,
            first_nullifier,
        ) else {
            failed = true;
            continue;
        };
        let mint = Address::new_from_array(envelope.mint);
        let utxo = Utxo {
            owner: address.signing_pubkey,
            asset: Mint::new(mint, 0),
            amount: envelope.amount,
            blinding: envelope.output_blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let Some(mut rebuilt) = merge_wallet_utxo(address, tx, context, utxo, None)? else {
            continue;
        };
        rebuilt.utxo.asset = assets.mint(&mint)?;
        let mut rebuilt = vec![rebuilt];
        assign_nullifiers(shielded_keys, &mut rebuilt)?;
        return Ok(MergeRebuild::Rebuilt(rebuilt));
    }
    if failed {
        return Ok(MergeRebuild::Undecryptable);
    }
    Ok(MergeRebuild::NotOurs)
}

fn rebuild_ring_merge<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    context: &OutputContext,
    utxos: &[WalletUtxo],
    ring_data_hash: [u8; 32],
) -> Result<MergeRebuild, TransactionError> {
    let held = |nullifier: &[u8; 32]| utxos.iter().find(|utxo| &utxo.nullifier == nullifier);
    let Some(&first_nullifier) = tx.nullifiers.first() else {
        return Ok(MergeRebuild::NotOurs);
    };
    // The first nullifier is always a real input, so it names the owner before
    // anything is derived from the nullifier secret.
    if held(&first_nullifier).is_none() {
        return Ok(MergeRebuild::Pending);
    }
    let Ok(slot_count) = u8::try_from(tx.nullifiers.len()) else {
        return Ok(MergeRebuild::NotOurs);
    };
    let mut requests: Vec<_> = (0..slot_count)
        .map(|slot_index| DeriveRequest::MergeDummyNullifier {
            first_nullifier,
            slot_index,
        })
        .collect();
    requests.push(DeriveRequest::MergeOutputBlinding { first_nullifier });
    let derived = shielded_keys.derive(&requests)?;
    let incomplete = || TransactionError::IncompleteDerivation {
        got: derived.len(),
        want: requests.len(),
    };
    if derived.len() != requests.len() {
        return Err(incomplete());
    }
    let Some((&blinding, dummy_nullifiers)) = derived.split_last() else {
        return Err(incomplete());
    };

    // Padded slots spend deterministic dummy nullifiers; every other nullifier
    // must be a note this wallet holds, because a merge proof binds one owner.
    let mut inputs = Vec::new();
    for (nullifier, dummy) in tx.nullifiers.iter().zip(dummy_nullifiers) {
        if nullifier == dummy {
            continue;
        }
        let Some(input) = held(nullifier) else {
            return Ok(MergeRebuild::Pending);
        };
        inputs.push(input);
    }
    let Some(first) = inputs.first() else {
        return Ok(MergeRebuild::NotOurs);
    };
    let (asset, ring_program_id) = (first.utxo.asset, first.utxo.ring_program_id);
    if ring_program_id.is_none()
        || inputs
            .iter()
            .any(|input| input.utxo.asset != asset || input.utxo.ring_program_id != ring_program_id)
    {
        return Ok(MergeRebuild::NotOurs);
    }
    let mut amount = 0u64;
    for input in &inputs {
        amount = amount
            .checked_add(input.utxo.amount)
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
    }

    let utxo = Utxo {
        owner: address.signing_pubkey,
        asset,
        amount,
        blinding,
        ring_program_id,
        data: Data::default(),
    };
    let Some(rebuilt) = merge_wallet_utxo(address, tx, context, utxo, Some(ring_data_hash))? else {
        return Ok(MergeRebuild::NotOurs);
    };
    let mut rebuilt = vec![rebuilt];
    assign_nullifiers(shielded_keys, &mut rebuilt)?;
    Ok(MergeRebuild::Rebuilt(rebuilt))
}

fn merge_wallet_utxo(
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    context: &OutputContext,
    utxo: Utxo,
    ring_data_hash: Option<[u8; 32]>,
) -> Result<Option<WalletUtxo>, TransactionError> {
    let hash = utxo.hash(
        &address.nullifier_pubkey,
        &[0; 32],
        &ring_data_hash.unwrap_or_default(),
        context.tree_id,
    )?;
    // Checked here rather than only in `verify_spendable`: a rebuilt note
    // seeds the next merge in a chain, so a wrong one must not.
    if hash != context.hash {
        return Ok(None);
    }
    Ok(Some(WalletUtxo {
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash: context.hash,
        nullifier: [0; 32],
        data_hash: None,
        ring_data_hash,
        tree_id: context.tree_id,
        leaf_index: context.leaf_index,
        slot: tx.slot,
        tx_signature: tx.tx_signature,
        slot_index: 0,
    }))
}

fn decrypt_each<'a, K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    viewing_pubkeys: Vec<P256Pubkey>,
    request: impl Fn(P256Pubkey) -> DecryptRequest<'a>,
) -> Result<Vec<Vec<u8>>, TransactionError> {
    let requests: Vec<_> = viewing_pubkeys.into_iter().map(request).collect();
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let plaintexts = shielded_keys.decrypt(&requests)?;
    if plaintexts.len() != requests.len() {
        return Err(TransactionError::IncompleteDecryption {
            got: plaintexts.len(),
            want: requests.len(),
        });
    }
    Ok(plaintexts)
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
