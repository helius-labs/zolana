use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{EncryptedRingDepositOutput, MergeOutputDerivation, OutputDataEncoding};
use zolana_interface::instruction::instruction_data::MergeMaskNonces;
use zolana_keypair::{constants::P256_PUBKEY_LEN, shielded::ShieldedAddress, P256Pubkey};

use crate::{
    asset::{AssetBalance, AssetRegistry, Balances, Mint},
    data::Data,
    error::TransactionError,
    indexer_types::{OutputSlot, ShieldedTransaction},
    instructions::merge::{merge_unmasked_amount, merge_unmasked_mint},
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
    /// Mints named by deposits or merges this wallet owns that the asset
    /// registry has no id for. Those outputs are left out; register the mints
    /// and decrypt again.
    pub unknown_mints: BTreeSet<Address>,
    /// This wallet's merges whose mint is in `unknown_mints`.
    /// [`extend`](Self::extend) retries them with every call, so registering
    /// the mint recovers them.
    pub pending_merges: Vec<ShieldedTransaction>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendableDecryptionResult {
    pub balances: Balances,
    pub utxos_with_data: Vec<WalletUtxo>,
    /// As on [`DecryptionResult`].
    pub unknown_asset_ids: BTreeSet<u64>,
    /// As on [`DecryptionResult`].
    pub unknown_mints: BTreeSet<Address>,
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
        for tx in transactions.iter().filter(|tx| !tx.merge) {
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
            .chain(transactions.iter().filter(|tx| tx.merge))
            .collect();
        let pending_merges = rebuild_merges(
            shielded_keys,
            &address,
            merges,
            assets,
            &mut utxos,
            &mut unknown_mints,
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
            if requests.is_empty() {
                return Ok(None);
            }
            let plaintexts = shielded_keys.decrypt(&requests)?;
            if plaintexts.len() != requests.len() {
                return Err(TransactionError::IncompleteDecryption {
                    got: plaintexts.len(),
                    want: requests.len(),
                });
            }
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
    if requests.is_empty() {
        return Ok(None);
    }
    let plaintexts = shielded_keys.decrypt(&requests)?;
    if plaintexts.len() != requests.len() {
        return Err(TransactionError::IncompleteDecryption {
            got: plaintexts.len(),
            want: requests.len(),
        });
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
    /// The merge's output, matching its published commitment.
    Rebuilt(Box<WalletUtxo>),
    /// The merge's output, matching its published commitment, in a mint the
    /// asset registry has no id for. Register the mint and rebuild again.
    UnknownMint(Address),
    /// Not a merge of this wallet's UTXOs.
    NotOurs,
}

/// Rebuilds the outputs of this wallet's merges, records the mints the
/// registry lacks, and returns the merges blocked on them.
fn rebuild_merges<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    merges: Vec<&ShieldedTransaction>,
    assets: &AssetRegistry,
    utxos: &mut Vec<WalletUtxo>,
    unknown_mints: &mut BTreeSet<Address>,
) -> Result<Vec<ShieldedTransaction>, TransactionError> {
    let mut pending = Vec::new();
    for tx in merges {
        match rebuild(shielded_keys, address, tx, assets)? {
            MergeRebuild::Rebuilt(rebuilt) => utxos.push(*rebuilt),
            MergeRebuild::UnknownMint(mint) => {
                unknown_mints.insert(mint);
                pending.push(tx.clone());
            }
            MergeRebuild::NotOurs => {}
        }
    }
    Ok(pending)
}

/// Rebuilds the output of `merge` from public data and the nullifier secret
/// alone: the proof binds the output blinding, the masked amount and the
/// masked mint to the first published nullifier, so no input needs to be
/// held, not even one a merger planted without telling the owner.
pub fn rebuild_merge<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    merge: &ShieldedTransaction,
    assets: &AssetRegistry,
) -> Result<MergeRebuild, TransactionError> {
    if !merge.merge {
        return Ok(MergeRebuild::NotOurs);
    }
    rebuild(shielded_keys, &shielded_keys.address()?, merge, assets)
}

fn rebuild<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    assets: &AssetRegistry,
) -> Result<MergeRebuild, TransactionError> {
    let (Some(slot), Some(&first_nullifier), Some(derivation)) = (
        tx.output_slots.first(),
        tx.nullifiers.first(),
        tx.messages
            .first()
            .and_then(|message| MergeOutputDerivation::decode(&message.data)),
    ) else {
        return Ok(MergeRebuild::NotOurs);
    };
    let ring_data_hash = derivation.output_ring_data_hash;
    // A ring merge's output keeps the ring program of its inputs, which the
    // indexer reports for the transaction.
    let ring_program_id = match (ring_data_hash, tx.ring_program_id) {
        (None, _) => None,
        (Some(_), Some(ring_program_id)) => Some(ring_program_id),
        (Some(_), None) => return Ok(MergeRebuild::NotOurs),
    };
    let nonces = MergeMaskNonces::derive(&derivation.mask_seed)?;
    let requests = [
        DeriveRequest::MergeOutputBlinding { first_nullifier },
        DeriveRequest::MergeAmountMask {
            first_nullifier,
            nonce: nonces.amount,
        },
        DeriveRequest::MergeMintMask {
            first_nullifier,
            nonce: nonces.mint,
            chunk_index: 0,
        },
        DeriveRequest::MergeMintMask {
            first_nullifier,
            nonce: nonces.mint,
            chunk_index: 1,
        },
    ];
    let derived = shielded_keys.derive(&requests)?;
    let [blinding, amount_mask, mint_prefix_mask, mint_last_mask] = derived.as_slice() else {
        return Err(TransactionError::IncompleteDerivation {
            got: derived.len(),
            want: requests.len(),
        });
    };
    let (Some(amount), Some(mint)) = (
        merge_unmasked_amount(&derivation.masked_amount, amount_mask),
        merge_unmasked_mint(
            &derivation.masked_mint,
            &[*mint_prefix_mask, *mint_last_mask],
        ),
    ) else {
        return Ok(MergeRebuild::NotOurs);
    };
    // The commitment hashes the mint, not its registry id, so it is checked
    // before the registry is consulted: an unknown mint is reported only for a
    // merge that is the owner's.
    let utxo = Utxo {
        owner: address.signing_pubkey,
        asset: Mint::new(mint, 0),
        amount,
        blinding: *blinding,
        ring_program_id,
        data: Data::default(),
    };
    let Some(mut rebuilt) = merge_output(shielded_keys, address, tx, slot, utxo, ring_data_hash)?
    else {
        return Ok(MergeRebuild::NotOurs);
    };
    rebuilt.utxo.asset = match assets.mint(&mint) {
        Ok(asset) => asset,
        Err(TransactionError::UnknownMint(mint)) => return Ok(MergeRebuild::UnknownMint(mint)),
        Err(error) => return Err(error),
    };
    Ok(MergeRebuild::Rebuilt(Box::new(rebuilt)))
}

/// `utxo` as the merge's output with its nullifier, if it hashes to the
/// published commitment.
fn merge_output<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    utxo: Utxo,
    ring_data_hash: Option<[u8; 32]>,
) -> Result<Option<WalletUtxo>, TransactionError> {
    let context = &slot.output_context;
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
    let mut rebuilt = WalletUtxo {
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash: hash,
        nullifier: [0; 32],
        data_hash: None,
        ring_data_hash,
        tree_id: context.tree_id,
        leaf_index: context.leaf_index,
        slot: tx.slot,
        tx_signature: tx.tx_signature,
        slot_index: 0,
    };
    assign_nullifiers(shielded_keys, std::slice::from_mut(&mut rebuilt))?;
    Ok(Some(rebuilt))
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
