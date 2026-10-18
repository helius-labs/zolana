use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{split_merge_output_body, EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_keypair::{constants::P256_PUBKEY_LEN, shielded::ShieldedAddress, P256Pubkey};

use crate::{
    asset::{AssetBalance, AssetRegistry, Balances, Mint},
    error::TransactionError,
    indexer_types::{OutputSlot, ShieldedTransaction},
    instructions::merge::MergeOutputPlaintext,
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
    /// Mints named by authenticated deposits or merge outputs this wallet owns
    /// that the asset registry has no id for. Those outputs are left out;
    /// register the mints and decrypt again.
    pub unknown_mints: BTreeSet<Address>,
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
        Ok(())
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
            utxos.sort_by_key(|utxo| {
                (
                    utxo.slot,
                    utxo.tx_signature.as_ref().to_vec(),
                    utxo.slot_index,
                )
            });
        }
        SpendableDecryptionResult {
            balances: Balances { assets: balances },
            utxos_with_data,
            unknown_asset_ids: self.unknown_asset_ids.clone(),
            unknown_mints: self.unknown_mints.clone(),
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
            // A ring merge publishes its ciphertext unverified: the ring merge
            // proof does not bind it, so only the commitment check accepts it.
            if scheme == EncryptedScheme::Merge {
                return decode_merge(shielded_keys, address, tx, slot, &blob, owner_cx, true);
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
        OutputDataEncoding::VerifiablyEncrypted(blob) => {
            decode_merge(shielded_keys, address, tx, slot, &blob, owner_cx, false)
        }
    }
}

/// A merge output publishes its amount and mint encrypted under a key the
/// owner derives from the nullifier secret and the first nullifier, so the
/// owner rebuilds the output from the merge transaction alone. A default merge
/// proof binds that ciphertext, whichever inputs the merger chose; a ring merge
/// (`ring`) publishes it unverified. The cipher is unauthenticated: a merge of
/// another wallet, or a wrong ring merge ciphertext, decrypts to noise, which
/// the plaintext range check or the commitment rejects.
fn decode_merge<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    address: &ShieldedAddress,
    tx: &ShieldedTransaction,
    slot: &OutputSlot,
    blob: &[u8],
    owner_cx: OwnerCx,
    ring: bool,
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
    // A ring merge leads with its output ring data hash, names its ring program
    // and is published unverified; a slot missing any of these is not a merge
    // output.
    if ring_data_hash.is_some() != ring || tx.ring_program_id.is_some() != ring {
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
    // Only the mint address enters the commitment. Resolve its registry ID
    // after authentication so unverified ciphertext cannot request backfills.
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
