use std::collections::{hash_map::Entry, HashMap, HashSet};

use solana_address::Address;
use zolana_event::OutputDataEncoding;
use zolana_keypair::{constants::P256_PUBKEY_LEN, shielded::ShieldedAddress};

use crate::{
    asset::{AssetBalance, AssetRegistry, Balances},
    error::TransactionError,
    indexer_types::{OutputSlot, ShieldedTransaction},
    keys::{DecryptLabel, DecryptRequest, DeriveRequest, ShieldedKeys},
    serialization::{
        anonymous::AnonymousRecipient, confidential::Confidential, plaintext::PlaintextTransfer,
        proofless::Proofless, scheme::EncryptedScheme, OwnerCx, UtxoSerialization,
    },
    utxo::{Utxo, WalletUtxo},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecryptionResult {
    pub utxos: Vec<WalletUtxo>,
    pub spent_nullifiers: HashSet<[u8; 32]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendableDecryptionResult {
    pub balances: Balances,
    pub utxos_with_data: Vec<WalletUtxo>,
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
    let address = shielded_keys.address()?;
    let spent_nullifiers = transactions
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().copied())
        .collect();
    let mut utxos = Vec::new();
    for tx in transactions {
        for (position, slot) in tx.output_slots.iter().enumerate() {
            let slot_index =
                u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
            let Some(decoded) = decode_slot(shielded_keys, &address, tx, slot, slot_index, assets)?
            else {
                continue;
            };
            for utxo in decoded.utxos {
                let hash = slot.output_context.hash;
                utxos.push(WalletUtxo {
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
    assign_nullifiers(shielded_keys, &mut utxos)?;
    utxos.sort_by_key(|utxo| {
        (
            utxo.slot,
            utxo.tx_signature.as_ref().to_vec(),
            utxo.slot_index,
        )
    });
    Ok(DecryptionResult {
        utxos,
        spent_nullifiers,
    })
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
