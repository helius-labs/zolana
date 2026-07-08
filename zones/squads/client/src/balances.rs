//! `getBalances`: decrypt every UTXO an account owns with the auditor-recovered
//! shared viewing key, drop spent ones, and aggregate per asset.
//!
//! An account's outputs arrive in two forms (see the zone output serialization):
//! proofless deposits carry a borsh `OutputData::Plaintext(ProoflessOutput)` and
//! are fetched via `get_encrypted_utxos_by_tags`; transfer/withdrawal outputs
//! carry the raw 71-byte recipient ciphertext and are fetched via
//! `get_shielded_transactions_by_tags`, decrypted with the shared viewing key.

use std::collections::HashMap;

use zolana_client::Rpc;
use zolana_interface::event::{decode_output_data, OutputData};
use zolana_keypair::{hash::hash_field, merge::decrypt_verifiable, NullifierKey, P256Pubkey};
use zolana_squads_interface::{
    constants::{RECIPIENT_CIPHERTEXT_LEN, SENDER_CIPHERTEXT_LEN},
    SQUADS_ZONE_PROGRAM_ID,
};
use zolana_squads_sdk::{
    encrypted_utxo::decrypt_recipient_ciphertext,
    prover::{decrypt_sender_change, ZoneUtxo},
};
use zolana_transaction::{
    instructions::transact::signed_transaction::asset_field, Address, EncryptedScheme,
};

use crate::{
    backend::{right_align_31, ResolvedAccount, SquadsBackend},
    error::{Result, SquadsBackendError},
    tags::account_query_tags,
    types::{AssetBalance, DecryptedUtxo, GetBalancesRequest, GetBalancesResponse},
};

const PAGE_LIMIT: u32 = 1_000;

/// One decrypted output before spent-filtering and aggregation.
struct RawUtxo {
    utxo_hash: [u8; 32],
    asset_id: u64,
    amount: u64,
    blinding: [u8; 31],
}

/// Parse a decrypted merge plaintext `amount(8 BE) || asset_field(32) ||
/// blinding(31)` into its fields, or `None` if the length is wrong.
fn parse_merge_plaintext(plaintext: &[u8]) -> Option<(u64, [u8; 32], [u8; 31])> {
    if plaintext.len() != 8 + 32 + 31 {
        return None;
    }
    let amount = u64::from_be_bytes(plaintext.get(0..8)?.try_into().ok()?);
    let asset: [u8; 32] = plaintext.get(8..40)?.try_into().ok()?;
    let blinding: [u8; 31] = plaintext.get(40..71)?.try_into().ok()?;
    Some((amount, asset, blinding))
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// The user's balance per asset, decrypted with the shared viewing key.
    pub fn get_balances(&self, request: GetBalancesRequest) -> Result<GetBalancesResponse> {
        self.authorize_read(request.viewing_key_account, &request.signature)?;

        let resolved = self.resolve_shared_key(request.viewing_key_account)?;
        let tags = account_query_tags(&resolved.account);
        let asset_map = self.asset_field_map()?;
        let nullifier_key = NullifierKey::from_secret(resolved.nullifier_secret);

        let mut raw: Vec<RawUtxo> = Vec::new();
        self.collect_deposits(&tags, &asset_map, &mut raw)?;
        self.collect_transfers(&tags, &asset_map, &resolved.shared_viewing_sk, &mut raw)?;
        // Merged outputs are keyed by the account view tag but carry a per-output
        // verifiable-encryption ciphertext (no tx-level tx_viewing_pk), so they need
        // their own decrypt pass. Run before change so a merged output can be the
        // candidate first input for a later chained-spend change.
        self.collect_merges(&tags, &asset_map, &resolved.shared_viewing_sk, &mut raw)?;
        // Sender change outputs are keyed by the tx's first input, so the deposits,
        // recipient outputs, and merged outputs collected above are the candidate
        // inputs.
        self.collect_change(&tags, &asset_map, &resolved, &mut raw)?;

        // Dedup by leaf hash (a tx can surface through both fetch paths / pages).
        let mut seen: HashMap<[u8; 32], ()> = HashMap::new();
        let mut unspent: Vec<RawUtxo> = Vec::new();
        for utxo in raw {
            if seen.insert(utxo.utxo_hash, ()).is_some() {
                continue;
            }
            if self.is_spent(&nullifier_key, &utxo.utxo_hash, &utxo.blinding)? {
                continue;
            }
            unspent.push(utxo);
        }

        Ok(GetBalancesResponse {
            balances: self.aggregate(unspent, &asset_map, request.skip_utxos),
        })
    }

    /// Mock authorization hook. A production backend verifies `signature` over the
    /// request by the account owner (or a smart-account key holder) and rejects
    /// reads of another user's data; the in-process mock authorizes every caller.
    fn authorize_read(&self, _viewing_key_account: Address, _signature: &[u8; 64]) -> Result<()> {
        Ok(())
    }

    /// `asset_field(mint)` and the raw mint bytes both map to `(asset_id, mint)`;
    /// transfer ciphertexts carry the field element, deposits carry the mint.
    fn asset_field_map(&self) -> Result<HashMap<[u8; 32], (u64, Address)>> {
        let mut map = HashMap::new();
        for (asset_id, mint) in self.assets() {
            let fe = asset_field(mint)
                .map_err(|e| SquadsBackendError::Crypto(format!("asset_field: {e:?}")))?;
            map.insert(fe, (*asset_id, *mint));
            map.insert(mint.to_bytes(), (*asset_id, *mint));
        }
        Ok(map)
    }

    fn collect_deposits(
        &self,
        tags: &[[u8; 32]],
        asset_map: &HashMap<[u8; 32], (u64, Address)>,
        out: &mut Vec<RawUtxo>,
    ) -> Result<()> {
        let mut cursor = None;
        loop {
            let response = self.indexer().get_encrypted_utxos_by_tags(
                tags.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
            )?;
            for item in response.matches {
                // Proofless deposits have no transaction viewing key / salt.
                if item.tx_viewing_pk.is_some() || item.salt.is_some() {
                    continue;
                }
                let Ok(output) = decode_output_data(&item.output_slot.payload) else {
                    continue;
                };
                let Some((asset_id, _)) = asset_map.get(&output.asset) else {
                    continue;
                };
                out.push(RawUtxo {
                    utxo_hash: item.output_slot.output_context.hash,
                    asset_id: *asset_id,
                    amount: output.amount,
                    blinding: output.blinding,
                });
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(())
    }

    fn collect_transfers(
        &self,
        tags: &[[u8; 32]],
        asset_map: &HashMap<[u8; 32], (u64, Address)>,
        shared_viewing_sk: &p256::SecretKey,
        out: &mut Vec<RawUtxo>,
    ) -> Result<()> {
        let mut cursor = None;
        loop {
            let response = self.indexer().get_shielded_transactions_by_tags(
                tags.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
            )?;
            for tx in response.transactions {
                let Some(tx_viewing_pk) = tx.tx_viewing_pk else {
                    continue;
                };
                for slot in tx.output_slots {
                    if !tags.contains(&slot.view_tag) {
                        continue;
                    }
                    let Ok(ciphertext): core::result::Result<[u8; RECIPIENT_CIPHERTEXT_LEN], _> =
                        slot.payload.as_slice().try_into()
                    else {
                        continue;
                    };
                    let Ok((amount, asset, blinding)) = decrypt_recipient_ciphertext(
                        shared_viewing_sk,
                        &tx_viewing_pk,
                        &ciphertext,
                    ) else {
                        continue;
                    };
                    // A wrong-key decryption yields random bytes; a known asset field
                    // element is the validation that this output is really ours.
                    let Some((asset_id, _)) = asset_map.get(&asset) else {
                        continue;
                    };
                    out.push(RawUtxo {
                        utxo_hash: slot.output_context.hash,
                        asset_id: *asset_id,
                        amount,
                        blinding,
                    });
                }
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(())
    }

    /// Collect merged outputs. A `merge_zone` consolidation appends one output tagged
    /// with the owner's account view tag, but its transaction carries no tx-level
    /// `tx_viewing_pk`; the output payload is a borsh `OutputData::VerifiablyEncrypted`
    /// blob `[MERGE_ENCRYPTED_UTXO_TYPE_PREFIX | EncryptedScheme::Merge |
    /// tx_viewing_pk(33) | ciphertext(71)]`. `collect_transfers` skips it (it expects a
    /// tx-level `tx_viewing_pk` and a 71-byte recipient payload), so this pass decrypts
    /// it with the shared viewing key. The consumed input UTXOs are nullified and
    /// filtered by the shared `is_spent` path, so this does not double-count.
    fn collect_merges(
        &self,
        tags: &[[u8; 32]],
        asset_map: &HashMap<[u8; 32], (u64, Address)>,
        shared_viewing_sk: &p256::SecretKey,
        out: &mut Vec<RawUtxo>,
    ) -> Result<()> {
        let mut cursor = None;
        loop {
            let response = self.indexer().get_shielded_transactions_by_tags(
                tags.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
            )?;
            for tx in response.transactions {
                for slot in tx.output_slots {
                    if !tags.contains(&slot.view_tag) {
                        continue;
                    }
                    let Some(OutputData::VerifiablyEncrypted(blob)) = slot.output_data() else {
                        continue;
                    };
                    if blob.first().copied() != Some(EncryptedScheme::Merge.as_byte()) {
                        continue;
                    }
                    let Some(tx_viewing_pk_bytes) =
                        blob.get(1..34).and_then(|s| <[u8; 33]>::try_from(s).ok())
                    else {
                        continue;
                    };
                    let Some(ciphertext) = blob.get(34..) else {
                        continue;
                    };
                    let Ok(tx_viewing_pk) = P256Pubkey::from_bytes(tx_viewing_pk_bytes) else {
                        continue;
                    };
                    let Ok(plaintext) =
                        decrypt_verifiable(shared_viewing_sk, &tx_viewing_pk, ciphertext)
                    else {
                        continue;
                    };
                    let Some((amount, asset, blinding)) = parse_merge_plaintext(&plaintext) else {
                        continue;
                    };
                    // A wrong-key decryption yields random bytes; a known asset field
                    // element is the validation that this output is really ours.
                    let Some((asset_id, _)) = asset_map.get(&asset) else {
                        continue;
                    };
                    out.push(RawUtxo {
                        utxo_hash: slot.output_context.hash,
                        asset_id: *asset_id,
                        amount,
                        blinding,
                    });
                }
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(())
    }

    /// Collect the sender's OWN change outputs. Each change slot is a 40-byte
    /// `amount || asset` ciphertext AES-CTR keyed directly by the transaction's
    /// `tx_viewing_sk`, which is derived from the sender secrets and the FIRST spent
    /// input. The backend does not know which input was first, so it tries every
    /// already-collected UTXO as the candidate first input and validates the decrypt
    /// by requiring a known asset field element (a wrong candidate yields garbage).
    ///
    /// Runs to a fixpoint so a change output that was itself spent as the first
    /// input of a later transaction can decrypt that later change (chained spends).
    fn collect_change(
        &self,
        tags: &[[u8; 32]],
        asset_map: &HashMap<[u8; 32], (u64, Address)>,
        resolved: &ResolvedAccount,
        out: &mut Vec<RawUtxo>,
    ) -> Result<()> {
        // Gather every sender-change output slot (40-byte payload, matching tag).
        let mut change_slots: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut cursor = None;
        loop {
            let response = self.indexer().get_shielded_transactions_by_tags(
                tags.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
            )?;
            for tx in response.transactions {
                for slot in tx.output_slots {
                    if !tags.contains(&slot.view_tag) {
                        continue;
                    }
                    if slot.payload.len() != SENDER_CIPHERTEXT_LEN {
                        continue;
                    }
                    change_slots.push((slot.output_context.hash, slot.payload));
                }
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        if change_slots.is_empty() {
            return Ok(());
        }

        // Identity fields shared by every candidate first-input ZoneUtxo.
        let owner_key_hash = resolved.account.owner.to_bytes();
        let nullifier_pubkey = resolved.account.nullifier_pubkey;
        let zone_program_id = hash_field(&SQUADS_ZONE_PROGRAM_ID)
            .map_err(|e| SquadsBackendError::Crypto(format!("zone program field: {e:?}")))?;
        let nullifier_secret_32 = right_align_31(&resolved.nullifier_secret);

        let mut decoded = vec![false; change_slots.len()];
        loop {
            let mut newly: Vec<RawUtxo> = Vec::new();
            for (idx, (utxo_hash, payload)) in change_slots.iter().enumerate() {
                if decoded[idx] {
                    continue;
                }
                for candidate in out.iter() {
                    let Some(mint) = self.mint_for_asset_id(candidate.asset_id) else {
                        continue;
                    };
                    let Ok(asset_fe) = asset_field(&mint) else {
                        continue;
                    };
                    let first_input = ZoneUtxo {
                        owner_key_hash,
                        nullifier_pubkey,
                        asset: asset_fe,
                        amount: candidate.amount,
                        blinding: right_align_31(&candidate.blinding),
                        program_data_hash: [0u8; 32],
                        zone_data_hash: [0u8; 32],
                        zone_program_id,
                        is_dummy: false,
                    };
                    let Ok((amount, decrypted_asset, change_blinding)) = decrypt_sender_change(
                        &resolved.shared_viewing_sk,
                        &nullifier_secret_32,
                        &first_input,
                        payload,
                    ) else {
                        continue;
                    };
                    // A wrong first input yields random bytes; a known asset field
                    // element is the validation that this change is really ours.
                    let Some((asset_id, _)) = asset_map.get(&decrypted_asset) else {
                        continue;
                    };
                    let Some(blinding_31) = change_blinding
                        .get(1..32)
                        .and_then(|s| <[u8; 31]>::try_from(s).ok())
                    else {
                        continue;
                    };
                    newly.push(RawUtxo {
                        utxo_hash: *utxo_hash,
                        asset_id: *asset_id,
                        amount,
                        blinding: blinding_31,
                    });
                    decoded[idx] = true;
                    break;
                }
            }
            if newly.is_empty() {
                break;
            }
            out.extend(newly);
        }
        Ok(())
    }

    /// A UTXO is spent when its nullifier is already in the tree, i.e. no
    /// non-inclusion proof can be produced for it.
    fn is_spent(
        &self,
        nullifier_key: &NullifierKey,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 31],
    ) -> Result<bool> {
        let nullifier = nullifier_key
            .nullifier(utxo_hash, blinding)
            .map_err(|e| SquadsBackendError::Crypto(format!("nullifier: {e:?}")))?;
        match self
            .indexer()
            .get_non_inclusion_proofs(self.tree(), vec![nullifier])
        {
            Ok(response) => Ok(response.proofs.is_empty()),
            Err(_) => Ok(true),
        }
    }

    fn aggregate(
        &self,
        utxos: Vec<RawUtxo>,
        asset_map: &HashMap<[u8; 32], (u64, Address)>,
        skip_utxos: bool,
    ) -> Vec<AssetBalance> {
        let mint_for = |asset_id: u64| -> Address {
            asset_map
                .values()
                .find(|(id, _)| *id == asset_id)
                .map(|(_, mint)| *mint)
                .unwrap_or_default()
        };

        let mut by_asset: HashMap<u64, AssetBalance> = HashMap::new();
        for utxo in utxos {
            let entry = by_asset
                .entry(utxo.asset_id)
                .or_insert_with(|| AssetBalance {
                    asset_id: utxo.asset_id,
                    mint: mint_for(utxo.asset_id),
                    amount: 0,
                    utxos: Vec::new(),
                });
            entry.amount = entry.amount.saturating_add(utxo.amount);
            if !skip_utxos {
                entry.utxos.push(DecryptedUtxo {
                    utxo_hash: utxo.utxo_hash,
                    asset_id: utxo.asset_id,
                    amount: utxo.amount,
                    blinding: utxo.blinding,
                });
            }
        }

        let mut balances: Vec<AssetBalance> = by_asset.into_values().collect();
        balances.sort_by_key(|b| b.asset_id);
        balances
    }
}
