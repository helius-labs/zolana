//! An account's outputs arrive in two forms. Proofless deposits carry a borsh
//! `OutputData::Plaintext(ProoflessOutput)` and are fetched via
//! `get_encrypted_utxos_by_tags`. Transfer and withdrawal outputs carry the raw
//! 71-byte recipient ciphertext, are fetched via
//! `get_shielded_transactions_by_tags`, and decrypt with the shared viewing key.

use std::collections::{HashMap, HashSet};

use zolana_client::{ClientError, Rpc};
use zolana_keypair::NullifierKey;

use zolana_squads_interface::{
    constants::{RECIPIENT_CIPHERTEXT_LEN, SENDER_CIPHERTEXT_LEN},
    SQUADS_ZONE_PROGRAM_ID,
};
use zolana_squads_sdk::{
    crypto::{low_31, right_align_31},
    encrypted_utxo::decrypt_recipient_ciphertext,
    prover::{decrypt_sender_change, ZoneUtxo},
};
use zolana_transaction::{instructions::transact::asset_field, Address};

use crate::{
    authorization::ReadAuthorization,
    backend::{ResolvedAccount, SquadsBackend},
    error::Result,
    tags::account_query_tags,
    types::{AssetBalance, DecryptedUtxo, GetBalancesRequest, GetBalancesResponse},
};

const PAGE_LIMIT: u32 = 1_000;

/// The indexer validation message that reports a nullifier already in the tree
/// or in its queue.
const NULLIFIER_IN_TREE: &str = "already used or queued";

struct RawUtxo {
    utxo_hash: [u8; 32],
    asset_id: u64,
    amount: u64,
    blinding: [u8; 31],
}

impl<I: Rpc, R: Rpc, A: ReadAuthorization> SquadsBackend<I, R, A> {
    /// The user's balance per asset, decrypted with the shared viewing key.
    pub fn get_balances(&self, request: GetBalancesRequest) -> Result<GetBalancesResponse> {
        self.authorize_read(request.viewing_key_account, &request.signature)?;
        self.collect_balances(request.viewing_key_account, request.skip_utxos)
    }

    /// Decrypt and aggregate one account's unspent UTXOs. The caller has already
    /// been authorized, or is the backend itself (the settlement crank).
    pub(crate) fn collect_balances(
        &self,
        viewing_key_account: Address,
        skip_utxos: bool,
    ) -> Result<GetBalancesResponse> {
        let resolved = self.resolve_shared_key(viewing_key_account)?;
        let tags = account_query_tags(&resolved.account);
        let asset_map = self.asset_field_map()?;
        let nullifier_key = NullifierKey::from_secret(resolved.nullifier_secret);

        let mut raw: Vec<RawUtxo> = Vec::new();
        self.collect_deposits(&tags, &asset_map, &mut raw)?;
        self.collect_transfers(&tags, &asset_map, &resolved.shared_viewing_sk, &mut raw)?;
        self.collect_change(&tags, &asset_map, &resolved, &mut raw)?;

        // Dedup by leaf hash (a tx can surface through both fetch paths / pages).
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut unspent: Vec<RawUtxo> = Vec::new();
        for utxo in raw {
            if !seen.insert(utxo.utxo_hash) {
                continue;
            }
            if self.is_spent(&nullifier_key, &utxo.utxo_hash, &utxo.blinding)? {
                continue;
            }
            unspent.push(utxo);
        }

        Ok(GetBalancesResponse {
            balances: self.aggregate(unspent, &asset_map, skip_utxos),
        })
    }

    /// `asset_field(mint)` and the raw mint bytes both map to `(asset_id, mint)`.
    /// Transfer ciphertexts carry the field element, deposits carry the mint.
    fn asset_field_map(&self) -> Result<HashMap<[u8; 32], (u64, Address)>> {
        let mut map = HashMap::new();
        for (asset_id, mint) in self.assets() {
            let fe = asset_field(mint)?;
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
                None,
            )?;
            for item in response.matches {
                // Proofless deposits have no transaction viewing key / salt.
                if item.tx_viewing_pk.is_some() || item.salt.is_some() {
                    continue;
                }
                let Ok(output) = zolana_event::decode_output_data(&item.output_slot.payload) else {
                    continue;
                };
                let Some((asset_id, _)) = asset_map.get(&output.asset) else {
                    continue;
                };
                out.push(RawUtxo {
                    utxo_hash: item.output_slot.output_context.hash,
                    asset_id: *asset_id,
                    amount: output.amount,
                    blinding: low_31(&output.blinding),
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
                None,
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
                    // A wrong-key decryption yields random bytes. A known asset
                    // field element validates that this output is ours.
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
        let mut change_slots: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut cursor = None;
        loop {
            let response = self.indexer().get_shielded_transactions_by_tags(
                tags.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
                None,
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

        let owner_key_hash = resolved.account.owner.to_bytes();
        let nullifier_pubkey = resolved.account.nullifier_pubkey;
        let ring_program_id = zolana_hasher::primitives::hash_bytes(&SQUADS_ZONE_PROGRAM_ID)?;
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
                        ring_data_hash: [0u8; 32],
                        ring_program_id,
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
                    // A wrong first input yields random bytes. A known asset
                    // field element validates that this change is ours.
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
        let nullifier = nullifier_key.nullifier(utxo_hash, &right_align_31(blinding))?;
        // The indexer rejects a non-inclusion request whose leaf is already used
        // or queued, and that rejection is the only failure that means spent.
        // Any other failure must propagate, or an indexer outage silently drops
        // UTXOs from the balance and from the crank's spendable set.
        match self
            .indexer()
            .get_non_inclusion_proofs(self.tree(), vec![nullifier], None)
        {
            Ok(response) => Ok(response.proofs.is_empty()),
            Err(ClientError::Indexer(message)) if message.contains(NULLIFIER_IN_TREE) => Ok(true),
            Err(error) => Err(error.into()),
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
