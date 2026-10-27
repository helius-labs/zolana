use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use spr_client::{EncryptedUtxoMatch, Rpc};
use spr_interface::event::OutputDataEncoding;
use spr_program::{
    derive_output_blinding_seed, derive_transact_output_blinding, program::ACCOUNT_BLINDING_SEED,
};
use spr_transaction::WalletUtxo;

use crate::{
    shared::zero_nullifier_key,
    state::{decode_state, AccountUtxo},
};

pub struct DiscoveredAccount {
    pub utxo: WalletUtxo,
    pub version: u64,
}

pub fn decode_wallet_utxo(
    indexed: EncryptedUtxoMatch,
    pda: &Address,
    first_nullifier: &[u8; 32],
    output_index: u32,
) -> Result<DiscoveredAccount> {
    if indexed.tx_viewing_pk.is_some() || indexed.salt.is_some() {
        bail!("indexed output is encrypted");
    }
    let output_data = indexed
        .output_slot
        .output_data()
        .ok_or_else(|| anyhow!("invalid output-data envelope"))?;
    let OutputDataEncoding::Plaintext(blob) = output_data else {
        bail!("indexed output is not plaintext");
    };
    let (address, state) = decode_state(&blob)?;
    let seed = derive_output_blinding_seed(first_nullifier, &ACCOUNT_BLINDING_SEED)?;
    let blinding = derive_transact_output_blinding(first_nullifier, &seed, output_index)?;
    let account_utxo = AccountUtxo {
        pda: *pda,
        address,
        state,
        blinding,
    };
    let version = account_utxo.state.version;
    let data_hash = account_utxo.data_hash()?;
    let utxo = account_utxo.utxo()?;
    let nullifier_key = zero_nullifier_key();
    // The recomputed commitment checks the tree, state, address and recovered blinding.
    let tree_id = indexed.output_slot.output_context.tree_id;
    let hash = utxo.hash(&nullifier_key.pubkey()?, &data_hash, &[0u8; 32], tree_id)?;
    if hash != indexed.output_slot.output_context.hash {
        bail!("decoded UTXO commitment does not match indexed output");
    }
    let nullifier = nullifier_key.nullifier(&hash, &utxo.blinding)?;
    Ok(DiscoveredAccount {
        utxo: WalletUtxo {
            utxo,
            nullifier_pubkey: nullifier_key.pubkey()?,
            utxo_hash: hash,
            nullifier,
            tx_viewing_key: None,
            data_hash: Some(data_hash),
            ring_data_hash: None,
            tree_id,
            leaf_index: indexed.output_slot.output_context.leaf_index,
            latest_tree_id: None,
            slot: indexed.slot,
            tx_signature: indexed.tx_signature,
            slot_index: output_index,
        },
        version,
    })
}

pub fn discover_account(indexer: &impl Rpc, pda: Address) -> Result<DiscoveredAccount> {
    let mut cursor = None;
    let mut matches = Vec::new();
    loop {
        let response = indexer.get_shielded_transactions_by_tags(
            vec![pda.to_bytes()],
            cursor,
            Some(100),
            None,
        )?;
        for transaction in response.transactions {
            let Some(first_nullifier) = transaction.nullifiers.first().copied() else {
                continue;
            };
            for (index, output_slot) in transaction.output_slots.into_iter().enumerate() {
                if output_slot.view_tag != pda.to_bytes() {
                    continue;
                }
                let indexed = EncryptedUtxoMatch {
                    slot: transaction.slot,
                    tx_signature: transaction.tx_signature,
                    output_slot,
                    tx_viewing_pk: transaction.tx_viewing_pk,
                    salt: transaction.salt,
                };
                matches.push((indexed, first_nullifier, u32::try_from(index)?));
            }
        }
        cursor = response.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    discover_from_matches(matches, &pda, |nullifier| {
        let input_utxo = indexer.get_shielded_transactions_by_nullifiers(
            vec![*nullifier],
            None,
            Some(1),
            None,
        )?;
        Ok(!input_utxo.transactions.is_empty())
    })
}

fn discover_from_matches(
    matches: impl IntoIterator<Item = (EncryptedUtxoMatch, [u8; 32], u32)>,
    pda: &Address,
    mut is_spent: impl FnMut(&[u8; 32]) -> Result<bool>,
) -> Result<DiscoveredAccount> {
    let mut candidates = Vec::new();
    for (indexed, first_nullifier, output_index) in matches {
        let Ok(candidate) = decode_wallet_utxo(indexed, pda, &first_nullifier, output_index) else {
            continue;
        };
        if !is_spent(&candidate.utxo.nullifier)? {
            candidates.push(candidate);
        }
    }
    let mut remaining = candidates.into_iter();
    match (remaining.next(), remaining.next()) {
        (None, _) => Err(anyhow!("no unspent UTXO found for PDA {pda}")),
        (Some(current), None) => Ok(current),
        (Some(_), Some(_)) => Err(anyhow!("multiple unspent UTXOs found for PDA {pda}")),
    }
}

#[cfg(test)]
#[path = "discovery_test.rs"]
mod tests;
