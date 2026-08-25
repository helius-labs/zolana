use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use zolana_client::{EncryptedUtxoMatch, Rpc, ZolanaIndexer};
use zolana_interface::event::OutputDataEncoding;
use zolana_transaction::WalletUtxo;

use crate::{
    shared::zero_nullifier_key,
    state::{decode_state, AccountUtxo},
};

pub struct DiscoveredAccount {
    pub utxo: WalletUtxo,
    pub version: u64,
}

pub fn decode_wallet_utxo(indexed: EncryptedUtxoMatch, pda: &Address) -> Result<DiscoveredAccount> {
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
    let account_utxo = AccountUtxo {
        pda: *pda,
        state: decode_state(&blob)?,
    };
    let version = account_utxo.state.version;
    let data_hash = account_utxo.state.data_hash()?;
    let utxo = account_utxo.utxo()?;
    let nullifier_key = zero_nullifier_key();
    let hash = utxo.hash(&nullifier_key.pubkey()?, &data_hash, &[0u8; 32])?;
    if hash != indexed.output_slot.output_context.hash {
        bail!("decoded UTXO commitment does not match indexed output");
    }
    let nullifier = nullifier_key.nullifier(&hash, &utxo.blinding)?;
    Ok(DiscoveredAccount {
        utxo: WalletUtxo {
            utxo,
            output_context: indexed.output_slot.output_context,
            nullifier,
            data_hash: Some(data_hash),
            ring_data_hash: None,
            spent: false,
        },
        version,
    })
}

pub fn discover_account(indexer: &ZolanaIndexer, pda: Address) -> Result<DiscoveredAccount> {
    let mut cursor = None;
    let mut candidates = Vec::new();
    loop {
        let response =
            indexer.get_encrypted_utxos_by_tags(vec![pda.to_bytes()], cursor, Some(100), None)?;
        for indexed in response.matches {
            let candidate = decode_wallet_utxo(indexed, &pda)?;
            let spend = indexer.get_shielded_transactions_by_nullifiers(
                vec![candidate.utxo.nullifier],
                None,
                Some(1),
                None,
            )?;
            if spend.transactions.is_empty() {
                candidates.push(candidate);
            }
        }
        cursor = response.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    candidates
        .into_iter()
        .max_by_key(|candidate| candidate.utxo.output_context.leaf_index)
        .ok_or_else(|| anyhow!("no unspent UTXO found for PDA {pda}"))
}
