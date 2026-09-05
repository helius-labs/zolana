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
    let mut since = None;
    let mut matches = Vec::new();
    loop {
        let response =
            indexer.get_encrypted_utxos_by_tags(vec![pda.to_bytes()], since, Some(100), None)?;
        matches.extend(response.matches);
        since = response.next;
        if since.is_none() {
            break;
        }
    }
    discover_from_matches(matches, &pda, |nullifier| {
        let spend = indexer.get_shielded_transactions_by_nullifiers(
            vec![*nullifier],
            None,
            Some(1),
            None,
        )?;
        Ok(!spend.transactions.is_empty())
    })
}

fn discover_from_matches(
    matches: impl IntoIterator<Item = EncryptedUtxoMatch>,
    pda: &Address,
    mut is_spent: impl FnMut(&[u8; 32]) -> Result<bool>,
) -> Result<DiscoveredAccount> {
    let mut candidates = Vec::new();
    for indexed in matches {
        let Ok(candidate) = decode_wallet_utxo(indexed, pda) else {
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
mod tests {
    use super::*;
    use crate::{account_pda, state::AccountState};
    use zolana_transaction::{OutputContext, OutputSlot};

    const AUTHORITY: [u8; 32] = [7u8; 32];

    fn test_pda() -> Address {
        account_pda(&Address::new_from_array(AUTHORITY))
    }

    fn derived_address(pda: &Address) -> [u8; 32] {
        compression_example_program::state::PdaOwner::new(pda.as_array())
            .unwrap()
            .address()
            .unwrap()
    }

    fn account_state(pda: &Address, value: u64, version: u64) -> AccountState {
        AccountState {
            address: derived_address(pda),
            authority: AUTHORITY,
            value,
            version,
        }
    }

    fn state_of(current: &DiscoveredAccount) -> AccountState {
        decode_state(current.utxo.utxo.data.utxo_data().unwrap()).unwrap()
    }

    fn tagged_plaintext(pda: Address, state: &AccountState, leaf_index: u64) -> EncryptedUtxoMatch {
        let account = AccountUtxo {
            pda,
            state: state.clone(),
        };
        let utxo = account.utxo().unwrap();
        let data_hash = state.data_hash().unwrap();
        let hash = utxo
            .hash(
                &zero_nullifier_key().pubkey().unwrap(),
                &data_hash,
                &[0u8; 32],
            )
            .unwrap();
        EncryptedUtxoMatch {
            slot: 0,
            tx_signature: Default::default(),
            output_slot: OutputSlot {
                view_tag: pda.to_bytes(),
                output_context: OutputContext {
                    hash,
                    tree: Address::default(),
                    leaf_index,
                },
                payload: state.to_output_data().unwrap(),
            },
            tx_viewing_pk: None,
            salt: None,
        }
    }

    fn tagged_garbage(pda: Address, leaf_index: u64) -> EncryptedUtxoMatch {
        EncryptedUtxoMatch {
            slot: 0,
            tx_signature: Default::default(),
            output_slot: OutputSlot {
                view_tag: pda.to_bytes(),
                output_context: OutputContext {
                    hash: [0u8; 32],
                    tree: Address::default(),
                    leaf_index,
                },
                payload: borsh::to_vec(&OutputDataEncoding::Plaintext(vec![0xff; 3])).unwrap(),
            },
            tx_viewing_pk: None,
            salt: None,
        }
    }

    fn unspent(_: &[u8; 32]) -> Result<bool> {
        Ok(false)
    }

    #[test]
    fn malformed_plaintext_tagged_to_the_pda_is_skipped() {
        let pda = test_pda();
        let legit = account_state(&pda, 1, 0);
        let current = discover_from_matches(
            [tagged_plaintext(pda, &legit, 10), tagged_garbage(pda, 11)],
            &pda,
            unspent,
        )
        .unwrap();

        assert_eq!(current.version, 0);
        assert_eq!(state_of(&current).value, 1);
    }

    #[test]
    fn forged_plaintext_with_a_higher_leaf_index_is_not_selected() {
        let pda = test_pda();
        let legit = account_state(&pda, 1, 0);
        let forged = account_state(&pda, 999, 7);
        match discover_from_matches(
            [
                tagged_plaintext(pda, &legit, 10),
                tagged_plaintext(pda, &forged, 11),
            ],
            &pda,
            unspent,
        ) {
            Ok(current) => {
                assert_eq!(current.version, 0);
                assert_eq!(state_of(&current).value, 1);
            }
            Err(err) => assert!(err.to_string().contains("multiple unspent"), "{err}"),
        }
    }
}
