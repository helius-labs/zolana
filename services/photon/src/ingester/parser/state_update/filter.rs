use super::types::{FilteredStateUpdate, RingsTransactionUpdate, StateUpdate};
use crate::api::error::PhotonApiError;
use crate::ingester::parser::tree_info::TreeInfo;
use log::debug;
use solana_pubkey::Pubkey;
use std::collections::{HashMap, HashSet};

impl StateUpdate {
    pub async fn filter_by_known_trees<C>(
        self,
        txn: &C,
    ) -> Result<FilteredStateUpdate, PhotonApiError>
    where
        C: sea_orm::ConnectionTrait + sea_orm::TransactionTrait,
    {
        let mut all_tree_pubkeys: HashSet<Pubkey> = HashSet::new();

        for rings_tx in self.rings_transactions.iter() {
            all_tree_pubkeys.insert(Pubkey::from(rings_tx.output_tree));
            for output in rings_tx.outputs.iter() {
                all_tree_pubkeys.insert(Pubkey::from(output.output_tree));
            }
            for nullifier in rings_tx.nullifiers.iter() {
                all_tree_pubkeys.insert(Pubkey::from(nullifier.nullifier_tree));
            }
        }
        all_tree_pubkeys.extend(
            self.nullifier_tree_batch_updates
                .iter()
                .map(|update| update.tree),
        );
        let tree_info_cache = if all_tree_pubkeys.is_empty() {
            HashMap::new()
        } else {
            let pubkeys_vec: Vec<Pubkey> = all_tree_pubkeys.into_iter().collect();
            TreeInfo::get_tree_info_batch(txn, &pubkeys_vec).await?
        };

        let known_trees: HashSet<_> = tree_info_cache.keys().copied().collect();

        let had_rings_transactions = !self.rings_transactions.is_empty();
        let rings_transactions = self
            .rings_transactions
            .into_iter()
            .filter(|rings_tx| {
                let unknown_trees = rings_transaction_trees(rings_tx)
                    .into_iter()
                    .filter(|tree| !known_trees.contains(tree))
                    .collect::<Vec<_>>();

                if unknown_trees.is_empty() {
                    return true;
                }

                let unknown_tree_list = unknown_trees
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                debug!(
                    "Skipping Rings transaction {} event {} for unknown trees: {}",
                    rings_tx.signature, rings_tx.event_index, unknown_tree_list
                );
                false
            })
            .collect::<Vec<_>>();

        let nullifier_tree_batch_updates = self
            .nullifier_tree_batch_updates
            .into_iter()
            .filter(|update| {
                if !known_trees.contains(&update.tree) {
                    debug!(
                        "Skipping nullifier tree batch update {} for unknown tree {}",
                        update.signature, update.tree
                    );
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        let transactions = if had_rings_transactions {
            let retained_rings_signatures = rings_transactions
                .iter()
                .map(|rings_tx| rings_tx.signature)
                .collect::<HashSet<_>>();
            self.transactions
                .into_iter()
                .filter(|transaction| {
                    if retained_rings_signatures.contains(&transaction.signature) {
                        true
                    } else {
                        debug!(
                            "Skipping transaction metadata {} because no known Rings event remains",
                            transaction.signature
                        );
                        false
                    }
                })
                .collect()
        } else {
            self.transactions
        };

        Ok(FilteredStateUpdate {
            state_update: StateUpdate {
                transactions,
                rings_transactions,
                nullifier_tree_batch_updates,
            },
            tree_info_cache,
        })
    }
}

fn rings_transaction_trees(rings_tx: &RingsTransactionUpdate) -> HashSet<Pubkey> {
    let mut trees = HashSet::new();
    trees.insert(Pubkey::from(rings_tx.output_tree));
    trees.extend(
        rings_tx
            .outputs
            .iter()
            .map(|output| Pubkey::from(output.output_tree)),
    );
    trees.extend(
        rings_tx
            .nullifiers
            .iter()
            .map(|nullifier| Pubkey::from(nullifier.nullifier_tree)),
    );
    trees
}

#[cfg(test)]
mod tests {
    use super::super::types::{
        NullifierTreeBatchUpdate, RingsNullifierUpdate, RingsOutputUpdate, RingsTransactionUpdate,
        StateUpdate, Transaction,
    };
    use crate::common::rings_tree::RingsTreeKind;
    use crate::monitor::tree_metadata_sync::{upsert_tree_metadata, TreeAccountData};
    use sea_orm::DatabaseConnection;
    use sea_orm_migration::MigratorTrait;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;

    async fn setup_test_db() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();

        crate::migration::RingsMigrator::up(&db, None)
            .await
            .unwrap();

        db
    }

    async fn insert_test_tree_pubkey(db: &DatabaseConnection, tree_pk: Pubkey) -> Pubkey {
        let data = TreeAccountData {
            queue_pubkey: tree_pk,
            root_history_capacity: RingsTreeKind::Nullifier.root_history_capacity(),
            input_queue_zkp_batch_size:
                zolana_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
            height: RingsTreeKind::Nullifier.tree_height(),
            sequence_number: 0,
            next_index: 0,
        };

        upsert_tree_metadata(db, tree_pk, &data, 0).await.unwrap();

        tree_pk
    }

    #[tokio::test]
    async fn filter_by_known_trees_filters_nullifier_tree_batch_updates() {
        let db = setup_test_db().await;
        let known_tree = insert_test_tree_pubkey(&db, Pubkey::new_from_array([1; 32])).await;
        let unknown_tree = Pubkey::new_from_array([2; 32]);

        let mut state_update = StateUpdate::new();
        state_update.nullifier_tree_batch_updates.extend([
            NullifierTreeBatchUpdate {
                tree: known_tree,
                new_root: [3; 32],
                signature: Signature::from([4; 64]),
            },
            NullifierTreeBatchUpdate {
                tree: unknown_tree,
                new_root: [5; 32],
                signature: Signature::from([6; 64]),
            },
        ]);

        let result = state_update.filter_by_known_trees(&db).await.unwrap();

        assert_eq!(result.state_update.nullifier_tree_batch_updates.len(), 1);
        assert_eq!(
            result.state_update.nullifier_tree_batch_updates[0].tree,
            known_tree
        );
        assert_eq!(result.tree_info_cache.len(), 1);
    }

    #[tokio::test]
    async fn filter_by_known_trees_filters_rings_transactions() {
        let db = setup_test_db().await;
        let known_tree = insert_test_tree_pubkey(&db, Pubkey::new_from_array([1; 32])).await;
        let unknown_output_tree = Pubkey::new_from_array([2; 32]);
        let unknown_nullifier_tree = Pubkey::new_from_array([3; 32]);

        let valid_signature = Signature::from([1; 64]);
        let unknown_output_signature = Signature::from([2; 64]);
        let unknown_nullifier_signature = Signature::from([3; 64]);

        let mut state_update = StateUpdate::new();
        state_update.transactions.extend([
            test_transaction(valid_signature),
            test_transaction(unknown_output_signature),
            test_transaction(unknown_nullifier_signature),
        ]);
        state_update.rings_transactions.extend([
            test_rings_transaction(valid_signature, 0, known_tree, known_tree, known_tree),
            test_rings_transaction(
                unknown_output_signature,
                1,
                unknown_output_tree,
                unknown_output_tree,
                known_tree,
            ),
            test_rings_transaction(
                unknown_nullifier_signature,
                2,
                known_tree,
                known_tree,
                unknown_nullifier_tree,
            ),
        ]);

        let result = state_update.filter_by_known_trees(&db).await.unwrap();

        assert_eq!(result.state_update.rings_transactions.len(), 1);
        assert_eq!(
            result.state_update.rings_transactions[0].signature,
            valid_signature
        );
        assert_eq!(result.state_update.transactions.len(), 1);
        assert!(result
            .state_update
            .transactions
            .contains(&test_transaction(valid_signature)));
    }

    fn test_transaction(signature: Signature) -> Transaction {
        Transaction {
            signature,
            slot: 1,
            error: None,
        }
    }

    fn test_rings_transaction(
        signature: Signature,
        event_index: i16,
        output_tree: Pubkey,
        output_leaf_tree: Pubkey,
        nullifier_tree: Pubkey,
    ) -> RingsTransactionUpdate {
        RingsTransactionUpdate {
            signature,
            event_index,
            slot: 1,
            rings_program_id: [9; 32],
            source_instruction_tag: 1,
            output_tree: output_tree.to_bytes(),
            first_output_leaf_index: 0,
            tx_viewing_pk: None,
            salt: None,
            proofless: false,
            encrypted_utxos: None,
            raw_event: None,
            parse_version: 1,
            outputs: vec![RingsOutputUpdate {
                output_index: 0,
                output_tree: output_leaf_tree.to_bytes(),
                leaf_index: 0,
                view_tag: [4; 32],
                utxo_hash: [5; 32],
                payload: vec![6],
            }],
            messages: Vec::new(),
            nullifiers: vec![RingsNullifierUpdate {
                input_index: 0,
                nullifier_tree: nullifier_tree.to_bytes(),
                input_queue_seq: 0,
                nullifier: [7; 32],
            }],
        }
    }
}
