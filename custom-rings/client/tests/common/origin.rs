//! Synthetic trusted chain data for client and service tests.
//! Production reconstructs this independently from confirmed SPP instructions.

use zolana_interface::event::{GeneralEvent, Input, OutputUtxo};
use zolana_ring_client::{ConfirmedEvent, ConfirmedEventKind};
use zolana_transaction::ShieldedTransaction;

pub fn event(transaction: &ShieldedTransaction) -> ConfirmedEvent {
    let kind = if transaction.proofless {
        ConfirmedEventKind::Deposit
    } else if transaction.tx_viewing_pk.is_none() {
        ConfirmedEventKind::Merge
    } else {
        ConfirmedEventKind::Transfer
    };
    let first = transaction.output_slots.first();
    ConfirmedEvent::new(
        kind,
        GeneralEvent {
            inputs: transaction
                .nullifiers
                .iter()
                .map(|nullifier| Input {
                    tree: [0; 32],
                    input_queue_seq: 0,
                    nullifier: *nullifier,
                })
                .collect(),
            outputs: transaction
                .output_slots
                .iter()
                .map(|slot| OutputUtxo {
                    view_tag: slot.view_tag,
                    utxo_hash: slot.output_context.hash,
                    data: slot.payload.clone(),
                })
                .collect(),
            messages: transaction.messages.clone(),
            tx_viewing_pk: transaction
                .tx_viewing_pk
                .as_ref()
                .map(|key| *key.as_bytes())
                .unwrap_or([0; 33]),
            salt: transaction.salt.unwrap_or_default(),
            first_output_leaf_index: first.map_or(0, |slot| slot.output_context.leaf_index),
            output_tree: first.map_or([0; 32], |slot| {
                zolana_interface::pda::tree(slot.output_context.tree_id).to_bytes()
            }),
            spl_transfers: Vec::new(),
        },
    )
}
