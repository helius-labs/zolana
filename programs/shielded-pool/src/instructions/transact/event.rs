use rings_interface::{
    event::{DepositWithdraw, GeneralEvent, Input},
    instruction::{
        instruction_data::transact::{OutputCiphertextRef, TransactIxDataRef},
        OutputUtxo,
    },
};

use super::verify::TransactProofInputs;

pub struct TreeWrite {
    pub inputs: Vec<Input>,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

/// Number of leading output positions covered by the sender bundle ciphertext
/// (`output_ciphertexts[0]`). The remaining ciphertexts are the per-recipient
/// tail slots. Shared by the event/data mapping and the owner public-input
/// mapping so the two cannot drift.
pub fn sender_slot_count(n_outputs: usize, n_ciphertexts: usize) -> usize {
    n_outputs.saturating_sub(n_ciphertexts.saturating_sub(1))
}

/// View_tag for the OWNER public-input mapping at output position `i`. Every
/// position resolves to a concrete ciphertext: the leading `sender_slot_count`
/// change positions all map to the sender bundle (`output_ciphertexts[0]`), and
/// each tail position maps to its own ciphertext.
///
/// This is intentionally DIFFERENT from the event/data mapping in
/// [`build_transact_event`], which replicates the bundle only at position 0 and
/// leaves the middle change positions empty.
pub fn owner_view_tag<'a>(
    output_ciphertexts: &'a [OutputCiphertextRef<'a>],
    sender_slot_count: usize,
    i: usize,
) -> Option<&'a [u8; 32]> {
    let idx = if i < sender_slot_count {
        0
    } else {
        1 + i - sender_slot_count
    };
    output_ciphertexts.get(idx).map(|c| c.view_tag)
}

pub fn build_transact_event(
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &TransactProofInputs,
    tree_write: TreeWrite,
) -> GeneralEvent {
    // Rebuild one event output per position from the two instruction vectors. The
    // bundle (`output_ciphertexts[0]`) covers the leading change positions, so
    // `sender_slot_count = M - (output_ciphertexts.len() - 1)`; positions 0 takes
    // the bundle, the remaining change positions are empty, and each tail position
    // takes its own ciphertext.
    let n_outputs = ix.output_utxo_hashes.len();
    let n_ciphertexts = ix.output_ciphertexts.len();
    let sender_slot_count = sender_slot_count(n_outputs, n_ciphertexts);
    let mut outputs = Vec::with_capacity(n_outputs);
    for (i, utxo_hash) in ix.output_utxo_hashes.iter().enumerate() {
        let ciphertext = if i == 0 {
            ix.output_ciphertexts.first()
        } else if i < sender_slot_count {
            None
        } else {
            ix.output_ciphertexts.get(1 + i - sender_slot_count)
        };
        outputs.push(OutputUtxo {
            view_tag: ciphertext.map_or([0u8; 32], |c| *c.view_tag),
            utxo_hash: *utxo_hash,
            data: ciphertext.map_or_else(Vec::new, |c| c.data.to_vec()),
        });
    }

    let deposit_withdraw = ix.is_deposit_or_withdrawal().then(|| DepositWithdraw {
        is_deposit: ix.is_deposit(),
        amount: ix
            .public_spl_amount
            .or(ix.public_sol_amount)
            .unwrap_or(0)
            .unsigned_abs(),
        asset: proof_inputs.spl_mint,
    });

    GeneralEvent {
        inputs: tree_write.inputs,
        outputs,
        tx_viewing_pk: *ix.tx_viewing_pk,
        salt: *ix.salt,
        first_output_leaf_index: tree_write.first_output_leaf_index,
        output_tree: tree_write.output_tree,
        relay_fee: (ix.relayer_fee != 0).then_some(u64::from(ix.relayer_fee)),
        deposit_withdraw,
    }
}
