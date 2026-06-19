use zolana_interface::{
    event::{DepositWithdraw, GeneralEvent, Input},
    instruction::{
        instruction_data::transact::{OutputUtxoRef, TransactIxDataRef},
        OutputUtxo,
    },
};

use super::verify::TransactProofInputs;

pub struct TreeWrite {
    pub inputs: Vec<Input>,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

pub fn build_transact_event(
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &TransactProofInputs,
    tree_write: TreeWrite,
) -> GeneralEvent {
    let mut outputs = Vec::with_capacity(1 + ix.recipient_utxo_data.len());
    outputs.push(output_utxo(&ix.sender_utxo_data));
    for recipient in &ix.recipient_utxo_data {
        outputs.push(output_utxo(recipient));
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

fn output_utxo(slot: &OutputUtxoRef<'_>) -> OutputUtxo {
    OutputUtxo {
        view_tag: *slot.view_tag,
        utxo_hash: *slot.utxo_hash,
        data: slot.data.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::instruction::instruction_data::transact::TransactIxData;

    use super::super::verify::MAX_INPUTS;

    fn empty_proof_inputs() -> TransactProofInputs {
        TransactProofInputs {
            utxo_roots: [[0u8; 32]; MAX_INPUTS],
            nullifier_tree_roots: [[0u8; 32]; MAX_INPUTS],
            solana_owner_pk_hashes: [[0u8; 32]; MAX_INPUTS],
            external_data_hash: [0u8; 32],
            spl_mint: None,
            program_id_hashchain: [0u8; 32],
            payer_pubkey_hash: [0u8; 32],
        }
    }

    #[test]
    fn copies_tx_viewing_pk_and_salt_from_instruction_data() {
        let tx_viewing_pk = [9u8; 33];
        let salt = [7u8; 16];
        let ix_data = TransactIxData {
            proof: [0u8; 192],
            expiry_unix_ts: 0,
            relayer_fee: 0,
            private_tx_hash: [0u8; 32],
            inputs: Vec::new(),
            public_sol_amount: None,
            public_spl_amount: None,
            cpi_signer: None,
            tx_viewing_pk,
            salt,
            sender_utxo_data: OutputUtxo {
                view_tag: [1u8; 32],
                utxo_hash: [2u8; 32],
                data: Vec::new(),
            },
            recipient_utxo_data: Vec::new(),
        };
        let bytes = ix_data.serialize().expect("serialize");
        let ix = TransactIxDataRef::from_bytes(&bytes).expect("ref");

        let event = build_transact_event(
            &ix,
            &empty_proof_inputs(),
            TreeWrite {
                inputs: Vec::new(),
                first_output_leaf_index: 0,
                output_tree: [0u8; 32],
            },
        );

        assert_eq!(event.tx_viewing_pk, tx_viewing_pk);
        assert_eq!(event.salt, salt);
    }
}
