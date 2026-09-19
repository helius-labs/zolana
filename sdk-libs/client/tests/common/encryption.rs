use crate::output_blindings::assign_output_blindings;
use zolana_transaction::{instructions::transact::SppProofInputs, SppProofOutputUtxo};

pub fn finalized_transaction(
    input_utxos: Vec<zolana_transaction::utxo::SppProofInputUtxo>,
    mut output_utxos: Vec<SppProofOutputUtxo>,
    sender: &zolana_keypair::ShieldedKeypair,
    payer: solana_address::Address,
    output_tree_id: u16,
    blinding_seed: [u8; 32],
    salt: [u8; 16],
) -> SppProofInputs {
    use zolana_interface::instruction::{OwnerTag, TransactOutput};
    use zolana_transaction::serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    };
    let first_nullifier = input_utxos.first().unwrap().nullifier;
    assign_output_blindings(&first_nullifier, &mut output_utxos, &blinding_seed);
    let tx = sender
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let mut outputs = Vec::new();
    let mut tags = Vec::new();
    for (slot_index, output) in output_utxos.iter().enumerate() {
        let address = output.owner_address.unwrap();
        let tag = address.signing_pubkey.confidential_view_tag().unwrap();
        let message = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: output.asset.asset_id,
                amount: output.amount,
                blinding: output.blinding,
                ring_program_id: output.ring_program_id,
                data: output.data.clone(),
            },
            tag,
            &ConfidentialEncode {
                tx: tx.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt,
                slot_index: slot_index as u32,
            },
        )
        .unwrap();
        outputs.push(TransactOutput {
            utxo_hash: output.hash(output_tree_id).unwrap(),
            owner_tag: if tag == payer.to_bytes() {
                OwnerTag::Account(0)
            } else {
                OwnerTag::Inline(tag)
            },
            data: Some(message.data),
        });
        tags.push(tag);
    }
    SppProofInputs {
        input_utxos,
        output_utxos,
        blinding_seed,
        output_tree_id,
        external_data: zolana_transaction::ExternalData::new(
            *tx.pubkey().as_bytes(),
            salt,
            outputs,
            tags,
            vec![],
        ),
        payer,
    }
}
