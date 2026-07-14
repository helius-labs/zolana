use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{constants::SALT_LEN, random_salt, ViewingKey};

use super::OutputUtxo;
use crate::{
    error::TransactionError,
    serialization::{
        confidential::TransferRecipientPlaintext,
        confidential_unified::{ConfidentialUnified, ConfidentialUnifiedEncode},
        UtxoSerialization,
    },
    AssetRegistry, SOL_MINT,
};

pub struct EncodedOutputs {
    pub salt: [u8; SALT_LEN],
    pub output_utxos: Vec<OutputUtxo>,
    pub outputs: Vec<TransactOutput>,
    pub resolved_owner_tags: Vec<[u8; 32]>,
}

pub fn encode_slots(
    outputs: &[OutputUtxo],
    assets: &AssetRegistry,
    transaction_viewing_key: &ViewingKey,
) -> Result<EncodedOutputs, TransactionError> {
    let salt = random_salt();
    let mut output_utxos = Vec::with_capacity(outputs.len());
    let mut transact_outputs = Vec::with_capacity(outputs.len());
    let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
    for (slot_index, output) in outputs.iter().enumerate() {
        let address = output
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        let asset_id = if output.asset == SOL_MINT {
            crate::SOL_ASSET_ID
        } else {
            assets.asset_id(&output.asset)?
        };
        let ciphertext = ConfidentialUnified::encode_plaintext(
            &TransferRecipientPlaintext {
                asset_id,
                amount: output.amount,
                blinding: output.blinding,
                zone_program_id: output.zone_program_id,
                data: output.data.clone(),
            },
            address.signing_pubkey.confidential_view_tag()?,
            &ConfidentialUnifiedEncode {
                tx: transaction_viewing_key.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt,
                slot_index: slot_index as u32,
            },
        )?;
        transact_outputs.push(TransactOutput {
            utxo_hash: output.hash()?,
            owner_tag: OwnerTag::Inline(ciphertext.view_tag),
            data: Some(ciphertext.data),
        });
        resolved_owner_tags.push(ciphertext.view_tag);
        output_utxos.push(output.clone());
    }
    Ok(EncodedOutputs {
        salt,
        output_utxos,
        outputs: transact_outputs,
        resolved_owner_tags,
    })
}
