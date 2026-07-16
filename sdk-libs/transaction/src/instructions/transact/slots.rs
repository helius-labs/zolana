use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{constants::SALT_LEN, random_salt, ShieldedAddress, ViewingKey};

use super::SppProofOutputUtxo;
use crate::{
    error::TransactionError,
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    AssetRegistry, SOL_ASSET_ID, SOL_MINT,
};

pub struct EncryptedTransactionData {
    pub salt: [u8; SALT_LEN],
    pub output_utxos: Vec<SppProofOutputUtxo>,
    pub outputs: Vec<TransactOutput>,
    pub resolved_owner_tags: Vec<[u8; 32]>,
}

fn confidential_ciphertext(
    output: &SppProofOutputUtxo,
    address: ShieldedAddress,
    asset_id: u64,
    tx: &ViewingKey,
    salt: [u8; SALT_LEN],
    slot_index: u32,
) -> Result<MessageData, TransactionError> {
    Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id,
            amount: output.amount,
            blinding: output.blinding,
            zone_program_id: output.zone_program_id,
            data: output.data.clone(),
        },
        address.signing_pubkey.confidential_view_tag()?,
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: address.viewing_pubkey,
            salt,
            slot_index,
        },
    )
}

pub fn encrypt_transaction_data(
    outputs: &[SppProofOutputUtxo],
    assets: &AssetRegistry,
    transaction_viewing_key: &ViewingKey,
) -> Result<EncryptedTransactionData, TransactionError> {
    let salt = random_salt();
    let mut output_utxos = Vec::with_capacity(outputs.len());
    let mut transact_outputs = Vec::with_capacity(outputs.len());
    let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
    for (slot_index, output) in outputs.iter().enumerate() {
        let address = output
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        let asset_id = assets.asset_id(&output.asset)?;
        let ciphertext = confidential_ciphertext(
            output,
            address,
            asset_id,
            transaction_viewing_key,
            salt,
            slot_index as u32,
        )?;
        transact_outputs.push(TransactOutput {
            utxo_hash: output.hash()?,
            owner_tag: OwnerTag::Inline(ciphertext.view_tag),
            data: Some(ciphertext.data),
        });
        resolved_owner_tags.push(ciphertext.view_tag);
        output_utxos.push(output.clone());
    }
    Ok(EncryptedTransactionData {
        salt,
        output_utxos,
        outputs: transact_outputs,
        resolved_owner_tags,
    })
}

/// Encode each real output as its own confidential ciphertext, keyed to that
/// output's owner viewing pubkey, at `slot_index == output position`. Dummy
/// outputs (`owner_address == None`) return `None`; the transfer builder fills
/// those positions with a length-matched random ciphertext under the padded tag.
pub fn encode_confidential_slots(
    outputs: &[SppProofOutputUtxo],
    assets: &AssetRegistry,
    tx: &ViewingKey,
    salt: [u8; SALT_LEN],
) -> Result<Vec<Option<MessageData>>, TransactionError> {
    outputs
        .iter()
        .enumerate()
        .map(|(slot_index, output)| {
            let Some(address) = output.owner_address else {
                return Ok(None);
            };
            let asset_id = if output.asset == SOL_MINT {
                SOL_ASSET_ID
            } else {
                assets.asset_id(&output.asset)?
            };
            Ok(Some(confidential_ciphertext(
                output,
                address,
                asset_id,
                tx,
                salt,
                slot_index as u32,
            )?))
        })
        .collect()
}
